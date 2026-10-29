//! PermissionCenter-Server.
//!
//! Nimmt Scan-Reports der Clients entgegen, gleicht sie mit dem Active
//! Directory ab, bewertet sie und stellt Ergebnisse über REST-API und
//! Web-Oberfläche bereit.

mod ad;
mod analysis;
mod api;
mod config;
mod db;
mod directory;
mod ingest;
mod releases;
mod web;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::Router;
use clap::{Parser, Subcommand};
use tower_http::compression::CompressionLayer;
use tower_http::decompression::RequestDecompressionLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use api::AppState;
use config::ServerConfig;
use pc_common::AdSnapshot;

#[derive(Parser)]
#[command(
    name = "pc-server",
    version,
    about = "PermissionCenter-Server – Auswertung von Berechtigungsscans"
)]
struct Cli {
    /// Konfigurationsdatei (Standard: ./pc-server.toml, Umgebungsvariablen PC_* überschreiben)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Webserver starten (Standard)
    Serve,
    /// AD-Daten aus einer JSON-Datei importieren (Export-ADData.ps1)
    ImportAd { file: PathBuf },
    /// AD-Daten per LDAP synchronisieren
    SyncAd,
    /// Scan-Report (JSON) direkt importieren
    ImportReport { file: PathBuf },
    /// Analyse neu berechnen
    Analyze,
    /// Wirksame Konfiguration ausgeben
    PrintConfig,
    /// Schlüsselpaar zum Signieren von Client-Releases erzeugen
    GenSigningKey {
        /// Datei für den privaten Schlüssel (sicher verwahren, nicht auf dem Server ablegen)
        #[arg(long)]
        out: PathBuf,
    },
    /// Client-Release für OTA-Updates veröffentlichen
    PublishClient {
        /// Pfad zur pc-client.exe
        #[arg(long)]
        file: PathBuf,
        /// Version (z. B. 0.2.0)
        #[arg(long)]
        version: String,
        /// Privater Signaturschlüssel (aus gen-signing-key)
        #[arg(long)]
        signing_key: Option<PathBuf>,
        #[arg(long)]
        notes: Option<String>,
        /// Statt lokal ablegen: an diesen PermissionCenter-Server hochladen (z. B. http://permcenter:8080)
        #[arg(long)]
        server: Option<String>,
        /// API-Token für den Upload (ein Wert aus PC_API_TOKENS des Zielservers)
        #[arg(long, env = "PC_API_TOKEN")]
        token: Option<String>,
    },
    /// Prüft, ob der lokale Server antwortet (für Docker-Healthchecks)
    Healthcheck {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("PC_LOG")
                .unwrap_or_else(|_| "info,tower_http=warn".into()),
        )
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("Tokio-Runtime");
    if let Err(e) = rt.block_on(run(cli)) {
        error!("{e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let (cfg, path) = ServerConfig::load(cli.config.as_deref())?;
    if let Some(p) = &path {
        info!("Konfiguration: {}", p.display());
    }
    match &cli.command {
        Some(Command::PrintConfig) => {
            print!("{}", toml::to_string_pretty(&cfg)?);
            return Ok(());
        }
        Some(Command::Healthcheck { addr }) => return healthcheck(addr).await,
        Some(Command::GenSigningKey { out }) => {
            if out.exists() {
                anyhow::bail!("{} existiert bereits", out.display());
            }
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("Zufallsquelle: {e}"))?;
            let (private, public) = pc_common::release::keypair_from_seed(seed);
            if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("Ordner {} nicht anlegbar", dir.display()))?;
            }
            std::fs::write(out, &private)
                .with_context(|| format!("{} nicht schreibbar", out.display()))?;
            println!("Privater Schlüssel gespeichert: {}", out.display());
            println!("Öffentlicher Schlüssel (in pc-client.toml [update] public_key und PC_CLIENT_UPDATE_PUBLIC_KEY eintragen):");
            println!("{public}");
            return Ok(());
        }
        Some(Command::PublishClient {
            file,
            version,
            signing_key,
            notes,
            server,
            token,
        }) => {
            let exe =
                std::fs::read(file).with_context(|| format!("{} nicht lesbar", file.display()))?;
            let signature = match signing_key {
                Some(k) => {
                    let key = std::fs::read_to_string(k)
                        .with_context(|| format!("{} nicht lesbar", k.display()))?;
                    let sha = pc_common::release::sha256_hex(&exe);
                    Some(
                        pc_common::release::sign(&key, version, &sha)
                            .map_err(|e| anyhow::anyhow!(e))?,
                    )
                }
                None => None,
            };
            if let Some(base) = server {
                let r = upload_release(
                    base,
                    token.as_deref(),
                    version,
                    exe,
                    signature,
                    notes.clone(),
                )
                .await?;
                println!(
                    "Release {} auf {} veröffentlicht ({} Byte, {})",
                    r.version,
                    base,
                    r.size,
                    if r.signature.is_some() {
                        "signiert"
                    } else {
                        "UNSIGNIERT"
                    }
                );
                return Ok(());
            }
            let r = releases::publish(
                &cfg.client_releases_dir,
                version,
                &exe,
                signature,
                notes.clone(),
                cfg.client_update_public_key.as_deref(),
            )?;
            println!(
                "Release {} veröffentlicht ({} Byte, SHA-256 {}, {})",
                r.version,
                r.size,
                r.sha256,
                if r.signature.is_some() {
                    "signiert"
                } else {
                    "UNSIGNIERT"
                }
            );
            return Ok(());
        }
        _ => {}
    }
    let pool = db::connect(&cfg.database_url, cfg.database_pool_size).await?;
    let state = AppState {
        db: pool,
        cfg: Arc::new(cfg),
        ad_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(state).await,
        Command::ImportAd { file } => {
            let bytes =
                std::fs::read(&file).with_context(|| format!("{} nicht lesbar", file.display()))?;
            let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
            let snap: AdSnapshot = serde_json::from_slice(bytes).context("AD-Export ungültig")?;
            let v = api::store_and_analyze(&state, snap, "import")
                .await
                .map_err(|_| anyhow::anyhow!("Import fehlgeschlagen"))?;
            println!("{v}");
            Ok(())
        }
        Command::SyncAd => {
            let v = api::run_ldap_sync(&state)
                .await
                .map_err(|_| anyhow::anyhow!("LDAP-Synchronisation fehlgeschlagen"))?;
            println!("{v}");
            Ok(())
        }
        Command::ImportReport { file } => {
            let text = std::fs::read_to_string(&file)?;
            let report: pc_common::ScanReport =
                serde_json::from_str(&text).context("Report ungültig")?;
            let mut client = state.db.get().await?;
            let tx = client.transaction().await?;
            let res = ingest::ingest(&tx, &report).await?;
            let a = analysis::run(&tx, &state.cfg.analysis).await?;
            tx.commit().await?;
            println!(
                "System {} importiert, {} Befunde gesamt",
                res.system_id, a.findings
            );
            Ok(())
        }
        Command::Analyze => {
            let mut client = state.db.get().await?;
            let tx = client.transaction().await?;
            let a = analysis::run(&tx, &state.cfg.analysis).await?;
            tx.commit().await?;
            println!("{} Befunde", a.findings);
            Ok(())
        }
        Command::PrintConfig
        | Command::Healthcheck { .. }
        | Command::GenSigningKey { .. }
        | Command::PublishClient { .. } => {
            unreachable!()
        }
    }
}

async fn serve(state: AppState) -> Result<()> {
    let cfg = state.cfg.clone();
    if cfg.api_tokens.is_empty() {
        warn!("Keine api_tokens konfiguriert – Uploads werden ohne Token angenommen");
    }

    // Periodischer AD-Abgleich
    if cfg.ldap.is_configured() && cfg.ldap.sync_interval_minutes > 0 {
        let st = state.clone();
        let every = Duration::from_secs(cfg.ldap.sync_interval_minutes * 60);
        tokio::spawn(async move {
            loop {
                match api::run_ldap_sync(&st).await {
                    Ok(v) => info!("LDAP-Synchronisation: {v}"),
                    Err(_) => warn!("LDAP-Synchronisation fehlgeschlagen"),
                }
                tokio::time::sleep(every).await;
            }
        });
    }

    let app = Router::new()
        .merge(api::router(state))
        .fallback(web::static_handler)
        .layer(DefaultBodyLimit::max(cfg.max_upload_mb * 1024 * 1024))
        .layer(RequestDecompressionLayer::new())
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("{} nicht bindbar", cfg.listen))?;
    info!(
        "PermissionCenter-Server {} lauscht auf http://{}",
        env!("CARGO_PKG_VERSION"),
        cfg.listen
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    info!("Server beendet");
    Ok(())
}

/// Lädt ein lokal signiertes Release per API auf einen entfernten Server hoch.
async fn upload_release(
    base: &str,
    token: Option<&str>,
    version: &str,
    exe: Vec<u8>,
    signature: Option<String>,
    notes: Option<String>,
) -> Result<pc_common::release::ClientRelease> {
    let token = token
        .context("--token (oder PC_API_TOKEN) fehlt – der Server erlaubt Uploads nur mit Token")?;
    let url = format!("{}/api/v1/client/releases", base.trim_end_matches('/'));
    let (token, version) = (token.to_string(), version.to_string());
    tokio::task::spawn_blocking(move || -> Result<pc_common::release::ClientRelease> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(300)))
            .http_status_as_error(false)
            .build()
            .into();
        let mut req = agent
            .post(&url)
            .query("version", &version)
            .header("X-Api-Key", &token);
        if let Some(s) = &signature {
            req = req.query("signature", s);
        }
        if let Some(n) = &notes {
            req = req.query("notes", n);
        }
        let mut resp = req
            .header("Content-Type", "application/octet-stream")
            .send(&exe[..])
            .with_context(|| format!("{url} nicht erreichbar"))?;
        if !resp.status().is_success() {
            let body = resp.body_mut().read_to_string().unwrap_or_default();
            anyhow::bail!("Server antwortete mit {}: {}", resp.status(), body.trim());
        }
        Ok(resp.body_mut().read_json()?)
    })
    .await?
}

/// Minimaler HTTP-Aufruf von `/api/v1/health` ohne zusätzliche Abhängigkeiten.
async fn healthcheck(addr: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
        .await??;
    let req = format!("GET /api/v1/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf);
    if text.starts_with("HTTP/1.1 200") && text.contains("\"database\":true") {
        Ok(())
    } else {
        anyhow::bail!("Server nicht gesund: {}", text.lines().next().unwrap_or(""))
    }
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
