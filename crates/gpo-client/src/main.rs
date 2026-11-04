//! PermissionCenter-GPO-Client.
//!
//! Läuft auf einem Domänencontroller (oder Rechner mit GPMC/RSAT), liest alle
//! Gruppenrichtlinien samt Einstellungen, Verknüpfungen und Berechtigungen und
//! überträgt sie an den PermissionCenter-Server.

mod collect;

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use flate2::write::GzEncoder;
use flate2::Compression;
use pc_common::gpo::{GpoSnapshot, GPO_SCHEMA_VERSION};
use ureq::tls::TlsConfig;

#[derive(Parser)]
#[command(name = "gpo-client", version, about = "PermissionCenter – Gruppenrichtlinien einlesen und übertragen")]
struct Cli {
    /// Adresse des PermissionCenter-Servers, z. B. https://permcenter.firma.local:8080
    #[arg(short, long, env = "PC_SERVER_URL")]
    server: Option<String>,
    /// API-Token (muss in PC_API_TOKENS des Servers stehen)
    #[arg(short, long, env = "PC_API_TOKEN")]
    token: Option<String>,
    /// Zertifikatsprüfung abschalten (nur für Tests)
    #[arg(long)]
    accept_invalid_certs: bool,
    /// Zeitlimit für den Upload in Sekunden
    #[arg(long, default_value_t = 300)]
    timeout: u64,
    /// Ergebnis zusätzlich als JSON-Datei speichern
    #[arg(long)]
    out: Option<PathBuf>,
    /// Vorhandene gpos.xml/perms.json aus diesem Ordner verwenden statt Live-Scan
    #[arg(long)]
    from: Option<PathBuf>,
    /// Nur einlesen, nichts übertragen
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FEHLER: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let dir = match &cli.from {
        Some(d) => d.clone(),
        None => {
            let d = std::env::temp_dir().join("PermissionCenter-gpo");
            println!("Lese Gruppenrichtlinien (kann einige Minuten dauern)…");
            collect::run_powershell(&d).map_err(|e| {
                anyhow!("{e}\nHinweis: Auf einem Domänencontroller (oder mit RSAT-GPMC) und mit ausreichenden Rechten ausführen.")
            })?;
            d
        }
    };
    let mut snap: GpoSnapshot = collect::load(&dir).map_err(|e| anyhow!(e))?;
    snap.schema_version = GPO_SCHEMA_VERSION;
    snap.host = std::env::var("COMPUTERNAME").unwrap_or_default();
    snap.client_version = env!("CARGO_PKG_VERSION").into();
    snap.collected_at = Some(chrono::Utc::now());
    if snap.domain.is_empty() {
        snap.domain = snap.gpos.first().map(|g| g.domain.clone()).unwrap_or_default();
    }
    let settings: usize = snap.gpos.iter().map(|g| g.settings.len()).sum();
    println!("{} GPOs, {} Einstellungen, {} Gruppen gelesen.", snap.gpos.len(), settings, snap.groups.len());
    if snap.gpos.is_empty() {
        bail!("Keine GPOs gefunden – Upload abgebrochen.");
    }

    let json = serde_json::to_vec(&snap)?;
    if let Some(p) = &cli.out {
        std::fs::write(p, &json).with_context(|| format!("{} schreiben", p.display()))?;
        println!("Gespeichert: {}", p.display());
    }
    if cli.dry_run {
        return Ok(());
    }
    let server = cli
        .server
        .as_deref()
        .ok_or_else(|| anyhow!("Keine Server-Adresse angegeben (--server oder PC_SERVER_URL)"))?;
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&json)?;
    let gz = gz.finish()?;

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(cli.timeout.max(10))))
        .tls_config(TlsConfig::builder().disable_verification(cli.accept_invalid_certs).build())
        .http_status_as_error(false)
        .build()
        .into();
    let url = format!("{}/api/v1/gpo/import", server.trim_end_matches('/'));
    let mut req = agent
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "gzip")
        .header("User-Agent", concat!("gpo-client/", env!("CARGO_PKG_VERSION")));
    if let Some(t) = &cli.token {
        req = req.header("X-Api-Key", t);
    }
    let mut resp = req.send(&gz[..]).with_context(|| format!("Server {url} nicht erreichbar"))?;
    if !resp.status().is_success() {
        let body = resp.body_mut().read_to_string().unwrap_or_default();
        bail!("Server antwortete mit {}: {}", resp.status(), body.trim());
    }
    let v: serde_json::Value = resp.body_mut().read_json()?;
    println!("Übertragen: {} GPOs übernommen, {} Befunde insgesamt.", v["gpos"], v["findings"]);
    Ok(())
}
