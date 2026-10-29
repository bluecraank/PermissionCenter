//! PermissionCenter-Client.
//!
//! Scannt Ordnerberechtigungen auf lokalen Laufwerken, Freigaben und
//! Netzlaufwerken, speichert die Ergebnisse in einer lokalen SQLite-DB und
//! überträgt sie an den PermissionCenter-Server.

mod acl;
mod config;
mod exclude;
mod localdb;
mod logging;
mod scanner;
mod service;
mod update;
mod upload;
mod win;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info, warn};

use config::ClientConfig;
use localdb::LocalDb;
use pc_common::ReportMode;

#[derive(Parser)]
#[command(
    name = "pc-client",
    version,
    about = "PermissionCenter-Client – Berechtigungsscanner für Windows-Server"
)]
struct Cli {
    /// Pfad zur Konfigurationsdatei (Standard: neben der EXE oder %ProgramData%\PermissionCenter\pc-client.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Ausführliche Protokollierung
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan ausführen, lokal speichern und an den Server senden
    Scan {
        /// Nur diese Pfade scannen (überschreibt Laufwerke/Freigaben aus der Konfiguration)
        #[arg(long = "path")]
        paths: Vec<String>,
        /// Report-Modus überschreiben
        #[arg(long, value_parser = parse_mode)]
        mode: Option<ReportMode>,
        /// Nicht an den Server senden
        #[arg(long)]
        no_upload: bool,
        /// Server-URL überschreiben
        #[arg(long)]
        server: Option<String>,
        /// Report zusätzlich als JSON-Datei speichern
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Noch nicht übertragene Scans an den Server senden
    Upload {
        #[arg(long)]
        server: Option<String>,
    },
    /// Nach neuer Client-Version suchen und installieren (OTA)
    Update {
        /// Nur prüfen, nicht installieren
        #[arg(long)]
        check: bool,
        #[arg(long)]
        server: Option<String>,
    },
    /// Gespeicherte Scans anzeigen
    Status,
    /// Verwaiste SIDs (gelöschte Konten) aus dem letzten Scan anzeigen
    Orphans,
    /// Report als JSON exportieren
    Export {
        /// Scan-UUID, ID oder `latest`
        #[arg(long, default_value = "latest")]
        scan: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Standardkonfiguration ausgeben oder schreiben
    InitConfig {
        /// Zieldatei (ohne Angabe: Ausgabe auf stdout)
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Systeminformationen und Freigaben anzeigen (Diagnose)
    Info,
    /// Letzte Zeilen der Logdatei anzeigen
    Logs {
        /// Anzahl Zeilen
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Nur Warnungen und Fehler
        #[arg(long)]
        errors: bool,
    },
    /// Windows-Dienst verwalten (Alternative zur geplanten Aufgabe)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Dienst registrieren (LocalSystem, automatischer Start, Neustart bei Fehlern)
    Install,
    /// Dienst entfernen
    Uninstall,
    /// Dienst starten
    Start,
    /// Dienst stoppen
    Stop,
    /// Wird vom Dienststeuerungs-Manager aufgerufen (nicht manuell starten)
    Run,
}

fn parse_mode(s: &str) -> Result<ReportMode, String> {
    match s {
        "full" => Ok(ReportMode::Full),
        "relevant" => Ok(ReportMode::Relevant),
        _ => Err("erlaubt: full, relevant".into()),
    }
}

fn main() {
    let cli = Cli::parse();
    // Konfiguration vor dem Logging laden – sie bestimmt Logverzeichnis und -level.
    let (cfg, cfg_path) = match ClientConfig::load(cli.config.as_deref()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Konfiguration fehlerhaft: {e:#}");
            std::process::exit(2);
        }
    };
    let is_service = matches!(
        cli.command,
        Command::Service {
            action: ServiceAction::Run
        }
    );
    let _log = logging::init(&cfg.logging, !is_service, cli.verbose);
    let cmd_name = command_name(&cli.command);
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let span = tracing::info_span!("run", id = %&run_id[..8], cmd = %cmd_name);
    let _enter = span.enter();
    logging::log_startup(cmd_name);
    match &cfg_path {
        Some(p) => info!(target: logging::RUN_TARGET, "Konfiguration: {}", p.display()),
        None => {
            info!(target: logging::RUN_TARGET, "Keine Konfigurationsdatei gefunden – Standardwerte aktiv")
        }
    }
    let started = std::time::Instant::now();
    let result = run(cli, cfg, cfg_path);
    match &result {
        Ok(()) => {
            info!(target: logging::RUN_TARGET, "Beendet nach {:.1}s", started.elapsed().as_secs_f64())
        }
        // `{:#}` gibt die vollständige Ursachenkette aus
        Err(e) => error!(
            "Abgebrochen nach {:.1}s: {e:#}",
            started.elapsed().as_secs_f64()
        ),
    }
    drop(_enter);
    drop(_log);
    if result.is_err() {
        std::process::exit(1);
    }
}

fn command_name(c: &Command) -> &'static str {
    match c {
        Command::Scan { .. } => "scan",
        Command::Upload { .. } => "upload",
        Command::Update { .. } => "update",
        Command::Status => "status",
        Command::Orphans => "orphans",
        Command::Export { .. } => "export",
        Command::InitConfig { .. } => "init-config",
        Command::Info => "info",
        Command::Logs { .. } => "logs",
        Command::Service { action } => match action {
            ServiceAction::Install => "service-install",
            ServiceAction::Uninstall => "service-uninstall",
            ServiceAction::Start => "service-start",
            ServiceAction::Stop => "service-stop",
            ServiceAction::Run => "service",
        },
    }
}

fn run(cli: Cli, mut cfg: ClientConfig, cfg_path: Option<PathBuf>) -> Result<()> {
    update::cleanup();

    match cli.command {
        Command::Scan {
            paths,
            mode,
            no_upload,
            server,
            out,
        } => {
            if let Some(m) = mode {
                cfg.scan.report_mode = m;
            }
            if server.is_some() {
                cfg.server.url = server;
            }
            // OTA-Update vor dem Scan; die neue Version führt den Scan dann selbst aus.
            let restarted = std::env::var_os(update::ENV_RESTARTED).is_some();
            if cfg.update.auto_update && cfg.server.url.is_some() && !no_upload && !restarted {
                match update::run(&cfg, true) {
                    Ok(update::Outcome::Installed(_)) => std::process::exit(update::restart()?),
                    Ok(_) => {}
                    Err(e) => warn!("Update übersprungen: {e:#}"),
                }
            }
            scan_store_upload(&cfg, &paths, out.as_deref(), no_upload)?;
        }
        Command::Upload { server } => {
            if server.is_some() {
                cfg.server.url = server;
            }
            let db = LocalDb::open(&cfg.db_path())?;
            upload_pending(&cfg, &db)?;
        }
        Command::Update { check, server } => {
            if server.is_some() {
                cfg.server.url = server;
            }
            match update::run(&cfg, !check)? {
                update::Outcome::UpToDate => {
                    println!("Client ist aktuell (Version {}).", update::CURRENT)
                }
                update::Outcome::Available(r) => {
                    println!(
                        "Neue Version verfügbar: {} → {} ({})",
                        update::CURRENT,
                        r.version,
                        r.notes.unwrap_or_default()
                    )
                }
                update::Outcome::Installed(r) => {
                    println!("Aktualisiert: {} → {}", update::CURRENT, r.version)
                }
            }
        }
        Command::Status => {
            let db = LocalDb::open(&cfg.db_path())?;
            println!("Lokale DB: {}", cfg.db_path().display());
            println!(
                "{:>4}  {:<36}  {:<25}  {:<8}  {:>9}  {:>9}  {:>6}  {:>7}  Upload",
                "ID", "Scan", "Beendet", "Modus", "Gescannt", "Gemeldet", "Fehler", "Verwaist"
            );
            for s in db.list()? {
                let up = match (&s.uploaded_at, &s.upload_error) {
                    (Some(t), _) => format!("ok {t}"),
                    (None, Some(e)) => format!("ausstehend ({}x, {e})", s.upload_attempts),
                    (None, None) => "ausstehend".into(),
                };
                println!(
                    "{:>4}  {:<36}  {:<25}  {:<8}  {:>9}  {:>9}  {:>6}  {:>7}  {}",
                    s.id,
                    s.scan_uuid,
                    &s.finished_at[..s.finished_at.len().min(25)],
                    s.report_mode,
                    s.folders_scanned,
                    s.folders_reported,
                    s.errors,
                    s.orphaned_aces,
                    up
                );
            }
        }
        Command::Orphans => {
            let db = LocalDb::open(&cfg.db_path())?;
            let rows = db.orphans()?;
            if rows.is_empty() {
                println!("Keine verwaisten SIDs mit expliziten Berechtigungen gefunden.");
            }
            for r in rows {
                println!(
                    "{:<50} {:>6} Ordner  z. B. {}",
                    r.sid, r.folders, r.example_path
                );
            }
        }
        Command::Export { scan, out } => {
            let db = LocalDb::open(&cfg.db_path())?;
            let payload = db
                .payload(&scan)?
                .with_context(|| format!("Scan '{scan}' nicht gefunden"))?;
            let report = localdb::decompress(&payload)?;
            std::fs::write(&out, serde_json::to_vec_pretty(&report)?)?;
            println!("Exportiert: {}", out.display());
        }
        Command::InitConfig { out, force } => {
            let text = config::TEMPLATE;
            match out {
                Some(p) => {
                    if p.exists() && !force {
                        anyhow::bail!(
                            "{} existiert bereits (--force zum Überschreiben)",
                            p.display()
                        );
                    }
                    std::fs::write(&p, text)?;
                    println!("Konfiguration geschrieben: {}", p.display());
                }
                None => print!("{text}"),
            }
        }
        Command::Logs { lines, errors } => {
            let dir = cfg.logging.dir();
            let file = logging::latest_file(&dir)
                .with_context(|| format!("Keine Logdatei in {}", dir.display()))?;
            let text = std::fs::read_to_string(&file)?;
            let rows: Vec<&str> = text
                .lines()
                .filter(|l| !errors || l.contains(" WARN ") || l.contains(" ERROR "))
                .collect();
            println!("== {} ==", file.display());
            for l in &rows[rows.len().saturating_sub(lines)..] {
                println!("{l}");
            }
        }
        Command::Service { action } => match action {
            ServiceAction::Install => service::install(cfg_path.as_deref())?,
            ServiceAction::Uninstall => service::uninstall()?,
            ServiceAction::Start => service::start()?,
            ServiceAction::Stop => service::stop()?,
            ServiceAction::Run => service::run_dispatcher(cfg)?,
        },
        Command::Info => {
            let h = win::system::host_info();
            println!("Host:        {}", h.hostname);
            println!("Domäne:      {}", h.domain.as_deref().unwrap_or("-"));
            println!("OS:          {} – {}", h.os_name, h.os_version);
            println!(
                "DC:          {}",
                if h.is_domain_controller { "ja" } else { "nein" }
            );
            println!(
                "Admin:       {}",
                if win::system::is_elevated() {
                    "ja"
                } else {
                    "nein"
                }
            );
            println!(
                "Laufwerke:   {}",
                win::system::drives(win::system::DRIVE_FIXED).join(", ")
            );
            println!(
                "Netzlaufw.:  {}",
                win::system::drives(win::system::DRIVE_REMOTE).join(", ")
            );
            println!("Lokale DB:   {}", cfg.db_path().display());
            match win::shares::enumerate() {
                Ok(shares) => {
                    println!("Freigaben:");
                    for s in shares {
                        let perms = match &s.permissions {
                            None => "Jeder: Vollzugriff (kein SD)".to_string(),
                            Some(p) => format!("{} Einträge", p.len()),
                        };
                        println!(
                            "  {:<20} {:<40} {}{}",
                            s.name,
                            s.path,
                            perms,
                            if s.is_special { " [Standard]" } else { "" }
                        );
                    }
                }
                Err(e) => println!("Freigaben:   {e}"),
            }
        }
    }
    Ok(())
}

/// Scan ausführen, lokal speichern, alte Scans aufräumen und hochladen.
pub fn scan_store_upload(
    cfg: &ClientConfig,
    paths: &[String],
    out: Option<&std::path::Path>,
    no_upload: bool,
) -> Result<()> {
    let report = scanner::run(&cfg.scan, paths, cfg.logging.max_logged_scan_errors)?;
    if let Some(out) = out {
        std::fs::write(out, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("{} nicht schreibbar", out.display()))?;
        info!("Report gespeichert: {}", out.display());
    }
    let mut db = LocalDb::open(&cfg.db_path())?;
    db.store(&report)?;
    let pruned = db.prune(cfg.storage.keep_scans)?;
    if pruned > 0 {
        info!("{pruned} alte Scans aus lokaler DB entfernt");
    }
    if no_upload {
        info!("Upload übersprungen (--no-upload)");
    } else if cfg.server.url.is_none() {
        warn!("Keine Server-URL konfiguriert – Report bleibt in der lokalen Warteschlange");
    } else {
        upload_pending(cfg, &db)?;
    }
    Ok(())
}

fn upload_pending(cfg: &ClientConfig, db: &LocalDb) -> Result<()> {
    let up = upload::ServerClient::new(&cfg.server)?;
    let pending = db.pending()?;
    if pending.is_empty() {
        info!("Keine ausstehenden Scans");
        return Ok(());
    }
    let mut failed = 0;
    for (id, payload) in pending {
        match up.send_report(&payload) {
            Ok(r) => {
                db.mark_uploaded(id)?;
                info!(
                    "Scan {id} übertragen (System-ID {}, {} Befunde)",
                    r.system_id, r.findings
                );
            }
            Err(e) => {
                failed += 1;
                db.mark_failed(id, &format!("{e:#}"))?;
                warn!("Upload von Scan {id} fehlgeschlagen: {e:#}");
            }
        }
    }
    if failed > 0 {
        anyhow::bail!("{failed} Scan(s) konnten nicht übertragen werden – erneuter Versuch mit `pc-client upload`");
    }
    Ok(())
}
