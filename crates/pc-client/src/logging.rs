//! Protokollierung: Konsole (CLI) und rotierende Tagesdatei.
//!
//! Format der Datei:
//! `2026-10-29 14:31:57.841 INFO  [run=3f2a… cmd=scan] scanner: Scan beendet: …`

use std::path::PathBuf;

use tracing::{error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::field::MakeExt;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::LoggingConfig;

pub const FILE_PREFIX: &str = "pc-client";
/// Verwaltungszeilen eines Laufs (Start, Konfiguration, Dauer): nur in der Datei, nicht auf der Konsole.
pub const RUN_TARGET: &str = "pc_client::run";

/// Hält den Hintergrund-Schreiber am Leben; beim Drop werden gepufferte Zeilen geschrieben.
pub struct LogGuard {
    _file: Option<WorkerGuard>,
}

/// Initialisiert das Logging. `console` = Ausgabe auf stderr (im Dienst aus).
pub fn init(cfg: &LoggingConfig, console: bool, verbose: bool) -> LogGuard {
    let timer = ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f".into());
    let console_filter = if verbose {
        "debug".to_string()
    } else {
        "info".to_string()
    };
    let console_layer =
        console.then(|| {
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                // Eigener Feldformatierer: sonst landen ANSI-Farbcodes der Konsole
                // über den gemeinsamen Span-Cache auch in der Logdatei.
                .fmt_fields(
                    tracing_subscriber::fmt::format::debug_fn(|w, field, value| {
                        if field.name() == "message" {
                            write!(w, "{value:?}")
                        } else {
                            write!(w, "{field}={value:?}")
                        }
                    })
                    .delimited(" "),
                )
                .with_target(false)
                .with_timer(timer.clone())
                .with_filter(EnvFilter::try_from_env("PC_LOG").unwrap_or_else(|_| {
                    EnvFilter::new(format!("{console_filter},{RUN_TARGET}=warn"))
                }))
        });

    let dir = cfg.dir();
    let mut file_err = None;
    let (file_layer, guard) = match std::fs::create_dir_all(&dir)
        .map_err(|e| e.to_string())
        .and_then(|_| {
            RollingFileAppender::builder()
                .rotation(Rotation::DAILY)
                .filename_prefix(FILE_PREFIX)
                .filename_suffix("log")
                .max_log_files(cfg.keep_days.max(1))
                .build(&dir)
                .map_err(|e| e.to_string())
        }) {
        Ok(appender) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let level = if verbose {
                "debug".to_string()
            } else {
                cfg.level.clone()
            };
            let layer = tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_timer(timer)
                .with_filter(EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info")));
            (Some(layer), Some(guard))
        }
        Err(e) => {
            file_err = Some(e);
            (None, None)
        }
    };

    tracing_subscriber::registry()
        .with(console_layer)
        .with(file_layer)
        .init();
    install_panic_hook();
    if let Some(e) = file_err {
        warn!(
            "Logdatei in {} nicht möglich ({e}) – nur Konsolenausgabe",
            dir.display()
        );
    }
    LogGuard { _file: guard }
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|p| {
        let loc = p
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let msg = p
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unbekannt".into());
        let bt = std::backtrace::Backtrace::force_capture();
        error!("ABSTURZ (panic) bei {loc}: {msg}\n{bt}");
        eprintln!("ABSTURZ (panic) bei {loc}: {msg}");
    }));
}

/// Kopfzeilen eines Laufs: Version, Prozess, Benutzer, Rechte.
pub fn log_startup(command: &str) {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    info!(
        target: RUN_TARGET,
        "pc-client {} gestartet: Befehl={command}, PID={}, Benutzer={domain}\\{user}, Admin={}, Argumente={:?}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        crate::win::system::is_elevated(),
        std::env::args().skip(1).collect::<Vec<_>>()
    );
}

/// Neueste Logdatei im Verzeichnis.
pub fn latest_file(dir: &std::path::Path) -> Option<PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(FILE_PREFIX))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}
