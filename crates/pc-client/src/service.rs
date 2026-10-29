//! Betrieb als Windows-Dienst „PermissionCenterClient“.
//!
//! Der Dienst scannt nach Zeitplan (`[service]`), prüft regelmäßig auf
//! OTA-Updates und beendet sich nach einem Update mit Fehlercode – die
//! Wiederherstellungsoptionen des Dienstes starten ihn dann mit der neuen
//! Version neu.

use std::ffi::OsString;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{Local, NaiveTime, TimeDelta};
use tracing::{error, info, warn};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::ClientConfig;
use crate::update;

pub const SERVICE_NAME: &str = "PermissionCenterClient";
const DISPLAY_NAME: &str = "PermissionCenter Client";
const DESCRIPTION: &str =
    "Scannt NTFS- und Freigabeberechtigungen und überträgt sie an den PermissionCenter-Server.";
/// Exit-Code nach erfolgreichem Update → Dienst-Wiederherstellung startet neu.
const EXIT_UPDATED: u32 = 10;

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
        .context("Dienststeuerung nicht erreichbar (Administratorrechte?)")
}

pub fn install(config: Option<&Path>) -> Result<()> {
    let exe = std::env::current_exe()?;
    let mut args: Vec<OsString> = Vec::new();
    if let Some(c) = config {
        let abs = std::fs::canonicalize(c).unwrap_or_else(|_| c.to_path_buf());
        // canonicalize liefert \\?\-Pfade; für die Dienstbefehlszeile normalisieren
        let s = abs
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_string();
        args.push("--config".into());
        args.push(s.into());
    }
    args.push("service".into());
    args.push("run".into());

    let mgr = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments: args,
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = mgr
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("Dienst konnte nicht angelegt werden (existiert er bereits?)")?;
    svc.set_description(DESCRIPTION)?;
    svc.set_delayed_auto_start(true)?;
    // Neustart nach Absturz oder Update (Exit-Code ≠ 0)
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(60),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(300),
            },
        ]),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    info!("Dienst {SERVICE_NAME} installiert ({})", exe.display());
    println!("Dienst „{DISPLAY_NAME}“ installiert. Starten mit: pc-client service start");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let mgr = manager(ServiceManagerAccess::CONNECT)?;
    let svc = mgr
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("Dienst nicht gefunden")?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        std::thread::sleep(Duration::from_secs(2));
    }
    svc.delete()?;
    info!("Dienst {SERVICE_NAME} entfernt");
    println!("Dienst entfernt.");
    Ok(())
}

pub fn start() -> Result<()> {
    let mgr = manager(ServiceManagerAccess::CONNECT)?;
    let svc = mgr
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .context("Dienst nicht gefunden")?;
    svc.start::<&str>(&[])?;
    println!("Dienst gestartet.");
    Ok(())
}

pub fn stop() -> Result<()> {
    let mgr = manager(ServiceManagerAccess::CONNECT)?;
    let svc = mgr
        .open_service(SERVICE_NAME, ServiceAccess::STOP)
        .context("Dienst nicht gefunden")?;
    svc.stop()?;
    println!("Dienst wird gestoppt.");
    Ok(())
}

// --- Dienstbetrieb -----------------------------------------------------------

static CONFIG: std::sync::OnceLock<ClientConfig> = std::sync::OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn run_dispatcher(cfg: ClientConfig) -> Result<()> {
    let _ = CONFIG.set(cfg);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Nur über die Dienststeuerung startbar (pc-client service start)")?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    // Lauf-ID des Hauptthreads gilt hier nicht – eigener Span für den Dienst
    let span = tracing::info_span!("service");
    let _e = span.enter();
    if let Err(e) = service_loop() {
        error!("Dienst beendet mit Fehler: {e:#}");
    }
}

fn status(state: ServiceState, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: if exit == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(exit)
        },
        checkpoint: 0,
        wait_hint: Duration::from_secs(if state == ServiceState::StopPending {
            30
        } else {
            0
        }),
        process_id: None,
    }
}

/// Nächster Scan-Zeitpunkt ab jetzt.
fn next_scan(cfg: &ClientConfig, last: Option<Instant>) -> Instant {
    if let Some(h) = cfg.service.interval_hours.filter(|h| *h > 0) {
        let every = Duration::from_secs(u64::from(h) * 3600);
        return last
            .map(|l| l + every)
            .unwrap_or_else(|| Instant::now() + every);
    }
    let time = NaiveTime::parse_from_str(&cfg.service.scan_time, "%H:%M").unwrap_or_else(|_| {
        warn!(
            "service.scan_time „{}“ ungültig – verwende 02:00",
            cfg.service.scan_time
        );
        NaiveTime::from_hms_opt(2, 0, 0).expect("gültige Zeit")
    });
    let now = Local::now();
    let mut target = now.date_naive().and_time(time);
    if target <= now.naive_local() + TimeDelta::seconds(30) {
        target += TimeDelta::days(1);
    }
    let wait = (target - now.naive_local())
        .to_std()
        .unwrap_or(Duration::from_secs(3600));
    Instant::now() + wait
}

fn service_loop() -> Result<()> {
    let cfg = CONFIG.get().context("Konfiguration fehlt")?.clone();
    let (tx, rx) = mpsc::channel::<()>();
    let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::Running, 0))?;
    info!(
        "Dienst gestartet (Version {}), Zeitplan: {}",
        update::CURRENT,
        match cfg.service.interval_hours {
            Some(h) if h > 0 => format!("alle {h} Stunden"),
            _ => format!("täglich {}", cfg.service.scan_time),
        }
    );

    let update_every = Duration::from_secs(cfg.service.update_check_minutes * 60);
    let mut next_update = Instant::now() + Duration::from_secs(120);
    let mut scan_at = if cfg.service.scan_on_start {
        Instant::now() + Duration::from_secs(60)
    } else {
        next_scan(&cfg, None)
    };
    info!(
        "Nächster Scan in {} Minuten",
        scan_at.saturating_duration_since(Instant::now()).as_secs() / 60
    );

    let poll_every = Duration::from_secs(cfg.service.task_poll_minutes * 60);
    let polling = cfg.server.url.is_some() && cfg.service.task_poll_minutes > 0;
    let mut next_poll = Instant::now() + Duration::from_secs(30);
    let hostname = crate::win::system::host_info().hostname;

    let mut exit_code = 0;
    loop {
        let mut wake = scan_at;
        if cfg.update.auto_update && cfg.service.update_check_minutes > 0 {
            wake = wake.min(next_update);
        }
        if polling {
            wake = wake.min(next_poll);
        }
        match rx.recv_timeout(wake.saturating_duration_since(Instant::now())) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                info!("Stopp angefordert");
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let now = Instant::now();
        let mut scan_due = now >= scan_at;
        let mut requested = false;
        if polling && now >= next_poll {
            next_poll = now + poll_every.max(Duration::from_secs(60));
            match crate::upload::ServerClient::new(&cfg.server)
                .and_then(|c| c.pending_scan(&hostname))
            {
                Ok(true) => {
                    info!("Scan in der Weboberfläche angefordert");
                    scan_due = true;
                    requested = true;
                }
                Ok(false) => {}
                Err(e) => tracing::debug!("Auftragsabfrage fehlgeschlagen: {e:#}"),
            }
        }
        if cfg.update.auto_update && cfg.server.url.is_some() && (scan_due || now >= next_update) {
            next_update = now + update_every.max(Duration::from_secs(300));
            match update::run(&cfg, true) {
                Ok(update::Outcome::Installed(r)) => {
                    info!("Update auf {} installiert – Dienst startet neu", r.version);
                    exit_code = EXIT_UPDATED;
                    break;
                }
                Ok(_) => {}
                Err(e) => warn!("Update-Prüfung fehlgeschlagen: {e:#}"),
            }
        }
        if scan_due {
            info!(
                "{} startet",
                if requested {
                    "Angeforderter Scan"
                } else {
                    "Geplanter Scan"
                }
            );
            if let Err(e) = crate::scan_store_upload(&cfg, &[], None, false) {
                error!("Scan fehlgeschlagen: {e:#}");
            }
            // Ein angeforderter Scan verschiebt den regulären Zeitplan nicht
            if !requested || Instant::now() >= scan_at {
                scan_at = next_scan(&cfg, Some(Instant::now()));
            }
            info!(
                "Nächster Scan in {} Minuten",
                scan_at.saturating_duration_since(Instant::now()).as_secs() / 60
            );
        }
    }
    handle.set_service_status(status(ServiceState::Stopped, exit_code))?;
    if exit_code != 0 {
        // Prozess mit Fehlercode beenden, damit die Wiederherstellung greift
        std::process::exit(exit_code as i32);
    }
    Ok(())
}
