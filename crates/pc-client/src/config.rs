use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use pc_common::ReportMode;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE_NAME: &str = "pc-client.toml";

/// Kommentierte Vorlage für `pc-client init-config`; entspricht den Standardwerten.
pub const TEMPLATE: &str = include_str!("config_template.toml");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    pub server: ServerConfig,
    pub scan: ScanConfig,
    pub storage: StorageConfig,
    pub update: UpdateConfig,
    pub logging: LoggingConfig,
    pub service: ServiceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Basis-URL des Servers, z. B. `https://permcenter.firma.local:8443`.
    pub url: Option<String>,
    /// Token, das der Server für Uploads erwartet (Header `X-Api-Key`).
    pub api_token: Option<String>,
    /// Zertifikatsprüfung abschalten (nur für Tests mit selbstsignierten Zertifikaten).
    pub accept_invalid_certs: bool,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Alle lokalen Festplatten scannen.
    pub local_drives: bool,
    /// Nur diese Laufwerke (z. B. `["D:", "E:"]`); leer = alle festen Laufwerke.
    pub drives: Vec<String>,
    /// Lokale Freigaben (NetShareEnum) erfassen und deren Pfade scannen.
    pub shares: bool,
    /// Verbundene Netzlaufwerke (Laufwerkstyp REMOTE) scannen.
    pub mapped_drives: bool,
    /// Zusätzliche Pfade, auch UNC (`\\server\freigabe`).
    pub extra_paths: Vec<String>,
    /// Ausschlüsse. `?:` = beliebiges Laufwerk, `*`/`?` als Platzhalter je
    /// Pfadsegment, `%VAR%` wird expandiert.
    pub exclude: Vec<String>,
    /// Ordner mit Attribut SYSTEM+HIDDEN automatisch überspringen.
    pub skip_system_hidden: bool,
    /// Maximale Tiefe ab Scan-Root (None = unbegrenzt).
    pub max_depth: Option<u32>,
    /// `relevant` oder `full`.
    pub report_mode: ReportMode,
    /// Ebenen, die im Modus `relevant` immer gemeldet werden (Gerüst des Baums).
    pub skeleton_depth: u32,
}

/// Protokollierung in Datei (zusätzlich zur Konsole).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Verzeichnis der Logdateien (Standard: %ProgramData%\PermissionCenter\logs).
    pub dir: Option<PathBuf>,
    /// trace, debug, info, warn, error – oder ein Filter wie `info,pc_client=debug`.
    pub level: String,
    /// Anzahl aufbewahrter Tageslogs.
    pub keep_days: usize,
    /// Einzelne Lesefehler (Zugriff verweigert …) bis zu dieser Anzahl je Scan als Warnung protokollieren.
    pub max_logged_scan_errors: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            dir: None,
            level: "info".into(),
            keep_days: 30,
            max_logged_scan_errors: 200,
        }
    }
}

impl LoggingConfig {
    pub fn dir(&self) -> PathBuf {
        self.dir.clone().unwrap_or_else(|| data_dir().join("logs"))
    }
}

/// Zeitplan im Dienstbetrieb (`pc-client service install`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceConfig {
    /// Tägliche Scan-Uhrzeit (Ortszeit, HH:MM). Wird ignoriert, wenn `interval_hours` gesetzt ist.
    pub scan_time: String,
    /// Alternativ: Scan alle n Stunden.
    pub interval_hours: Option<u32>,
    /// Direkt nach dem Dienststart einmal scannen.
    pub scan_on_start: bool,
    /// Abstand der Update-Prüfung in Minuten (0 = nur vor Scans).
    pub update_check_minutes: u64,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            scan_time: "02:00".into(),
            interval_hours: None,
            scan_on_start: false,
            update_check_minutes: 60,
        }
    }
}

/// OTA-Updates über den PermissionCenter-Server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateConfig {
    /// Vor jedem Scan nach einer neuen Client-Version suchen und sie installieren.
    pub auto_update: bool,
    /// Öffentlicher Ed25519-Schlüssel (Base64) zur Prüfung der Release-Signatur.
    pub public_key: Option<String>,
    /// Nur signierte Releases installieren (dringend empfohlen).
    pub require_signature: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            auto_update: true,
            public_key: None,
            require_signature: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Pfad der lokalen SQLite-Datenbank.
    pub db_path: Option<PathBuf>,
    /// Anzahl aufbewahrter Scans in der lokalen DB.
    pub keep_scans: u32,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            scan: ScanConfig::default(),
            storage: StorageConfig::default(),
            update: UpdateConfig::default(),
            logging: LoggingConfig::default(),
            service: ServiceConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: None,
            api_token: None,
            accept_invalid_certs: false,
            timeout_secs: 300,
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            local_drives: true,
            drives: Vec::new(),
            shares: true,
            mapped_drives: false,
            extra_paths: Vec::new(),
            exclude: default_excludes(),
            skip_system_hidden: true,
            max_depth: None,
            report_mode: ReportMode::Relevant,
            skeleton_depth: 2,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: None,
            keep_scans: 10,
        }
    }
}

/// Systembekannte Ordner, die standardmäßig nicht gescannt werden.
pub fn default_excludes() -> Vec<String> {
    [
        "%SystemRoot%",
        "%ProgramFiles%",
        "%ProgramFiles(x86)%",
        "%ProgramData%",
        "?:\\Windows",
        "?:\\Windows.old",
        "?:\\Program Files",
        "?:\\Program Files (x86)",
        "?:\\ProgramData",
        "?:\\$Recycle.Bin",
        "?:\\System Volume Information",
        "?:\\Recovery",
        "?:\\PerfLogs",
        "?:\\Config.Msi",
        "?:\\Boot",
        "?:\\MSOCache",
        "?:\\$WinREAgent",
        "?:\\$Windows.~BT",
        "?:\\$Windows.~WS",
        "?:\\$SysReset",
        "?:\\$GetCurrent",
        "?:\\Users\\Default",
        "?:\\Users\\*\\AppData",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl ClientConfig {
    /// Lädt die Konfiguration: expliziter Pfad, sonst neben der EXE, sonst
    /// `%ProgramData%\PermissionCenter`, sonst Standardwerte.
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>)> {
        let candidates: Vec<PathBuf> = match explicit {
            Some(p) => vec![p.to_path_buf()],
            None => default_config_candidates(),
        };
        for path in candidates {
            if path.is_file() {
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("Konfiguration {} nicht lesbar", path.display()))?;
                let cfg: ClientConfig = toml::from_str(&text)
                    .with_context(|| format!("Konfiguration {} fehlerhaft", path.display()))?;
                return Ok((cfg, Some(path)));
            }
            if explicit.is_some() {
                anyhow::bail!("Konfigurationsdatei {} nicht gefunden", path.display());
            }
        }
        Ok((Self::default(), None))
    }

    pub fn db_path(&self) -> PathBuf {
        self.storage
            .db_path
            .clone()
            .unwrap_or_else(|| data_dir().join("pc-client.db"))
    }

    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }
}

/// `%ProgramData%\PermissionCenter`
pub fn data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
        .join("PermissionCenter")
}

fn default_config_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join(CONFIG_FILE_NAME));
        }
    }
    v.push(data_dir().join(CONFIG_FILE_NAME));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_matches_defaults() {
        let t: ClientConfig = toml::from_str(TEMPLATE).unwrap();
        assert_eq!(
            toml::to_string(&t).unwrap(),
            toml::to_string(&ClientConfig::default()).unwrap()
        );
    }

    #[test]
    fn default_roundtrip() {
        let cfg = ClientConfig::default();
        let text = cfg.to_toml().unwrap();
        let back: ClientConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.scan.exclude, cfg.scan.exclude);
        let partial: ClientConfig = toml::from_str("[server]\nurl = \"http://x\"\n").unwrap();
        assert_eq!(partial.server.url.as_deref(), Some("http://x"));
        assert!(partial.scan.shares);
    }
}
