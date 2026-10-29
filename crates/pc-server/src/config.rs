use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Adresse und Port, z. B. `0.0.0.0:8080`.
    pub listen: String,
    /// PostgreSQL-Verbindung, z. B. `postgres://permcenter:geheim@db:5432/permcenter`.
    pub database_url: String,
    /// Maximale Anzahl DB-Verbindungen im Pool.
    pub database_pool_size: usize,
    /// Erlaubte Client-Tokens (Header `X-Api-Key`). Leer = Uploads ohne Token.
    pub api_tokens: Vec<String>,
    /// Maximale Upload-Größe in MiB (unkomprimiert).
    pub max_upload_mb: usize,
    /// Ablage der Client-Releases für OTA-Updates.
    pub client_releases_dir: PathBuf,
    /// Öffentlicher Ed25519-Schlüssel (Base64). Wenn gesetzt, nimmt der Server nur korrekt signierte Releases an.
    pub client_update_public_key: Option<String>,
    pub auth: AuthConfig,
    pub ldap: LdapConfig,
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Kein Login (aktueller Stand laut Aufgabenstellung).
    #[default]
    None,
    /// Anmeldung gegen das AD per LDAP-Bind (vorbereitet, noch nicht aktiv).
    Ldap,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    pub mode: AuthMode,
    /// AD-Gruppe (sAMAccountName), deren Mitglieder sich anmelden dürfen.
    pub allowed_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LdapConfig {
    /// z. B. `ldaps://dc01.firma.local:636` oder `ldap://dc01.firma.local`.
    pub url: Option<String>,
    /// Bind-Benutzer, z. B. `svc-permcenter@firma.local`.
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    /// Such-Basis, z. B. `DC=firma,DC=local`.
    pub base_dn: Option<String>,
    /// StartTLS bei `ldap://` verwenden.
    pub starttls: bool,
    /// Zertifikatsprüfung abschalten (nur für Tests).
    pub no_tls_verify: bool,
    /// Automatische Synchronisation in Minuten (0 = aus).
    pub sync_interval_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    /// Benutzer ohne Anmeldung seit so vielen Tagen gelten als inaktiv.
    pub inactive_days: i64,
    /// Systeme ohne Scan seit so vielen Tagen gelten als veraltet.
    pub stale_scan_days: i64,
    /// Explizite Rechte ab dieser Tiefe gelten als zu tief verschachtelt.
    pub deep_explicit_depth: i64,
    /// Maximale Anzahl Einzelbefunde je Regel und System.
    pub max_findings_per_rule: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".into(),
            database_url: "postgres://permcenter:permcenter@localhost:5432/permcenter".into(),
            database_pool_size: 16,
            api_tokens: Vec::new(),
            max_upload_mb: 512,
            client_releases_dir: PathBuf::from("client-releases"),
            client_update_public_key: None,
            auth: AuthConfig::default(),
            ldap: LdapConfig::default(),
            analysis: AnalysisConfig::default(),
        }
    }
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: None,
            bind_dn: None,
            bind_password: None,
            base_dn: None,
            starttls: false,
            no_tls_verify: false,
            sync_interval_minutes: 0,
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            inactive_days: 90,
            stale_scan_days: 7,
            deep_explicit_depth: 6,
            max_findings_per_rule: 500,
        }
    }
}

impl LdapConfig {
    pub fn is_configured(&self) -> bool {
        self.url.is_some() && self.base_dn.is_some()
    }
}

impl ServerConfig {
    pub fn load(path: Option<&Path>) -> Result<(Self, Option<PathBuf>)> {
        let path = match path {
            Some(p) => p.to_path_buf(),
            None => {
                let p = PathBuf::from("pc-server.toml");
                if !p.is_file() {
                    let mut cfg = Self::default();
                    cfg.apply_env();
                    return Ok((cfg, None));
                }
                p
            }
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("Konfiguration {} nicht lesbar", path.display()))?;
        let mut cfg: Self = toml::from_str(&text)
            .with_context(|| format!("Konfiguration {} fehlerhaft", path.display()))?;
        cfg.apply_env();
        Ok((cfg, Some(path)))
    }

    /// Umgebungsvariablen überschreiben die Datei (für Docker/Compose).
    pub fn apply_env(&mut self) {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if let Some(v) = env("PC_LISTEN") {
            self.listen = v;
        }
        if let Some(v) = env("PC_DATABASE_URL") {
            self.database_url = v;
        }
        if let Some(v) = env("PC_API_TOKENS") {
            self.api_tokens = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if let Some(v) = env("PC_CLIENT_RELEASES_DIR") {
            self.client_releases_dir = PathBuf::from(v);
        }
        if let Some(v) = env("PC_CLIENT_UPDATE_PUBLIC_KEY") {
            self.client_update_public_key = Some(v);
        }
        if let Some(v) = env("PC_LDAP_URL") {
            self.ldap.url = Some(v);
        }
        if let Some(v) = env("PC_LDAP_BIND_DN") {
            self.ldap.bind_dn = Some(v);
        }
        if let Some(v) = env("PC_LDAP_BIND_PASSWORD") {
            self.ldap.bind_password = Some(v);
        }
        if let Some(v) = env("PC_LDAP_BASE_DN") {
            self.ldap.base_dn = Some(v);
        }
        if let Some(v) = env("PC_LDAP_SYNC_INTERVAL_MINUTES").and_then(|v| v.parse().ok()) {
            self.ldap.sync_interval_minutes = v;
        }
    }
}
