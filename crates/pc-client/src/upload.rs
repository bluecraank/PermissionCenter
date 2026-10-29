//! Kommunikation mit dem PermissionCenter-Server (Report-Upload, Update-Abfrage).

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use pc_common::release::ClientRelease;
use pc_common::UploadResponse;
use ureq::tls::TlsConfig;
use ureq::Agent;

use crate::config::ServerConfig;

pub struct ServerClient {
    agent: Agent,
    base: String,
    token: Option<String>,
}

impl ServerClient {
    pub fn new(cfg: &ServerConfig) -> Result<Self> {
        let base = cfg
            .url
            .as_deref()
            .ok_or_else(|| anyhow!("Keine Server-URL konfiguriert ([server] url)"))?;
        let agent: Agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(cfg.timeout_secs.max(10))))
            .tls_config(
                TlsConfig::builder()
                    .disable_verification(cfg.accept_invalid_certs)
                    .build(),
            )
            .http_status_as_error(false)
            .build()
            .into();
        Ok(Self {
            agent,
            base: base.trim_end_matches('/').to_string(),
            token: cfg.api_token.clone(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Sendet eine gzip-komprimierte JSON-Nutzlast.
    pub fn send_report(&self, gz_payload: &[u8]) -> Result<UploadResponse> {
        let url = self.url("/api/v1/reports");
        let mut req = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .header(
                "User-Agent",
                concat!("pc-client/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(t) = &self.token {
            req = req.header("X-Api-Key", t);
        }
        let mut resp = req
            .send(gz_payload)
            .with_context(|| format!("Server {url} nicht erreichbar"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(anyhow!("Server antwortete mit {status}: {}", body.trim()));
        }
        Ok(resp.body_mut().read_json::<UploadResponse>()?)
    }

    /// Neuestes veröffentlichtes Client-Release (None, wenn keines vorhanden).
    pub fn latest_release(&self) -> Result<Option<ClientRelease>> {
        let url = self.url("/api/v1/client/latest");
        let mut req = self.agent.get(&url);
        if let Some(t) = &self.token {
            req = req.header("X-Api-Key", t);
        }
        let mut resp = req
            .call()
            .with_context(|| format!("Server {url} nicht erreichbar"))?;
        match resp.status().as_u16() {
            204 | 404 => Ok(None),
            200 => Ok(Some(resp.body_mut().read_json::<ClientRelease>()?)),
            s => Err(anyhow!("Update-Abfrage: Server antwortete mit {s}")),
        }
    }

    /// Lädt eine Datei vom Server (relativer Pfad).
    pub fn download(&self, path: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let url = self.url(path);
        let mut req = self.agent.get(&url);
        if let Some(t) = &self.token {
            req = req.header("X-Api-Key", t);
        }
        let mut resp = req
            .call()
            .with_context(|| format!("Download {url} fehlgeschlagen"))?;
        if !resp.status().is_success() {
            return Err(anyhow!("Download: Server antwortete mit {}", resp.status()));
        }
        Ok(resp
            .body_mut()
            .with_config()
            .limit(max_bytes)
            .read_to_vec()?)
    }
}
