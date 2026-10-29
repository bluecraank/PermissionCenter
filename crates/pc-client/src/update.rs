//! OTA-Selbstaktualisierung des Clients.
//!
//! Ablauf: neueste Version beim Server abfragen → herunterladen → Größe,
//! SHA-256 und Ed25519-Signatur prüfen → laufende EXE nach `.old` umbenennen
//! (unter Windows erlaubt) → neue EXE an ihre Stelle verschieben. Beim
//! nächsten Start wird `.old` entfernt.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{info, warn};

use crate::config::ClientConfig;
use crate::upload::ServerClient;
use pc_common::release::{compare_versions, is_valid_version, sha256_hex, verify, ClientRelease};

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// Gesetzt, wenn sich der Client nach einem Update selbst neu gestartet hat (verhindert Schleifen).
pub const ENV_RESTARTED: &str = "PC_CLIENT_UPDATED";
const MAX_EXE_BYTES: u64 = 200 * 1024 * 1024;

pub enum Outcome {
    UpToDate,
    Available(ClientRelease),
    Installed(ClientRelease),
}

fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut s = exe.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Entfernt Reste eines früheren Updates.
pub fn cleanup() {
    if let Ok(exe) = std::env::current_exe() {
        for suffix in [".old", ".new"] {
            let p = sibling(&exe, suffix);
            if p.exists() && std::fs::remove_file(&p).is_ok() {
                info!("Altversion {} entfernt", p.display());
            }
        }
    }
}

/// Prüft auf ein Update und installiert es, wenn `install` gesetzt ist.
pub fn run(cfg: &ClientConfig, install: bool) -> Result<Outcome> {
    let server = ServerClient::new(&cfg.server)?;
    let Some(rel) = server.latest_release()? else {
        info!("Kein Client-Release auf dem Server veröffentlicht");
        return Ok(Outcome::UpToDate);
    };
    if !is_valid_version(&rel.version)
        || compare_versions(&rel.version, CURRENT) != Ordering::Greater
    {
        info!("Client ist aktuell ({CURRENT}, Server: {})", rel.version);
        return Ok(Outcome::UpToDate);
    }
    info!("Neue Client-Version verfügbar: {CURRENT} → {}", rel.version);
    if !install {
        return Ok(Outcome::Available(rel));
    }

    // Signaturprüfung vor dem Download klären
    match (&cfg.update.public_key, &rel.signature, cfg.update.require_signature) {
        (None, _, true) => bail!(
            "Update abgelehnt: kein öffentlicher Schlüssel konfiguriert ([update] public_key) und require_signature = true"
        ),
        (Some(_), None, _) => bail!("Update abgelehnt: Release {} ist nicht signiert", rel.version),
        _ => {}
    }

    let bytes = server.download(&rel.download_url, MAX_EXE_BYTES)?;
    if bytes.len() as u64 != rel.size {
        bail!(
            "Update abgelehnt: Größe {} statt {} Byte",
            bytes.len(),
            rel.size
        );
    }
    let hash = sha256_hex(&bytes);
    if !hash.eq_ignore_ascii_case(&rel.sha256) {
        bail!("Update abgelehnt: SHA-256 stimmt nicht überein");
    }
    if let (Some(pk), Some(sig)) = (&cfg.update.public_key, &rel.signature) {
        verify(pk, &rel.version, &hash, sig).map_err(|e| anyhow!("Update abgelehnt: {e}"))?;
        info!("Signatur von {} gültig", rel.version);
    } else {
        warn!(
            "Update {} wird OHNE Signaturprüfung installiert",
            rel.version
        );
    }
    if bytes.len() < 2 || &bytes[..2] != b"MZ" {
        bail!("Update abgelehnt: keine Windows-EXE");
    }

    replace_self(&bytes)?;
    info!("Client auf Version {} aktualisiert", rel.version);
    Ok(Outcome::Installed(rel))
}

fn replace_self(bytes: &[u8]) -> Result<()> {
    let exe = std::env::current_exe().context("Pfad der EXE unbekannt")?;
    let new = sibling(&exe, ".new");
    let old = sibling(&exe, ".old");
    std::fs::write(&new, bytes).with_context(|| format!("{} nicht schreibbar", new.display()))?;
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old).with_context(|| format!("{} nicht umbenennbar", exe.display()))?;
    if let Err(e) = std::fs::rename(&new, &exe) {
        // Zurückrollen, damit der Client lauffähig bleibt
        let _ = std::fs::rename(&old, &exe);
        return Err(anyhow!("Neue Version nicht aktivierbar: {e}"));
    }
    Ok(())
}

/// Startet die (neue) EXE mit denselben Argumenten und gibt deren Exit-Code zurück.
pub fn restart() -> Result<i32> {
    let exe = std::env::current_exe()?;
    let status = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(ENV_RESTARTED, "1")
        .status()
        .context("Neustart nach Update fehlgeschlagen")?;
    Ok(status.code().unwrap_or(1))
}
