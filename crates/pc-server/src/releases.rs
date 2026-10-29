//! Ablage der Client-Releases für OTA-Updates.
//!
//! Layout: `<client_releases_dir>/<version>/pc-client.exe` und `release.json`.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;

use pc_common::release::{compare_versions, is_valid_version, sha256_hex, verify, ClientRelease};

pub const EXE_NAME: &str = "pc-client.exe";
const META_NAME: &str = "release.json";

pub fn download_url(version: &str) -> String {
    format!("/api/v1/client/releases/{version}/download")
}

pub fn list(dir: &Path) -> Result<Vec<ClientRelease>> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(out);
    };
    for e in entries.flatten() {
        let meta = e.path().join(META_NAME);
        if !meta.is_file() || !e.path().join(EXE_NAME).is_file() {
            continue;
        }
        match std::fs::read_to_string(&meta).map(|t| serde_json::from_str::<ClientRelease>(&t)) {
            Ok(Ok(mut r)) => {
                r.download_url = download_url(&r.version);
                out.push(r);
            }
            _ => tracing::warn!("Release-Metadaten {} unlesbar", meta.display()),
        }
    }
    out.sort_by(|a, b| compare_versions(&b.version, &a.version));
    Ok(out)
}

pub fn latest(dir: &Path) -> Result<Option<ClientRelease>> {
    Ok(list(dir)?.into_iter().next())
}

pub fn exe_path(dir: &Path, version: &str) -> Option<PathBuf> {
    if !is_valid_version(version) {
        return None;
    }
    let p = dir.join(version).join(EXE_NAME);
    p.is_file().then_some(p)
}

/// Legt ein Release ab. Ist `public_key` gesetzt, muss die Signatur dazu passen.
pub fn publish(
    dir: &Path,
    version: &str,
    exe: &[u8],
    signature: Option<String>,
    notes: Option<String>,
    public_key: Option<&str>,
) -> Result<ClientRelease> {
    if !is_valid_version(version) {
        bail!("Ungültige Versionsangabe '{version}'");
    }
    if exe.len() < 2 || &exe[..2] != b"MZ" {
        bail!("Datei ist keine Windows-EXE");
    }
    let sha256 = sha256_hex(exe);
    if let Some(pk) = public_key {
        let sig = signature
            .as_deref()
            .context("Signatur fehlt (client_update_public_key ist gesetzt)")?;
        verify(pk, version, &sha256, sig).map_err(|e| anyhow::anyhow!(e))?;
    }
    if let Some(cur) = latest(dir)? {
        if compare_versions(version, &cur.version) == Ordering::Less {
            tracing::warn!(
                "Veröffentliche {version}, obwohl {} bereits vorhanden ist",
                cur.version
            );
        }
    }
    let target = dir.join(version);
    std::fs::create_dir_all(&target)
        .with_context(|| format!("{} nicht anlegbar", target.display()))?;
    let tmp = target.join(format!("{EXE_NAME}.tmp"));
    std::fs::write(&tmp, exe)?;
    std::fs::rename(&tmp, target.join(EXE_NAME))?;
    let release = ClientRelease {
        version: version.to_string(),
        sha256,
        size: exe.len() as u64,
        signature,
        published_at: Utc::now(),
        notes,
        download_url: download_url(version),
    };
    std::fs::write(target.join(META_NAME), serde_json::to_vec_pretty(&release)?)?;
    Ok(release)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::release::{keypair_from_seed, sign};

    #[test]
    fn publish_and_list() {
        let dir = std::env::temp_dir().join(format!("pc-rel-{}", uuid::Uuid::new_v4()));
        let (sk, pk) = keypair_from_seed([3u8; 32]);
        let exe = b"MZfake-exe".to_vec();
        let sig = sign(&sk, "0.2.0", &sha256_hex(&exe)).unwrap();
        assert!(publish(&dir, "0.2.0", &exe, None, None, Some(&pk)).is_err());
        assert!(publish(&dir, "0.2.0", b"no-exe", Some(sig.clone()), None, Some(&pk)).is_err());
        assert!(publish(&dir, "../x", &exe, Some(sig.clone()), None, None).is_err());
        publish(&dir, "0.2.0", &exe, Some(sig), None, Some(&pk)).unwrap();
        publish(&dir, "0.10.0", &exe, None, Some("Test".into()), None).unwrap();
        let l = list(&dir).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].version, "0.10.0");
        assert!(exe_path(&dir, "0.2.0").is_some());
        assert!(exe_path(&dir, "..").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
