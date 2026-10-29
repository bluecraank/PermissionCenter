//! Client-Releases für OTA-Updates: Versionsvergleich, Prüfsummen und Ed25519-Signaturen.
//!
//! Signiert wird nicht die Datei selbst, sondern die Nachricht
//! `permissioncenter-client\n<version>\n<sha256-hex>` – damit sind Version und
//! Inhalt gemeinsam geschützt (kein „Downgrade“ mit gültiger Signatur möglich).

use std::cmp::Ordering;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Metadaten eines veröffentlichten Client-Releases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRelease {
    pub version: String,
    pub sha256: String,
    pub size: u64,
    /// Ed25519-Signatur (Base64) über [`signed_message`].
    pub signature: Option<String>,
    pub published_at: DateTime<Utc>,
    #[serde(default)]
    pub notes: Option<String>,
    /// Relativer Download-Pfad auf dem Server.
    #[serde(default)]
    pub download_url: String,
}

pub fn signed_message(version: &str, sha256_hex: &str) -> Vec<u8> {
    format!(
        "permissioncenter-client\n{version}\n{}",
        sha256_hex.to_lowercase()
    )
    .into_bytes()
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn key32(b64: &str, what: &str) -> Result<[u8; 32], String> {
    let raw = B64
        .decode(b64.trim())
        .map_err(|e| format!("{what} ist kein gültiges Base64: {e}"))?;
    raw.try_into()
        .map_err(|_| format!("{what} muss 32 Byte lang sein"))
}

/// Erzeugt ein Schlüsselpaar aus 32 Zufallsbytes. Rückgabe: (privat, öffentlich) als Base64.
pub fn keypair_from_seed(seed: [u8; 32]) -> (String, String) {
    let sk = SigningKey::from_bytes(&seed);
    (
        B64.encode(sk.to_bytes()),
        B64.encode(sk.verifying_key().to_bytes()),
    )
}

pub fn public_key_of(private_b64: &str) -> Result<String, String> {
    let sk = SigningKey::from_bytes(&key32(private_b64, "Privater Schlüssel")?);
    Ok(B64.encode(sk.verifying_key().to_bytes()))
}

pub fn sign(private_b64: &str, version: &str, sha256_hex: &str) -> Result<String, String> {
    let sk = SigningKey::from_bytes(&key32(private_b64, "Privater Schlüssel")?);
    Ok(B64.encode(sk.sign(&signed_message(version, sha256_hex)).to_bytes()))
}

pub fn verify(
    public_b64: &str,
    version: &str,
    sha256_hex: &str,
    signature_b64: &str,
) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&key32(public_b64, "Öffentlicher Schlüssel")?)
        .map_err(|e| format!("Öffentlicher Schlüssel ungültig: {e}"))?;
    let raw = B64
        .decode(signature_b64.trim())
        .map_err(|e| format!("Signatur ist kein gültiges Base64: {e}"))?;
    let sig: [u8; 64] = raw
        .try_into()
        .map_err(|_| "Signatur muss 64 Byte lang sein".to_string())?;
    vk.verify(
        &signed_message(version, sha256_hex),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| "Signatur ungültig".to_string())
}

/// Vergleicht Versionen der Form `x.y.z[-pre]`. Vorabversionen sind kleiner als die Endversion.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    fn parse(v: &str) -> (Vec<u64>, Option<&str>) {
        let v = v.trim().trim_start_matches('v');
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        let mut nums: Vec<u64> = core.split('.').map(|p| p.parse().unwrap_or(0)).collect();
        nums.resize(3, 0);
        (nums, pre)
    }
    let (na, pa) = parse(a);
    let (nb, pb) = parse(b);
    na.cmp(&nb).then_with(|| match (pa, pb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => x.cmp(y),
    })
}

/// Gültige Versionsbezeichnung (verhindert Pfadmanipulation in Release-Verzeichnissen).
pub fn is_valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.chars().next().is_some_and(|c| c.is_ascii_digit())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(compare_versions("0.2.0", "0.1.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.0-rc1", "1.0.0"), Ordering::Less);
        assert_eq!(compare_versions("0.10.0", "0.9.0"), Ordering::Greater);
        assert!(is_valid_version("0.2.0-beta.1"));
        assert!(!is_valid_version("../0.2"));
        assert!(!is_valid_version("a.b"));
    }

    #[test]
    fn sign_and_verify() {
        let (sk, pk) = keypair_from_seed([7u8; 32]);
        assert_eq!(public_key_of(&sk).unwrap(), pk);
        let hash = sha256_hex(b"exe");
        let sig = sign(&sk, "0.2.0", &hash).unwrap();
        assert!(verify(&pk, "0.2.0", &hash, &sig).is_ok());
        // Andere Version oder anderer Inhalt mit gleicher Signatur muss scheitern
        assert!(verify(&pk, "0.1.0", &hash, &sig).is_err());
        assert!(verify(&pk, "0.2.0", &sha256_hex(b"evil"), &sig).is_err());
    }
}
