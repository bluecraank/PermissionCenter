//! Binär-SIDs parsen und in die Zeichenkettenform `S-1-…` umwandeln.

/// Wandelt eine binäre SID in die Form `S-R-I-S1-S2…` um.
/// Gibt `None` zurück, wenn der Puffer zu kurz oder die SID ungültig ist.
pub fn sid_to_string(bytes: &[u8]) -> Option<String> {
    let len = sid_length(bytes)?;
    let bytes = &bytes[..len];
    let revision = bytes[0];
    let count = bytes[1] as usize;
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let mut s = if authority >= 1 << 32 {
        format!("S-{revision}-0x{authority:012X}")
    } else {
        format!("S-{revision}-{authority}")
    };
    for i in 0..count {
        let off = 8 + i * 4;
        let sub = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        s.push('-');
        s.push_str(&sub.to_string());
    }
    Some(s)
}

/// Länge einer binären SID in Bytes, sofern gültig.
pub fn sid_length(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 8 || bytes[0] != 1 {
        return None;
    }
    let count = bytes[1] as usize;
    if count > 15 {
        return None;
    }
    let len = 8 + count * 4;
    (bytes.len() >= len).then_some(len)
}

/// Wandelt `S-1-…` zurück in die Binärform (z. B. für LDAP-Filter).
pub fn string_to_sid(s: &str) -> Option<Vec<u8>> {
    let mut parts = s.strip_prefix("S-")?.split('-');
    let revision: u8 = parts.next()?.parse().ok()?;
    let auth_str = parts.next()?;
    let authority: u64 = if let Some(hex) = auth_str.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        auth_str.parse().ok()?
    };
    let subs: Vec<u32> = parts.map(|p| p.parse().ok()).collect::<Option<_>>()?;
    if subs.len() > 15 {
        return None;
    }
    let mut out = vec![revision, subs.len() as u8];
    out.extend_from_slice(&authority.to_be_bytes()[2..8]);
    for sub in subs {
        out.extend_from_slice(&sub.to_le_bytes());
    }
    Some(out)
}

/// Domänenpräfix einer Konto-SID (`S-1-5-21-a-b-c`), ohne RID.
pub fn domain_prefix(sid: &str) -> Option<&str> {
    if !sid.starts_with("S-1-5-21-") {
        return None;
    }
    let idx = sid.rfind('-')?;
    let prefix = &sid[..idx];
    // S-1-5-21-a-b-c besteht aus 7 Teilen
    (prefix.split('-').count() == 7).then_some(prefix)
}

/// Relative ID (letzte Komponente) einer SID.
pub fn rid(sid: &str) -> Option<u32> {
    sid.rsplit('-').next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for s in [
            "S-1-1-0",
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-21-3623811015-3361044348-30300820-1013",
        ] {
            let b = string_to_sid(s).unwrap();
            assert_eq!(sid_to_string(&b).unwrap(), s);
        }
    }

    #[test]
    fn invalid() {
        assert!(sid_to_string(&[1, 2, 0, 0]).is_none());
        assert!(string_to_sid("X-1-5").is_none());
    }

    #[test]
    fn prefix_and_rid() {
        let s = "S-1-5-21-1-2-3-1105";
        assert_eq!(domain_prefix(s), Some("S-1-5-21-1-2-3"));
        assert_eq!(rid(s), Some(1105));
        assert_eq!(domain_prefix("S-1-5-32-544"), None);
    }
}
