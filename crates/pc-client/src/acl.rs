//! Plattformunabhängiger Parser für binäre ACLs (DACL) aus Security-Descriptoren.

use pc_common::rights::{classify, FILE_FULL_CONTROL};
use pc_common::sid::sid_to_string;
use pc_common::{wellknown, Ace, AceType};

pub const INHERITED_ACE: u8 = 0x10;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x0;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x1;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x2;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x5;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x6;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x9;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0xA;

/// Parst eine ACL (beginnend mit ACL-Header). Ungültige Einträge werden übersprungen.
pub fn parse_acl(acl: &[u8]) -> Vec<Ace> {
    let mut out = Vec::new();
    if acl.len() < 8 {
        return out;
    }
    let acl_size = u16::from_le_bytes([acl[2], acl[3]]) as usize;
    let count = u16::from_le_bytes([acl[4], acl[5]]) as usize;
    let acl = &acl[..acl_size.min(acl.len())];
    let mut off = 8usize;
    for _ in 0..count {
        if off + 4 > acl.len() {
            break;
        }
        let ace_type = acl[off];
        let flags = acl[off + 1];
        let size = u16::from_le_bytes([acl[off + 2], acl[off + 3]]) as usize;
        if size < 8 || off + size > acl.len() {
            break;
        }
        let body = &acl[off..off + size];
        if let Some(ace) = parse_ace(ace_type, flags, body) {
            out.push(ace);
        }
        off += size;
    }
    out
}

fn parse_ace(ace_type: u8, flags: u8, body: &[u8]) -> Option<Ace> {
    let mask = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let (kind, sid_off) = match ace_type {
        ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => (AceType::Allow, 8),
        ACCESS_DENIED_ACE_TYPE | ACCESS_DENIED_CALLBACK_ACE_TYPE => (AceType::Deny, 8),
        SYSTEM_AUDIT_ACE_TYPE => (AceType::Audit, 8),
        ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE => {
            // Objekt-ACE: Flags(4) + optional 2 GUIDs (je 16)
            let obj_flags = u32::from_le_bytes(body.get(8..12)?.try_into().ok()?);
            let mut o = 12;
            if obj_flags & 0x1 != 0 {
                o += 16;
            }
            if obj_flags & 0x2 != 0 {
                o += 16;
            }
            let kind = if ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE {
                AceType::Allow
            } else {
                AceType::Deny
            };
            (kind, o)
        }
        _ => (AceType::Other, 8),
    };
    let sid = sid_to_string(body.get(sid_off..)?)?;
    Some(Ace {
        sid,
        ace_type: kind,
        mask,
        rights: classify(mask),
        inherited: flags & INHERITED_ACE != 0,
        flags,
    })
}

/// Ersatz für eine NULL-DACL: Jeder hat Vollzugriff.
pub fn null_dacl() -> Vec<Ace> {
    vec![Ace {
        sid: wellknown::EVERYONE.to_string(),
        ace_type: AceType::Allow,
        mask: FILE_FULL_CONTROL,
        rights: classify(FILE_FULL_CONTROL),
        inherited: false,
        flags: 0x3,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::rights::Rights;
    use pc_common::sid::string_to_sid;

    fn ace(t: u8, flags: u8, mask: u32, sid: &str) -> Vec<u8> {
        let sid = string_to_sid(sid).unwrap();
        let size = 8 + sid.len();
        let mut v = vec![t, flags];
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(&sid);
        v
    }

    #[test]
    fn parses_acl() {
        let a1 = ace(0, 0x13, FILE_FULL_CONTROL, "S-1-5-18");
        let a2 = ace(1, 0x00, 0x0012_0089, "S-1-5-21-1-2-3-1105");
        let size = 8 + a1.len() + a2.len();
        let mut acl = vec![2, 0];
        acl.extend_from_slice(&(size as u16).to_le_bytes());
        acl.extend_from_slice(&2u16.to_le_bytes());
        acl.extend_from_slice(&[0, 0]);
        acl.extend(a1);
        acl.extend(a2);
        let aces = parse_acl(&acl);
        assert_eq!(aces.len(), 2);
        assert_eq!(aces[0].sid, "S-1-5-18");
        assert!(aces[0].inherited);
        assert_eq!(aces[0].rights, Rights::FullControl);
        assert_eq!(aces[1].ace_type, AceType::Deny);
        assert_eq!(aces[1].rights, Rights::Read);
        assert!(!aces[1].inherited);
    }

    #[test]
    fn truncated_acl() {
        assert!(parse_acl(&[2, 0, 50, 0, 3, 0, 0, 0, 0]).is_empty());
    }
}
