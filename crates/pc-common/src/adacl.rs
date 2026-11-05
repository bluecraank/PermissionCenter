//! Berechtigungen an AD-Objekten: Datenmodell, Einordnung der Rechte und Parser für
//! binäre Security-Descriptoren (`nTSecurityDescriptor`).
//!
//! LDAP-Abgleich und `Export-ADData.ps1` liefern dieselben Rohwerte (Maske, Objekttyp).
//! Bewertet wird nur hier, damit beide Wege zum selben Ergebnis kommen.

use serde::{Deserialize, Serialize};

use crate::sid::sid_to_string;

const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const DS_SELF: u32 = 0x0000_0008;
const DS_WRITE_PROP: u32 = 0x0000_0020;
const DS_CONTROL_ACCESS: u32 = 0x0000_0100;
/// Maske von `ActiveDirectoryRights.GenericAll`.
const FULL_CONTROL: u32 = 0x000F_01FF;

const GUID_MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
const GUID_SPN: &str = "f3a64788-5306-11d1-a9c5-0000f80367c1";
const GUID_KEY_CREDENTIAL: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
const GUID_ALLOWED_TO_ACT: &str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
const GUID_ACCOUNT_RESTRICTIONS: &str = "4c164200-20c0-11d0-a768-00aa003049e2";
const GUID_GP_LINK: &str = "f30e3bbe-9ff0-11d1-b603-0000f80367c1";
const GUID_FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
const GUID_GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
const GUID_GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";

/// Ein Erlauben-Eintrag, der tatsächlich für das Objekt selbst gilt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdAce {
    pub trustee: String,
    pub mask: u32,
    /// Attribut, Eigenschaftssatz oder erweitertes Recht (GUID in Kleinbuchstaben).
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub inherited: bool,
}

/// Berechtigungen eines AD-Objekts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdAclObject {
    pub dn: String,
    #[serde(default)]
    pub sid: Option<String>,
    /// user, computer, group, domain, ou, container, gpo
    pub kind: String,
    /// Anzeigename, bei GPOs statt der GUID.
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    /// Vererbung vom übergeordneten Objekt ist abgeschaltet.
    #[serde(default)]
    pub protected: bool,
    /// Rohwert von `gPLink` (nur Domäne und OUs).
    #[serde(default)]
    pub gp_link: Option<String>,
    /// Rohwert von `gPOptions`; 1 = Vererbung von GPOs blockiert.
    #[serde(default)]
    pub gp_options: i32,
    #[serde(default)]
    pub aces: Vec<AdAce>,
}

/// Für Angriffspfade relevante Rechte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdRight {
    GenericAll,
    GenericWrite,
    WriteDacl,
    WriteOwner,
    Owner,
    ForceChangePassword,
    AllExtendedRights,
    AddMember,
    AddSelf,
    WriteSpn,
    KeyCredentialLink,
    Rbcd,
    GpLink,
    GetChanges,
    GetChangesAll,
    DcSync,
}

impl AdRight {
    pub fn id(self) -> &'static str {
        match self {
            Self::GenericAll => "generic_all",
            Self::GenericWrite => "generic_write",
            Self::WriteDacl => "write_dacl",
            Self::WriteOwner => "write_owner",
            Self::Owner => "owner",
            Self::ForceChangePassword => "force_change_password",
            Self::AllExtendedRights => "all_extended_rights",
            Self::AddMember => "add_member",
            Self::AddSelf => "add_self",
            Self::WriteSpn => "write_spn",
            Self::KeyCredentialLink => "key_credential_link",
            Self::Rbcd => "rbcd",
            Self::GpLink => "gp_link",
            Self::GetChanges => "get_changes",
            Self::GetChangesAll => "get_changes_all",
            Self::DcSync => "dcsync",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::GenericAll => "Vollzugriff",
            Self::GenericWrite => "Alle Eigenschaften schreiben",
            Self::WriteDacl => "Berechtigungen ändern",
            Self::WriteOwner => "Besitzer ändern",
            Self::Owner => "Ist Besitzer",
            Self::ForceChangePassword => "Kennwort zurücksetzen",
            Self::AllExtendedRights => "Alle erweiterten Rechte",
            Self::AddMember => "Mitglieder hinzufügen",
            Self::AddSelf => "Sich selbst hinzufügen",
            Self::WriteSpn => "SPN schreiben",
            Self::KeyCredentialLink => "Anmeldeschlüssel schreiben",
            Self::Rbcd => "Delegierung schreiben (RBCD)",
            Self::GpLink => "GPO verknüpfen",
            Self::GetChanges => "Verzeichnisänderungen replizieren",
            Self::GetChangesAll => "Alle Verzeichnisänderungen replizieren",
            Self::DcSync => "Kennwort-Hashes replizieren (DCSync)",
        }
    }
}

/// Rechte, die ein Eintrag gewährt – unabhängig vom Zielobjekt.
pub fn rights_of(ace: &AdAce) -> Vec<AdRight> {
    let ty = ace.object_type.as_deref();
    let m = ace.mask;
    if ty.is_none() && (m & GENERIC_ALL != 0 || m & FULL_CONTROL == FULL_CONTROL) {
        return vec![AdRight::GenericAll];
    }
    let mut out = Vec::new();
    if m & WRITE_DAC != 0 {
        out.push(AdRight::WriteDacl);
    }
    if m & WRITE_OWNER != 0 {
        out.push(AdRight::WriteOwner);
    }
    if m & GENERIC_WRITE != 0 || (m & DS_WRITE_PROP != 0 && ty.is_none()) {
        out.push(AdRight::GenericWrite);
    }
    if m & DS_WRITE_PROP != 0 {
        match ty {
            Some(GUID_MEMBER) => out.push(AdRight::AddMember),
            Some(GUID_SPN) => out.push(AdRight::WriteSpn),
            Some(GUID_KEY_CREDENTIAL) => out.push(AdRight::KeyCredentialLink),
            Some(GUID_ALLOWED_TO_ACT | GUID_ACCOUNT_RESTRICTIONS) => out.push(AdRight::Rbcd),
            Some(GUID_GP_LINK) => out.push(AdRight::GpLink),
            _ => {}
        }
    }
    if m & DS_SELF != 0 && matches!(ty, None | Some(GUID_MEMBER)) {
        out.push(AdRight::AddSelf);
    }
    if m & DS_CONTROL_ACCESS != 0 {
        match ty {
            None => out.push(AdRight::AllExtendedRights),
            Some(GUID_FORCE_CHANGE_PASSWORD) => out.push(AdRight::ForceChangePassword),
            Some(GUID_GET_CHANGES) => out.push(AdRight::GetChanges),
            Some(GUID_GET_CHANGES_ALL) => out.push(AdRight::GetChangesAll),
            _ => {}
        }
    }
    out
}

/// Konten, die das AD ohnehin kontrollieren. Ihre Einträge stehen auf fast jedem
/// Objekt und werden nicht gespeichert (SYSTEM, SELF, CREATOR OWNER, Enterprise-DCs,
/// Administratoren, Domänen- und Organisations-Admins).
pub fn is_default_trustee(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18" | "S-1-5-10" | "S-1-3-0" | "S-1-5-9" | "S-1-5-32-544"
    ) || (sid.starts_with("S-1-5-21-") && (sid.ends_with("-512") || sid.ends_with("-519")))
}

/// Eintrag lohnt das Speichern.
pub fn is_relevant(ace: &AdAce) -> bool {
    !is_default_trustee(&ace.trustee) && !rights_of(ace).is_empty()
}

/// Objektart aus den Werten von `objectClass`.
pub fn kind_from_classes<S: AsRef<str>>(classes: &[S]) -> &'static str {
    let has = |c: &str| classes.iter().any(|v| v.as_ref().eq_ignore_ascii_case(c));
    if has("computer") {
        "computer"
    } else if has("user") {
        "user"
    } else if has("group") {
        "group"
    } else if has("domainDNS") {
        "domain"
    } else if has("organizationalUnit") {
        "ou"
    } else if has("groupPolicyContainer") {
        "gpo"
    } else {
        "container"
    }
}

/// Eine Verknüpfung aus `gPLink`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpLink {
    pub dn: String,
    pub disabled: bool,
    pub enforced: bool,
}

/// Zerlegt `[LDAP://cn={…},cn=policies,…;0][…]`.
pub fn parse_gp_link(raw: &str) -> Vec<GpLink> {
    raw.split('[')
        .filter_map(|part| {
            let part = part.split(']').next()?;
            let (path, opts) = part.rsplit_once(';')?;
            let dn = path
                .get(..7)
                .filter(|p| p.eq_ignore_ascii_case("LDAP://"))
                .map(|_| &path[7..])?;
            let opts: u32 = opts.trim().parse().ok()?;
            Some(GpLink {
                dn: dn.to_string(),
                disabled: opts & 1 != 0,
                enforced: opts & 2 != 0,
            })
        })
        .collect()
}

/// Ergebnis von [`parse_security_descriptor`].
#[derive(Debug, Default)]
pub struct ParsedSd {
    pub owner: Option<String>,
    pub protected: bool,
    pub aces: Vec<AdAce>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn guid_at(b: &[u8], o: usize) -> Option<String> {
    let g = b.get(o..o + 16)?;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    ))
}

const SE_DACL_PROTECTED: u16 = 0x1000;
const ACE_TYPE_ALLOW: u8 = 0x00;
const ACE_TYPE_ALLOW_OBJECT: u8 = 0x05;
const ACE_FLAG_INHERIT_ONLY: u8 = 0x08;
const ACE_FLAG_INHERITED: u8 = 0x10;
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;

/// Liest einen binären Security-Descriptor im Self-Relative-Format.
///
/// Übernimmt nur Erlauben-Einträge, die für das Objekt selbst gelten. `None`, wenn
/// die Daten beschädigt sind.
pub fn parse_security_descriptor(b: &[u8]) -> Option<ParsedSd> {
    let control = u16_at(b, 2)?;
    let owner_off = u32_at(b, 4)? as usize;
    let dacl_off = u32_at(b, 16)? as usize;
    let mut out = ParsedSd {
        owner: match owner_off {
            0 => None,
            o => Some(sid_to_string(b.get(o..)?)?),
        },
        protected: control & SE_DACL_PROTECTED != 0,
        aces: Vec::new(),
    };
    if dacl_off == 0 {
        return Some(out);
    }
    let count = u16_at(b, dacl_off + 4)? as usize;
    let mut pos = dacl_off + 8;
    for _ in 0..count {
        let ace_type = *b.get(pos)?;
        let flags = *b.get(pos + 1)?;
        let size = u16_at(b, pos + 2)? as usize;
        if size < 8 || pos + size > b.len() {
            return None;
        }
        let ace = &b[pos..pos + size];
        pos += size;
        if flags & ACE_FLAG_INHERIT_ONLY != 0 {
            continue;
        }
        let mask = u32_at(ace, 4)?;
        let (object_type, sid_off) = match ace_type {
            ACE_TYPE_ALLOW => (None, 8),
            ACE_TYPE_ALLOW_OBJECT => {
                let f = u32_at(ace, 8)?;
                let mut o = 12;
                let ty = if f & ACE_OBJECT_TYPE_PRESENT != 0 {
                    o += 16;
                    Some(guid_at(ace, 12)?)
                } else {
                    None
                };
                if f & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    o += 16;
                }
                (ty, o)
            }
            _ => continue,
        };
        out.aces.push(AdAce {
            trustee: sid_to_string(ace.get(sid_off..)?)?,
            mask,
            object_type,
            inherited: flags & ACE_FLAG_INHERITED != 0,
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(mask: u32, ty: Option<&str>) -> AdAce {
        AdAce {
            trustee: "S-1-5-21-1-2-3-1105".into(),
            mask,
            object_type: ty.map(str::to_string),
            inherited: false,
        }
    }

    #[test]
    fn classify_rights() {
        assert_eq!(rights_of(&ace(0xF01FF, None)), [AdRight::GenericAll]);
        assert_eq!(rights_of(&ace(0x40000, None)), [AdRight::WriteDacl]);
        // ActiveDirectoryRights.GenericWrite = Lesezugriff + Self + alle Eigenschaften
        assert_eq!(
            rights_of(&ace(0x20028, None)),
            [AdRight::GenericWrite, AdRight::AddSelf]
        );
        assert_eq!(
            rights_of(&ace(0x20, Some(GUID_MEMBER))),
            [AdRight::AddMember]
        );
        assert_eq!(
            rights_of(&ace(0x100, Some(GUID_GET_CHANGES_ALL))),
            [AdRight::GetChangesAll]
        );
        // Lesen und unbekannte erweiterte Rechte sind nicht relevant
        assert!(rights_of(&ace(0x20094, None)).is_empty());
        assert!(rights_of(&ace(0x100, Some("ab721a53-1e2f-11d0-9819-00aa0040529b"))).is_empty());
    }

    #[test]
    fn default_trustees_are_dropped() {
        let mut a = ace(0xF01FF, None);
        assert!(is_relevant(&a));
        a.trustee = "S-1-5-21-1-2-3-512".into();
        assert!(!is_relevant(&a));
        a.trustee = "S-1-5-18".into();
        assert!(!is_relevant(&a));
    }

    #[test]
    fn gp_links() {
        let l = parse_gp_link(
            "[LDAP://cn={A},cn=policies,cn=system,DC=x,DC=y;0][ldap://cn={B},cn=policies,cn=system,DC=x,DC=y;2][LDAP://cn={C},DC=x;1]",
        );
        assert_eq!(l.len(), 3);
        assert_eq!(l[0].dn, "cn={A},cn=policies,cn=system,DC=x,DC=y");
        assert!(!l[0].enforced && !l[0].disabled);
        assert!(l[1].enforced);
        assert!(l[2].disabled);
        assert!(parse_gp_link(" ").is_empty());
    }

    fn sid_bytes(subs: &[u32], auth: u8) -> Vec<u8> {
        let mut v = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, auth];
        for s in subs {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    fn raw_ace(ty: u8, flags: u8, body: Vec<u8>) -> Vec<u8> {
        let mut v = vec![ty, flags];
        v.extend_from_slice(&((body.len() as u16 + 4).to_le_bytes()));
        v.extend(body);
        v
    }

    /// Security-Descriptor wie aus dem AD (Self-Relative, Besitzer hinter dem Kopf).
    fn sample_sd() -> Vec<u8> {
        let trustee = sid_bytes(&[21, 1, 2, 3, 1105], 5);
        let allow_body = || {
            let mut body = 0xF01FFu32.to_le_bytes().to_vec();
            body.extend(&trustee);
            body
        };
        let mut aces = vec![raw_ace(ACE_TYPE_ALLOW, 0, allow_body())];
        // Objektbezogen und vererbt: Kennwort zurücksetzen
        let mut body = 0x100u32.to_le_bytes().to_vec();
        body.extend(1u32.to_le_bytes());
        body.extend([
            0x70, 0x95, 0x29, 0x00, 0x6d, 0x24, 0xd0, 0x11, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e,
            0x05, 0x29,
        ]);
        body.extend(&trustee);
        aces.push(raw_ace(ACE_TYPE_ALLOW_OBJECT, ACE_FLAG_INHERITED, body));
        // Gilt nur für Unterobjekte und Verweigern: beide werden übersprungen
        aces.push(raw_ace(ACE_TYPE_ALLOW, ACE_FLAG_INHERIT_ONLY, allow_body()));
        aces.push(raw_ace(0x01, 0, allow_body()));

        let owner = sid_bytes(&[21, 1, 2, 3, 512], 5);
        let dacl_off = 20 + owner.len();
        let mut sd = vec![1, 0];
        sd.extend((0x8000u16 | SE_DACL_PROTECTED).to_le_bytes());
        sd.extend(20u32.to_le_bytes()); // Besitzer
        sd.extend(0u32.to_le_bytes()); // Gruppe
        sd.extend(0u32.to_le_bytes()); // SACL
        sd.extend((dacl_off as u32).to_le_bytes());
        sd.extend(&owner);
        let len: usize = aces.iter().map(Vec::len).sum();
        sd.extend([2, 0]);
        sd.extend(((len + 8) as u16).to_le_bytes());
        sd.extend((aces.len() as u16).to_le_bytes());
        sd.extend([0, 0]);
        for a in aces {
            sd.extend(a);
        }
        sd
    }

    #[test]
    fn parses_descriptor() {
        let sd = parse_security_descriptor(&sample_sd()).unwrap();
        assert_eq!(sd.owner.as_deref(), Some("S-1-5-21-1-2-3-512"));
        assert!(sd.protected);
        assert_eq!(sd.aces.len(), 2);
        assert_eq!(sd.aces[0].trustee, "S-1-5-21-1-2-3-1105");
        assert_eq!(sd.aces[0].object_type, None);
        assert_eq!(
            sd.aces[1].object_type.as_deref(),
            Some(GUID_FORCE_CHANGE_PASSWORD)
        );
        assert!(sd.aces[1].inherited);
    }

    #[test]
    fn broken_descriptor_is_rejected() {
        let full = sample_sd();
        assert!(parse_security_descriptor(&full[..full.len() - 3]).is_none());
        assert!(parse_security_descriptor(&[1, 0]).is_none());
    }

    #[test]
    fn kinds() {
        assert_eq!(
            kind_from_classes(&["top", "person", "user", "computer"]),
            "computer"
        );
        assert_eq!(kind_from_classes(&["top", "domainDNS"]), "domain");
        assert_eq!(kind_from_classes(&["top", "container"]), "container");
    }
}
