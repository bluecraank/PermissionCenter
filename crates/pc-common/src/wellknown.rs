//! Bekannte SIDs (Well-Known SIDs), die nie als „verwaist“ gelten.

use crate::sid;

/// Breite Prinzipale, deren Schreibrechte als Risiko gelten.
pub const EVERYONE: &str = "S-1-1-0";
pub const ANONYMOUS: &str = "S-1-5-7";
pub const AUTHENTICATED_USERS: &str = "S-1-5-11";
pub const BUILTIN_USERS: &str = "S-1-5-32-545";
pub const BUILTIN_GUESTS: &str = "S-1-5-32-546";
pub const CREATOR_OWNER: &str = "S-1-3-0";
pub const SYSTEM: &str = "S-1-5-18";
pub const BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";

/// RIDs der Domänengruppen „Domänen-Benutzer“, „Domänen-Gäste“, „Domänencomputer“.
pub const RID_DOMAIN_USERS: u32 = 513;
pub const RID_DOMAIN_GUESTS: u32 = 514;
pub const RID_DOMAIN_COMPUTERS: u32 = 515;

const WELL_KNOWN: &[(&str, &str)] = &[
    ("S-1-0-0", "NULL SID"),
    ("S-1-1-0", "Jeder"),
    ("S-1-2-0", "LOKAL"),
    ("S-1-2-1", "KONSOLENANMELDUNG"),
    ("S-1-3-0", "ERSTELLER-BESITZER"),
    ("S-1-3-1", "ERSTELLERGRUPPE"),
    ("S-1-3-4", "BESITZERRECHTE"),
    ("S-1-5-1", "DIALUP"),
    ("S-1-5-2", "NETZWERK"),
    ("S-1-5-3", "BATCH"),
    ("S-1-5-4", "INTERAKTIV"),
    ("S-1-5-6", "DIENST"),
    ("S-1-5-7", "ANONYMOUS-ANMELDUNG"),
    ("S-1-5-9", "Domänencontroller der Organisation"),
    ("S-1-5-10", "SELBST"),
    ("S-1-5-11", "Authentifizierte Benutzer"),
    ("S-1-5-12", "EINGESCHRÄNKT"),
    ("S-1-5-13", "TERMINALSERVERBENUTZER"),
    ("S-1-5-14", "REMOTE INTERAKTIVE ANMELDUNG"),
    ("S-1-5-15", "Diese Organisation"),
    ("S-1-5-17", "IUSR"),
    ("S-1-5-18", "SYSTEM"),
    ("S-1-5-19", "LOKALER DIENST"),
    ("S-1-5-20", "NETZWERKDIENST"),
    ("S-1-5-32-544", "VORDEFINIERT\\Administratoren"),
    ("S-1-5-32-545", "VORDEFINIERT\\Benutzer"),
    ("S-1-5-32-546", "VORDEFINIERT\\Gäste"),
    ("S-1-5-32-547", "VORDEFINIERT\\Hauptbenutzer"),
    ("S-1-5-32-548", "VORDEFINIERT\\Konten-Operatoren"),
    ("S-1-5-32-549", "VORDEFINIERT\\Server-Operatoren"),
    ("S-1-5-32-550", "VORDEFINIERT\\Druck-Operatoren"),
    ("S-1-5-32-551", "VORDEFINIERT\\Sicherungs-Operatoren"),
    (
        "S-1-5-32-554",
        "VORDEFINIERT\\Prä-Windows 2000 kompatibler Zugriff",
    ),
    ("S-1-5-32-555", "VORDEFINIERT\\Remotedesktopbenutzer"),
    ("S-1-5-32-568", "VORDEFINIERT\\IIS_IUSRS"),
    ("S-1-15-2-1", "ALLE ANWENDUNGSPAKETE"),
    ("S-1-15-2-2", "ALLE EINGESCHRÄNKTEN ANWENDUNGSPAKETE"),
    ("S-1-16-4096", "Niedrige Verbindlichkeitsstufe"),
    ("S-1-16-8192", "Mittlere Verbindlichkeitsstufe"),
    ("S-1-16-12288", "Hohe Verbindlichkeitsstufe"),
    ("S-1-16-16384", "Systemverbindlichkeitsstufe"),
];

/// Name eines bekannten SIDs, falls vorhanden.
pub fn well_known_name(sid: &str) -> Option<&'static str> {
    WELL_KNOWN.iter().find(|(s, _)| *s == sid).map(|(_, n)| *n)
}

/// SID ist eine universelle/vordefinierte SID oder eine Dienst-/App-SID,
/// die niemals einem gelöschten Konto entspricht.
pub fn is_well_known(sid: &str) -> bool {
    if well_known_name(sid).is_some() {
        return true;
    }
    // NT SERVICE\*, App-Container-Fähigkeiten, Verbindlichkeitsstufen, BUILTIN
    sid.starts_with("S-1-5-80-")
        || sid.starts_with("S-1-5-32-")
        || sid.starts_with("S-1-15-")
        || sid.starts_with("S-1-16-")
        || sid.starts_with("S-1-5-83-")
        || sid.starts_with("S-1-5-90-")
        || sid.starts_with("S-1-5-96-")
}

/// Prinzipal umfasst praktisch alle Benutzer (Jeder, Authentifizierte Benutzer,
/// Benutzer, Domänen-Benutzer, Gäste, Anonym).
pub fn is_broad_principal(sid: &str) -> bool {
    if matches!(
        sid,
        EVERYONE | ANONYMOUS | AUTHENTICATED_USERS | BUILTIN_USERS | BUILTIN_GUESTS
    ) {
        return true;
    }
    sid::domain_prefix(sid).is_some()
        && matches!(
            sid::rid(sid),
            Some(RID_DOMAIN_USERS) | Some(RID_DOMAIN_GUESTS)
        )
}

/// SIDs, die für Systembetrieb und Administration nötig sind und bei
/// Bewertungen nicht als Auffälligkeit zählen.
pub fn is_administrative(sid: &str) -> bool {
    if matches!(
        sid,
        SYSTEM | BUILTIN_ADMINISTRATORS | CREATOR_OWNER | "S-1-5-32-551" | "S-1-5-19" | "S-1-5-20"
    ) {
        return true;
    }
    // Domänen-Admins (512), Organisations-Admins (519)
    sid::domain_prefix(sid).is_some() && matches!(sid::rid(sid), Some(512) | Some(519))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        assert!(is_well_known("S-1-5-18"));
        assert!(is_well_known(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        ));
        assert!(!is_well_known("S-1-5-21-1-2-3-1105"));
        assert!(is_broad_principal("S-1-1-0"));
        assert!(is_broad_principal("S-1-5-21-1-2-3-513"));
        assert!(!is_broad_principal("S-1-5-21-1-2-3-1105"));
        assert!(is_administrative("S-1-5-21-1-2-3-512"));
    }
}
