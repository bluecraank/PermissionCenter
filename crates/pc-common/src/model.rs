use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::rights::Rights;

/// Version des Report-Formats. Der Server lehnt unbekannte Major-Versionen ab.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Vollständiges Ergebnis eines Scan-Laufs auf einem System.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub scan_id: Uuid,
    pub client_version: String,
    pub host: HostInfo,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    /// `full` = alle Ordner, `relevant` = nur Ordner mit eigenen Berechtigungen
    /// (plus Vorfahren und die oberen Ebenen als Gerüst).
    pub report_mode: ReportMode,
    pub roots: Vec<ScanRoot>,
    pub shares: Vec<ShareInfo>,
    pub folders: Vec<FolderRecord>,
    pub principals: Vec<PrincipalInfo>,
    pub errors: Vec<ScanError>,
    pub stats: ScanStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReportMode {
    Full,
    #[default]
    Relevant,
}

impl ReportMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportMode::Full => "full",
            ReportMode::Relevant => "relevant",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    /// DNS-Domäne bzw. Arbeitsgruppe.
    pub domain: Option<String>,
    pub os_name: String,
    pub os_version: String,
    pub os_build: Option<u32>,
    pub is_domain_controller: bool,
    /// SID des Rechnerkontos-Domänenpräfix (z. B. `S-1-5-21-…`), falls bekannt.
    pub machine_sid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// Lokales festes Laufwerk.
    LocalDrive,
    /// Pfad einer lokalen Freigabe.
    Share,
    /// Verbundenes Netzlaufwerk oder konfigurierter UNC-Pfad.
    Remote,
}

impl RootKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RootKind::LocalDrive => "local_drive",
            RootKind::Share => "share",
            RootKind::Remote => "remote",
        }
    }
}

/// Startpunkt eines Scans (Laufwerk, Freigabe, UNC-Pfad).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRoot {
    pub path: String,
    pub kind: RootKind,
    /// ID des Ordnerdatensatzes für den Wurzelordner.
    pub folder_id: Option<u64>,
    pub folders_scanned: u64,
    pub folders_excluded: u64,
    pub errors: u64,
}

/// Ein Ordner mit seiner Berechtigungsliste.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderRecord {
    /// Innerhalb des Reports eindeutige ID.
    pub id: u64,
    pub parent_id: Option<u64>,
    pub path: String,
    /// Tiefe relativ zum Scan-Root (Root = 0).
    pub depth: u32,
    pub owner_sid: Option<String>,
    /// DACL ist geschützt, d. h. die Vererbung ist unterbrochen.
    pub inheritance_protected: bool,
    /// Ordner hat mindestens einen nicht vererbten ACE.
    pub has_explicit_aces: bool,
    /// Nächster Vorfahr (oder er selbst), dessen ACL die Rechte dieses Ordners
    /// bestimmt – die Wurzel des „Berechtigungsstrangs“.
    pub acl_source_id: Option<u64>,
    pub aces: Vec<Ace>,
    /// Direkte Dateien im Ordner.
    pub file_count: u64,
    /// Summe der Dateigrößen direkt im Ordner (Bytes).
    pub file_bytes: u64,
    /// Anzahl aller Unterordner (rekursiv, inkl. nicht gemeldeter).
    pub subfolder_total: u64,
    pub is_reparse_point: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AceType {
    Allow,
    Deny,
    Audit,
    Other,
}

impl AceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AceType::Allow => "allow",
            AceType::Deny => "deny",
            AceType::Audit => "audit",
            AceType::Other => "other",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "allow" => AceType::Allow,
            "deny" => AceType::Deny,
            "audit" => AceType::Audit,
            _ => AceType::Other,
        }
    }
}

/// Access Control Entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ace {
    pub sid: String,
    pub ace_type: AceType,
    /// Rohe Zugriffsmaske.
    pub mask: u32,
    /// Vereinfachte Rechtestufe für Auswertung und Anzeige.
    pub rights: Rights,
    pub inherited: bool,
    /// ACE_FLAGS (OBJECT_INHERIT=0x1, CONTAINER_INHERIT=0x2, NO_PROPAGATE=0x4, INHERIT_ONLY=0x8, INHERITED=0x10).
    pub flags: u8,
}

/// Lokale Freigabe (SMB-Share) des Systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInfo {
    pub name: String,
    pub path: String,
    pub remark: Option<String>,
    /// STYPE_* Wert aus NetShareEnum.
    pub share_type: u32,
    /// Administrative/versteckte Standardfreigabe (C$, ADMIN$, IPC$ …).
    pub is_special: bool,
    /// Freigabeberechtigungen. `None` = kein Security-Descriptor (= Jeder: Vollzugriff).
    pub permissions: Option<Vec<Ace>>,
    pub folder_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    Group,
    /// Lokale Gruppe / Alias (z. B. BUILTIN\Administratoren).
    Alias,
    WellKnownGroup,
    Computer,
    /// SID eines gelöschten Kontos.
    Deleted,
    /// SID konnte nicht aufgelöst werden (Konto existiert nicht mehr).
    Unresolved,
    /// Auflösung fehlgeschlagen (z. B. DC nicht erreichbar) – Status unbekannt.
    Unknown,
    Other,
}

impl PrincipalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalKind::User => "user",
            PrincipalKind::Group => "group",
            PrincipalKind::Alias => "alias",
            PrincipalKind::WellKnownGroup => "well_known_group",
            PrincipalKind::Computer => "computer",
            PrincipalKind::Deleted => "deleted",
            PrincipalKind::Unresolved => "unresolved",
            PrincipalKind::Unknown => "unknown",
            PrincipalKind::Other => "other",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "user" => Self::User,
            "group" => Self::Group,
            "alias" => Self::Alias,
            "well_known_group" => Self::WellKnownGroup,
            "computer" => Self::Computer,
            "deleted" => Self::Deleted,
            "unresolved" => Self::Unresolved,
            "unknown" => Self::Unknown,
            _ => Self::Other,
        }
    }
    /// Konto existiert nachweislich nicht mehr.
    pub fn is_orphaned(&self) -> bool {
        matches!(self, Self::Deleted | Self::Unresolved)
    }
    pub fn is_group_like(&self) -> bool {
        matches!(self, Self::Group | Self::Alias | Self::WellKnownGroup)
    }
}

/// Aus Sicht des Clients aufgelöster Sicherheitsprinzipal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalInfo {
    pub sid: String,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub kind: PrincipalKind,
}

impl PrincipalInfo {
    pub fn display_name(&self) -> String {
        match (&self.domain, &self.name) {
            (Some(d), Some(n)) if !d.is_empty() => format!("{d}\\{n}"),
            (_, Some(n)) => n.clone(),
            _ => self.sid.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub path: String,
    pub code: Option<u32>,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub folders_scanned: u64,
    pub folders_reported: u64,
    pub folders_excluded: u64,
    pub folders_with_explicit_aces: u64,
    pub folders_inheritance_protected: u64,
    pub reparse_points_skipped: u64,
    pub files_seen: u64,
    pub errors: u64,
    pub orphaned_aces: u64,
    pub duration_ms: u64,
}

/// Antwort des Servers auf einen Report-Upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    pub accepted: bool,
    pub system_id: i64,
    pub scan_id: Uuid,
    pub findings: u64,
    pub message: Option<String>,
}

/// AD-Daten für den Import (aus LDAP oder aus `Export-ADData.ps1`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdSnapshot {
    pub domain: Option<String>,
    pub domain_sid: Option<String>,
    pub collected_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub users: Vec<AdUser>,
    #[serde(default)]
    pub groups: Vec<AdGroup>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdUser {
    pub sid: String,
    pub sam_account_name: String,
    #[serde(default)]
    pub user_principal_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub distinguished_name: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub last_logon: Option<DateTime<Utc>>,
    #[serde(default)]
    pub password_last_set: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created: Option<DateTime<Utc>>,
    #[serde(default)]
    pub is_computer: bool,
    /// SIDs der Gruppen, in denen das Konto direkt Mitglied ist.
    #[serde(default)]
    pub member_of: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdGroup {
    pub sid: String,
    pub sam_account_name: String,
    #[serde(default)]
    pub distinguished_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// global / domain_local / universal / builtin
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub is_security: bool,
    /// SIDs der direkten Mitglieder (Benutzer, Computer, Gruppen).
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub created: Option<DateTime<Utc>>,
}
