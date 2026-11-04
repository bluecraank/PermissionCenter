//! Datenmodell der Gruppenrichtlinien (Vertrag zwischen `gpo-client` und Server).

use serde::{Deserialize, Serialize};

pub const GPO_SCHEMA_VERSION: u32 = 1;

/// Berechtigung auf einer GPO (aus `Get-GPPermission`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GpoPerm {
    pub sid: String,
    pub name: String,
    pub domain: String,
    /// User, Group, Computer, WellKnownGroup, Alias, Unknown …
    pub sid_type: String,
    /// GpoApply, GpoRead, GpoEdit, GpoEditDeleteModifySecurity
    pub permission: String,
    pub denied: bool,
    pub inherited: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GpoLink {
    pub som_name: String,
    pub som_path: String,
    pub enabled: bool,
    pub enforced: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GpoSetting {
    /// Computer | Benutzer
    pub scope: String,
    pub area: String,
    pub name: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GpoMember {
    pub name: String,
    pub sam: String,
    pub class: String,
}

/// Gruppe mit „Übernehmen“-Recht auf mindestens einer GPO samt Mitgliedern.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GpoGroup {
    pub sid: String,
    pub name: String,
    pub members: Vec<GpoMember>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GpoItem {
    /// GUID ohne Klammern, kleingeschrieben
    pub id: String,
    pub name: String,
    pub domain: String,
    pub created: String,
    pub modified: String,
    pub owner: String,
    pub wmi_filter: String,
    pub computer_enabled: bool,
    pub user_enabled: bool,
    pub computer_version: String,
    pub user_version: String,
    pub links: Vec<GpoLink>,
    pub permissions: Vec<GpoPerm>,
    pub settings: Vec<GpoSetting>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GpoSnapshot {
    pub schema_version: u32,
    pub domain: String,
    pub host: String,
    pub client_version: String,
    pub collected_at: Option<chrono::DateTime<chrono::Utc>>,
    pub gpos: Vec<GpoItem>,
    pub groups: Vec<GpoGroup>,
}
