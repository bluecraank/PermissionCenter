//! Analyse-Engine: erzeugt Befunde (Findings), Bewertungen und Empfehlungen.
//!
//! Die Analyse wird nach jedem Report-Upload und jedem AD-Abgleich komplett
//! neu berechnet. Regeln sind in [`RULES`] beschrieben.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use futures_util::pin_mut;
use serde::Serialize;
use tokio_postgres::binary_copy::BinaryCopyInWriter;
use tokio_postgres::types::Type;
use tokio_postgres::Transaction;

use crate::config::AnalysisConfig;
use crate::directory::Directory;
use pc_common::rights::{can_change_permissions, Rights};
use pc_common::sid::rid;
use pc_common::wellknown;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Info,
        }
    }
    fn weight(&self) -> f64 {
        match self {
            Severity::Critical => 25.0,
            Severity::High => 12.0,
            Severity::Medium => 5.0,
            Severity::Low => 1.5,
            Severity::Info => 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub severity: Severity,
    /// `system` oder `ad`
    pub scope: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub recommendation: &'static str,
}

pub const RULES: &[Rule] = &[
    Rule {
        id: "ORPHANED_SID",
        severity: Severity::High,
        scope: "system",
        title: "Verwaiste SID in Berechtigungen",
        description: "Ein Ordner enthält explizite Berechtigungen für ein Konto, das nicht mehr existiert (gelöschter Benutzer oder Gruppe).",
        recommendation: "Verwaiste Einträge entfernen (z. B. mit icacls /remove *SID). Vorher prüfen, ob eine Nachfolgegruppe die Rechte übernehmen muss.",
    },
    Rule {
        id: "BROAD_WRITE",
        severity: Severity::High,
        scope: "system",
        title: "Schreibrechte für alle Benutzer",
        description: "Jeder, Authentifizierte Benutzer, Benutzer oder Domänen-Benutzer haben Schreib-, Änderungs- oder Vollzugriff.",
        recommendation: "Breite Gruppen auf Lesen beschränken und Schreibrechte über fachliche Berechtigungsgruppen (AGDLP) vergeben.",
    },
    Rule {
        id: "SHARE_OPEN",
        severity: Severity::Medium,
        scope: "system",
        title: "Freigabe mit Vollzugriff für Jeder",
        description: "Die Freigabeberechtigung erlaubt Jeder bzw. allen Benutzern Vollzugriff oder Ändern. Der Schutz hängt dann allein an NTFS.",
        recommendation: "Freigabeberechtigung auf „Authentifizierte Benutzer: Ändern“ setzen und den Zugriff über NTFS steuern; Administratoren Vollzugriff.",
    },
    Rule {
        id: "DISABLED_USER_ACE",
        severity: Severity::Medium,
        scope: "system",
        title: "Deaktivierter Benutzer berechtigt",
        description: "Ein im AD deaktiviertes Benutzerkonto hat noch explizite Berechtigungen.",
        recommendation: "Berechtigung entfernen bzw. im Rahmen des Austrittsprozesses automatisiert bereinigen.",
    },
    Rule {
        id: "PERMISSION_DELEGATION",
        severity: Severity::Medium,
        scope: "system",
        title: "Vollzugriff außerhalb der Administration",
        description: "Ein nicht-administrativer Benutzer bzw. eine Gruppe hat Vollzugriff und kann damit selbst Berechtigungen und Besitz ändern.",
        recommendation: "Vollzugriff auf „Ändern“ reduzieren. Rechteverwaltung nur durch Administratoren.",
    },
    Rule {
        id: "STALE_SYSTEM",
        severity: Severity::Medium,
        scope: "system",
        title: "System nicht aktuell gescannt",
        description: "Der letzte Scan des Systems ist älter als der konfigurierte Zeitraum.",
        recommendation: "Dienst bzw. geplante Aufgabe des Clients prüfen (Install-PcClient.ps1) und Erreichbarkeit des Servers sicherstellen.",
    },
    Rule {
        id: "DIRECT_USER_ACE",
        severity: Severity::Low,
        scope: "system",
        title: "Berechtigung direkt für Benutzer",
        description: "Rechte sind direkt einem Benutzerkonto statt einer Gruppe zugewiesen. Das erschwert Nachvollziehbarkeit und Rezertifizierung.",
        recommendation: "Rechte über Gruppen vergeben (AGDLP: Konto → globale Gruppe → domänenlokale Gruppe → Berechtigung).",
    },
    Rule {
        id: "INACTIVE_USER_ACE",
        severity: Severity::Low,
        scope: "system",
        title: "Inaktiver Benutzer berechtigt",
        description: "Ein Benutzer mit expliziter Berechtigung hat sich seit langer Zeit nicht angemeldet.",
        recommendation: "Konto und Berechtigung mit der Fachabteilung klären, ggf. deaktivieren und entfernen.",
    },
    Rule {
        id: "DENY_ACE",
        severity: Severity::Low,
        scope: "system",
        title: "Verweigern-Einträge",
        description: "Explizite Verweigern-Einträge erhöhen die Komplexität und führen leicht zu unerwarteten Zugriffsproblemen.",
        recommendation: "Verweigern-Einträge durch eine saubere Gruppenstruktur ersetzen.",
    },
    Rule {
        id: "DEEP_EXPLICIT",
        severity: Severity::Low,
        scope: "system",
        title: "Berechtigungen tief in der Struktur",
        description: "Explizite Berechtigungen auf tiefen Verzeichnisebenen sind schwer zu überblicken.",
        recommendation: "Berechtigungen auf die oberen 2–3 Ebenen beschränken; Struktur ggf. umorganisieren.",
    },
    Rule {
        id: "ORPHANED_OWNER",
        severity: Severity::Low,
        scope: "system",
        title: "Besitzer existiert nicht mehr",
        description: "Ordner gehören einem gelöschten Konto.",
        recommendation: "Besitz auf die Administratorengruppe übertragen (icacls /setowner).",
    },
    Rule {
        id: "INHERITANCE_BROKEN",
        severity: Severity::Info,
        scope: "system",
        title: "Vererbung unterbrochen",
        description: "Ordner mit deaktivierter Vererbung bilden eigene Berechtigungsstränge.",
        recommendation: "Unterbrechungen dokumentieren und auf das notwendige Minimum reduzieren.",
    },
    Rule {
        id: "SCAN_ERRORS",
        severity: Severity::Info,
        scope: "system",
        title: "Ordner nicht lesbar",
        description: "Der Client konnte Ordner nicht lesen; die Ergebnisse sind dort unvollständig.",
        recommendation: "Client als SYSTEM bzw. mit Sicherungs-Operator-Rechten ausführen.",
    },
    Rule {
        id: "AD_EMPTY_GROUP",
        severity: Severity::Low,
        scope: "ad",
        title: "Leere Gruppe",
        description: "Sicherheitsgruppe ohne Mitglieder.",
        recommendation: "Gruppe löschen, sofern sie nicht als Vorlage dient. Ist sie berechtigt, auch die Berechtigungen bereinigen.",
    },
    Rule {
        id: "AD_ORPHANED_GROUP",
        severity: Severity::Low,
        scope: "ad",
        title: "Gruppe nur mit deaktivierten Mitgliedern",
        description: "Alle Benutzer der Gruppe sind deaktiviert – die Gruppe ist faktisch verwaist.",
        recommendation: "Gruppe und zugehörige Berechtigungen entfernen oder neue Verantwortliche zuweisen.",
    },
    Rule {
        id: "AD_UNUSED_GROUP",
        severity: Severity::Info,
        scope: "ad",
        title: "Gruppe ohne Berechtigungen",
        description: "Sicherheitsgruppe, die weder direkt noch über Verschachtelung in gescannten Berechtigungen vorkommt.",
        recommendation: "Prüfen, ob die Gruppe anderweitig genutzt wird (Anwendungen, GPOs); andernfalls löschen.",
    },
    Rule {
        id: "AD_INACTIVE_USER",
        severity: Severity::Low,
        scope: "ad",
        title: "Inaktives Benutzerkonto",
        description: "Aktiviertes Konto ohne Anmeldung im konfigurierten Zeitraum.",
        recommendation: "Konto deaktivieren und nach Karenzzeit löschen.",
    },
    Rule {
        id: "AD_DISABLED_IN_GROUPS",
        severity: Severity::Info,
        scope: "ad",
        title: "Deaktivierte Konten in Gruppen",
        description: "Deaktivierte Benutzer sind weiterhin Mitglied von Sicherheitsgruppen.",
        recommendation: "Gruppenmitgliedschaften beim Deaktivieren entfernen (Austrittsprozess).",
    },
];

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

struct Finding {
    system_id: Option<i64>,
    rule: &'static str,
    title: String,
    detail: String,
    path: Option<String>,
    sid: Option<String>,
    affected: i64,
}

#[derive(Default)]
struct Agg {
    count: i64,
    paths: Vec<String>,
}

impl Agg {
    fn add(&mut self, path: &str) {
        self.count += 1;
        if self.paths.len() < 5 {
            self.paths.push(path.to_string());
        }
    }
    fn detail(&self) -> String {
        let mut s = format!("{} Ordner betroffen", self.count);
        if !self.paths.is_empty() {
            s.push_str(", z. B.:\n");
            s.push_str(&self.paths.join("\n"));
        }
        s
    }
}

struct AceRow {
    system_id: i64,
    path: String,
    depth: i64,
    sid: String,
    ace_type: String,
    mask: u32,
    rights: Rights,
}

/// Seit der letzten Analyse neu aufgetretener Befund.
#[derive(Debug, Clone, Serialize)]
pub struct NewFinding {
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    pub system_id: Option<i64>,
}

/// Verschlechterung der Note eines Bereichs.
#[derive(Debug, Clone, Serialize)]
pub struct GradeChange {
    /// `total`, `infra`, `ad` oder `system`
    pub scope: &'static str,
    pub system_id: i64,
    pub old_grade: String,
    pub new_grade: String,
    pub old_score: i32,
    pub new_score: i32,
}

#[derive(Debug, Default)]
pub struct AnalysisSummary {
    pub findings: usize,
    pub new_findings: Vec<NewFinding>,
    pub grade_changes: Vec<GradeChange>,
    /// Erste Analyse überhaupt – alles wäre „neu“, daher keine Benachrichtigung.
    pub initial: bool,
}

/// Berechnet alle Befunde neu (innerhalb der übergebenen Transaktion).
pub async fn run(tx: &Transaction<'_>, cfg: &AnalysisConfig) -> Result<AnalysisSummary> {
    // Parallele Läufe (gleichzeitige Uploads) serialisieren
    tx.execute(
        "SELECT pg_advisory_xact_lock($1)",
        &[&crate::db::ANALYSIS_LOCK],
    )
    .await?;
    let dir = Directory::load(tx, cfg.inactive_days).await?;
    let mut findings: Vec<Finding> = Vec::new();
    let max = cfg.max_findings_per_rule;

    // --- Explizite ACEs aller Systeme ---
    let rows: Vec<AceRow> = tx
        .query(
            "SELECT a.system_id, f.path, f.depth, a.sid, a.ace_type, a.mask, a.rights
             FROM aces a JOIN folders f ON f.system_id = a.system_id AND f.local_id = a.folder_local_id
             WHERE NOT a.inherited AND a.ace_type IN ('allow','deny')",
            &[],
        )
        .await?
        .iter()
        .map(|r| AceRow {
            system_id: r.get(0),
            path: r.get(1),
            depth: r.get::<_, i32>(2) as i64,
            sid: r.get(3),
            ace_type: r.get(4),
            mask: r.get::<_, i64>(5) as u32,
            rights: Rights::parse(r.get(6)),
        })
        .collect();

    let mut per_sid: BTreeMap<(i64, &'static str, String), Agg> = BTreeMap::new();
    let mut per_system: BTreeMap<(i64, &'static str), Agg> = BTreeMap::new();
    let mut broad_count: HashMap<i64, usize> = HashMap::new();
    let mut broad_seen: HashSet<(i64, String, String)> = HashSet::new();

    for r in &rows {
        let allow = r.ace_type == "allow";
        if dir.is_orphaned(&r.sid) {
            per_sid
                .entry((r.system_id, "ORPHANED_SID", r.sid.clone()))
                .or_default()
                .add(&r.path);
            continue;
        }
        if !allow {
            per_system
                .entry((r.system_id, "DENY_ACE"))
                .or_default()
                .add(&r.path);
            continue;
        }
        if wellknown::is_broad_principal(&r.sid) && r.rights.can_write() {
            let n = broad_count.entry(r.system_id).or_default();
            if *n < max && broad_seen.insert((r.system_id, r.path.clone(), r.sid.clone())) {
                *n += 1;
                findings.push(Finding {
                    system_id: Some(r.system_id),
                    rule: "BROAD_WRITE",
                    title: format!("{}: {}", dir.view(&r.sid).name, r.rights.label_de()),
                    detail: format!(
                        "{} hat {} auf {}",
                        dir.view(&r.sid).name,
                        r.rights.label_de(),
                        r.path
                    ),
                    path: Some(r.path.clone()),
                    sid: Some(r.sid.clone()),
                    affected: 1,
                });
            }
        }
        if can_change_permissions(r.mask)
            && !wellknown::is_administrative(&r.sid)
            && !wellknown::is_broad_principal(&r.sid)
            && !admin_like(&dir, &r.sid)
        {
            per_sid
                .entry((r.system_id, "PERMISSION_DELEGATION", r.sid.clone()))
                .or_default()
                .add(&r.path);
        }
        if dir.is_user(&r.sid) {
            per_sid
                .entry((r.system_id, "DIRECT_USER_ACE", r.sid.clone()))
                .or_default()
                .add(&r.path);
            if let Some(u) = dir.users.get(&r.sid) {
                if !u.enabled {
                    per_sid
                        .entry((r.system_id, "DISABLED_USER_ACE", r.sid.clone()))
                        .or_default()
                        .add(&r.path);
                } else if dir.is_inactive(u) {
                    per_sid
                        .entry((r.system_id, "INACTIVE_USER_ACE", r.sid.clone()))
                        .or_default()
                        .add(&r.path);
                }
            }
        }
        if r.depth >= cfg.deep_explicit_depth {
            per_system
                .entry((r.system_id, "DEEP_EXPLICIT"))
                .or_default()
                .add(&r.path);
        }
    }

    for ((system_id, rule_id, sid), agg) in per_sid {
        let name = dir.view(&sid).name;
        findings.push(Finding {
            system_id: Some(system_id),
            rule: rule_id,
            title: format!(
                "{} – {}",
                rule(rule_id).map(|r| r.title).unwrap_or(rule_id),
                name
            ),
            detail: agg.detail(),
            path: agg.paths.first().cloned(),
            sid: Some(sid),
            affected: agg.count,
        });
    }

    // --- Ordner-Eigenschaften ---
    {
        let it = tx
            .query(
                "SELECT system_id, path, owner_sid, protected, error, is_root FROM folders
                 WHERE protected OR error IS NOT NULL OR owner_sid IS NOT NULL",
                &[],
            )
            .await?;
        for r in &it {
            let (system_id, path, owner, protected, error, is_root): (
                i64,
                String,
                Option<String>,
                bool,
                Option<String>,
                bool,
            ) = (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5));
            if owner.as_deref().is_some_and(|o| dir.is_orphaned(o)) {
                per_system
                    .entry((system_id, "ORPHANED_OWNER"))
                    .or_default()
                    .add(&path);
            }
            if protected && !is_root {
                per_system
                    .entry((system_id, "INHERITANCE_BROKEN"))
                    .or_default()
                    .add(&path);
            }
            if error.is_some() {
                per_system
                    .entry((system_id, "SCAN_ERRORS"))
                    .or_default()
                    .add(&path);
            }
        }
    }
    for ((system_id, rule_id), agg) in per_system {
        findings.push(Finding {
            system_id: Some(system_id),
            rule: rule_id,
            title: rule(rule_id)
                .map(|r| r.title)
                .unwrap_or(rule_id)
                .to_string(),
            detail: agg.detail(),
            path: agg.paths.first().cloned(),
            sid: None,
            affected: agg.count,
        });
    }

    // --- Freigaben ---
    {
        let shares: Vec<(i64, i64, String, String, bool)> = tx
            .query(
                "SELECT s.id, s.system_id, s.name, s.path, s.has_sd FROM shares s
                 WHERE NOT s.is_special AND (s.share_type & 255) = 0",
                &[],
            )
            .await?
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
            .collect();
        let mut share_aces: HashMap<i64, Vec<(String, Rights)>> = HashMap::new();
        for r in tx
            .query(
                "SELECT share_id, sid, rights FROM share_aces WHERE ace_type = 'allow'",
                &[],
            )
            .await?
        {
            share_aces
                .entry(r.get(0))
                .or_default()
                .push((r.get(1), Rights::parse(r.get(2))));
        }
        for (id, system_id, name, path, has_sd) in shares {
            let open: Option<(String, Rights)> = if !has_sd {
                Some((wellknown::EVERYONE.to_string(), Rights::FullControl))
            } else {
                share_aces
                    .get(&id)
                    .into_iter()
                    .flatten()
                    .cloned()
                    .find(|(sid, rights)| {
                        wellknown::is_broad_principal(sid) && matches!(rights, Rights::FullControl)
                    })
            };
            if let Some((sid, rights)) = open {
                findings.push(Finding {
                    system_id: Some(system_id),
                    rule: "SHARE_OPEN",
                    title: format!(
                        "Freigabe \\\\{name}: {} {}",
                        dir.view(&sid).name,
                        rights.label_de()
                    ),
                    detail: format!(
                        "Freigabe {name} ({path}) erlaubt {} {}",
                        dir.view(&sid).name,
                        rights.label_de()
                    ),
                    path: Some(path),
                    sid: Some(sid),
                    affected: 1,
                });
            }
        }
    }

    // --- Veraltete Systeme ---
    {
        let limit = Utc::now() - Duration::days(cfg.stale_scan_days);
        let it = tx
            .query(
                "SELECT y.id, y.hostname, s.finished_at FROM systems y LEFT JOIN scans s ON s.id = y.last_scan_id",
                &[],
            )
            .await?;
        for r in &it {
            let (id, host, ts): (i64, String, Option<DateTime<Utc>>) =
                (r.get(0), r.get(1), r.get(2));
            if ts.is_none_or(|t| t < limit) {
                findings.push(Finding {
                    system_id: Some(id),
                    rule: "STALE_SYSTEM",
                    title: format!("{host} nicht aktuell gescannt"),
                    detail: format!(
                        "Letzter Scan: {}",
                        ts.map(|t| t.format("%d.%m.%Y %H:%M").to_string())
                            .unwrap_or_else(|| "nie".into())
                    ),
                    path: None,
                    sid: None,
                    affected: 1,
                });
            }
        }
    }

    // --- Active Directory ---
    if dir.ad_loaded {
        let used: HashSet<String> = tx
            .query(
                "SELECT DISTINCT sid FROM aces UNION SELECT DISTINCT sid FROM share_aces",
                &[],
            )
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect();
        let mut ad_counts: HashMap<&'static str, usize> = HashMap::new();
        let mut push_ad = |f: Finding, findings: &mut Vec<Finding>| {
            let n = ad_counts.entry(f.rule).or_default();
            if *n < max {
                *n += 1;
                findings.push(f);
            }
        };
        let mut groups: Vec<_> = dir.groups.iter().collect();
        groups.sort_by(|a, b| a.1.sam.cmp(&b.1.sam));
        for (sid, g) in groups {
            // Vordefinierte Gruppen (RID < 1000, BUILTIN) nicht bewerten
            if !g.is_security || rid(sid).is_none_or(|r| r < 1000) || wellknown::is_well_known(sid)
            {
                continue;
            }
            let view = dir.view(sid);
            let direct = dir.members.get(sid).map(|m| m.len()).unwrap_or(0);
            if direct == 0 {
                push_ad(
                    Finding {
                        system_id: None,
                        rule: "AD_EMPTY_GROUP",
                        title: format!("Leere Gruppe {}", view.name),
                        detail: if used.contains(sid) {
                            "Gruppe hat keine Mitglieder, ist aber in Berechtigungen eingetragen."
                                .into()
                        } else {
                            "Gruppe hat keine Mitglieder.".into()
                        },
                        path: None,
                        sid: Some(sid.clone()),
                        affected: 1,
                    },
                    &mut findings,
                );
            } else {
                let users = dir.transitive_user_members(sid);
                if !users.is_empty()
                    && users
                        .iter()
                        .all(|u| dir.users.get(u).is_some_and(|x| !x.enabled))
                {
                    push_ad(
                        Finding {
                            system_id: None,
                            rule: "AD_ORPHANED_GROUP",
                            title: format!(
                                "Gruppe {} nur mit deaktivierten Mitgliedern",
                                view.name
                            ),
                            detail: format!("{} Benutzer, alle deaktiviert", users.len()),
                            path: None,
                            sid: Some(sid.clone()),
                            affected: users.len() as i64,
                        },
                        &mut findings,
                    );
                }
            }
            let indirectly_used = used.contains(sid)
                || dir
                    .transitive_groups(sid)
                    .iter()
                    .any(|(g, _)| used.contains(g));
            if !indirectly_used && !used.is_empty() {
                push_ad(
                    Finding {
                        system_id: None,
                        rule: "AD_UNUSED_GROUP",
                        title: format!("Gruppe {} ohne Berechtigungen", view.name),
                        detail: g.description.clone().unwrap_or_default(),
                        path: None,
                        sid: Some(sid.clone()),
                        affected: 1,
                    },
                    &mut findings,
                );
            }
        }

        let mut disabled_in_groups = 0i64;
        let mut examples = Vec::new();
        let mut users: Vec<_> = dir.users.iter().filter(|(_, u)| !u.is_computer).collect();
        users.sort_by(|a, b| a.1.sam.cmp(&b.1.sam));
        for (sid, u) in users {
            if rid(sid).is_some_and(|r| r < 1000) {
                continue; // Administrator, Gast, krbtgt
            }
            if dir.is_inactive(u) {
                push_ad(
                    Finding {
                        system_id: None,
                        rule: "AD_INACTIVE_USER",
                        title: format!("Inaktiv: {}", dir.view(sid).name),
                        detail: match u.last_logon {
                            Some(t) => format!("Letzte Anmeldung {}", t.format("%d.%m.%Y")),
                            None => "Nie angemeldet".into(),
                        },
                        path: None,
                        sid: Some(sid.clone()),
                        affected: 1,
                    },
                    &mut findings,
                );
            }
            if !u.enabled {
                let groups = dir
                    .member_of
                    .get(sid)
                    .map(|g| {
                        g.iter()
                            .filter(|g| {
                                dir.groups.contains_key(*g) && rid(g).is_some_and(|r| r >= 1000)
                            })
                            .count()
                    })
                    .unwrap_or(0);
                if groups > 0 {
                    disabled_in_groups += 1;
                    if examples.len() < 5 {
                        examples.push(format!("{} ({} Gruppen)", dir.view(sid).name, groups));
                    }
                }
            }
        }
        if disabled_in_groups > 0 {
            findings.push(Finding {
                system_id: None,
                rule: "AD_DISABLED_IN_GROUPS",
                title: format!("{disabled_in_groups} deaktivierte Konten in Gruppen"),
                detail: format!("z. B.:\n{}", examples.join("\n")),
                path: None,
                sid: None,
                affected: disabled_in_groups,
            });
        }
    }

    // --- Speichern ---
    let now = Utc::now();
    let initial = crate::db::get_meta(tx, "analysis_at").await?.is_none();
    let old_fps: HashSet<String> = tx
        .query(
            "SELECT fingerprint FROM findings WHERE fingerprint IS NOT NULL",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    tx.execute("DELETE FROM findings", &[]).await?;
    {
        let sink = tx
            .copy_in(
                "COPY findings (system_id, rule, severity, title, detail, path, sid, affected, created_at, fingerprint) FROM STDIN BINARY",
            )
            .await?;
        let writer = BinaryCopyInWriter::new(
            sink,
            &[
                Type::INT8,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::TEXT,
                Type::INT8,
                Type::TIMESTAMPTZ,
                Type::TEXT,
            ],
        );
        pin_mut!(writer);
        for f in &findings {
            let sev = rule(f.rule).map(|r| r.severity).unwrap_or(Severity::Info);
            let fp = fingerprint(f);
            writer
                .as_mut()
                .write(&[
                    &f.system_id,
                    &f.rule,
                    &sev.as_str(),
                    &f.title,
                    &f.detail,
                    &f.path,
                    &f.sid,
                    &f.affected,
                    &now,
                    &fp,
                ])
                .await?;
        }
        writer.finish().await?;
    }
    // Audit-Assist: verschwundene Befunde gelten als behoben, wieder aufgetauchte als offen
    tx.execute(
        "UPDATE finding_states SET status = 'resolved', resolved_at = $1
         WHERE status IN ('fixed', 'accepted')
           AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.fingerprint = finding_states.fingerprint)",
        &[&now],
    )
    .await?;
    tx.execute(
        "DELETE FROM finding_states WHERE status = 'resolved'
           AND EXISTS (SELECT 1 FROM findings f WHERE f.fingerprint = finding_states.fingerprint)",
        &[],
    )
    .await?;
    crate::db::set_meta(tx, "analysis_at", Some(&now.to_rfc3339())).await?;
    let new_findings = findings
        .iter()
        .filter(|f| !old_fps.contains(&fingerprint(f)))
        .map(|f| NewFinding {
            rule: f.rule,
            severity: rule(f.rule).map(|r| r.severity).unwrap_or(Severity::Info),
            title: f.title.clone(),
            system_id: f.system_id,
        })
        .collect();
    let grade_changes = record_history(tx).await?;
    Ok(AnalysisSummary {
        findings: findings.len(),
        new_findings,
        grade_changes,
        initial,
    })
}

/// Schreibt die Tageswerte der Bewertung (gesamt, Infrastruktur, AD, je System)
/// und liefert alle Bereiche, deren Note sich verschlechtert hat.
async fn record_history(tx: &Transaction<'_>) -> Result<Vec<GradeChange>> {
    let rows = tx
        .query(
            "SELECT f.system_id, f.severity, f.affected FROM findings f
             WHERE NOT EXISTS (SELECT 1 FROM finding_states fs WHERE fs.fingerprint = f.fingerprint AND fs.status = 'accepted')",
            &[],
        )
        .await?;
    // (Bereich, System) → Befunde
    let mut groups: BTreeMap<(&'static str, i64), Vec<(Severity, i64)>> = BTreeMap::new();
    for g in [("total", 0), ("infra", 0), ("ad", 0)] {
        groups.insert(g, Vec::new());
    }
    for r in tx.query("SELECT id FROM systems", &[]).await? {
        groups.insert(("system", r.get(0)), Vec::new());
    }
    for r in &rows {
        let sys: Option<i64> = r.get(0);
        let item = (Severity::parse(r.get(1)), r.get::<_, i64>(2));
        groups.entry(("total", 0)).or_default().push(item);
        match sys {
            Some(id) => {
                groups.entry(("infra", 0)).or_default().push(item);
                groups.entry(("system", id)).or_default().push(item);
            }
            None => groups.entry(("ad", 0)).or_default().push(item),
        }
    }
    let previous: HashMap<(String, i64), (String, i32)> = tx
        .query(
            "SELECT DISTINCT ON (scope, system_id) scope, system_id, grade, score FROM score_history
             ORDER BY scope, system_id, day DESC",
            &[],
        )
        .await?
        .iter()
        .map(|r| ((r.get(0), r.get(1)), (r.get(2), r.get(3))))
        .collect();
    let today = Utc::now().date_naive();
    let mut changes = Vec::new();
    for ((scope, sys), items) in groups {
        let mut counts = [0i32; 5];
        for (sev, _) in &items {
            counts[*sev as usize] += 1;
        }
        let s = score(items);
        tx.execute(
            "INSERT INTO score_history (day, scope, system_id, score, grade, critical, high, medium, low, info)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (day, scope, system_id) DO UPDATE SET score = excluded.score, grade = excluded.grade,
                critical = excluded.critical, high = excluded.high, medium = excluded.medium,
                low = excluded.low, info = excluded.info",
            &[
                &today,
                &scope,
                &sys,
                &(s.score as i32),
                &s.grade,
                &counts[0],
                &counts[1],
                &counts[2],
                &counts[3],
                &counts[4],
            ],
        )
        .await?;
        if let Some((old_grade, old_score)) = previous.get(&(scope.to_string(), sys)) {
            if s.grade > old_grade.as_str() {
                changes.push(GradeChange {
                    scope,
                    system_id: sys,
                    old_grade: old_grade.clone(),
                    new_grade: s.grade.to_string(),
                    old_score: *old_score,
                    new_score: s.score as i32,
                });
            }
        }
    }
    Ok(changes)
}

/// Stabile Kennung eines Befunds über Analyseläufe hinweg (für den Audit-Assist).
///
/// Zusammengefasste Befunde (je System bzw. je System und SID) werden ohne Pfad
/// gebildet, da die Beispielpfade wechseln können.
fn fingerprint(f: &Finding) -> String {
    let path = match f.rule {
        "BROAD_WRITE" | "SHARE_OPEN" => f.path.as_deref().unwrap_or(""),
        _ => "",
    };
    let key = format!(
        "{}|{}|{}|{}",
        f.rule,
        f.system_id
            .map(|i| i.to_string())
            .unwrap_or_else(|| "ad".into()),
        f.sid.as_deref().unwrap_or(""),
        path.to_lowercase()
    );
    pc_common::release::sha256_hex(key.as_bytes())[..24].to_string()
}

/// Gruppen, deren Name auf Administration hindeutet (z. B. „Domänen-Admins“, „FS-Admins“).
fn admin_like(dir: &Directory, sid: &str) -> bool {
    let n = dir.view(sid).name.to_lowercase();
    n.contains("admin") || n.contains("backup") || n.contains("sicherung")
}

#[derive(Debug, Clone, Serialize)]
pub struct Score {
    pub score: u32,
    pub grade: &'static str,
    pub penalty: f64,
}

/// Bewertet eine Menge von Befunden (Schwere, Anzahl betroffener Objekte) mit 0–100 Punkten.
pub fn score<'a>(items: impl IntoIterator<Item = (Severity, i64)>) -> Score {
    let penalty: f64 = items
        .into_iter()
        .map(|(sev, affected)| sev.weight() * (1.0 + (affected.max(1) as f64).log10()).min(3.0))
        .sum();
    let score = (100.0 * (-penalty / 80.0).exp()).round() as u32;
    let grade = match score {
        90.. => "A",
        75..=89 => "B",
        60..=74 => "C",
        45..=59 => "D",
        30..=44 => "E",
        _ => "F",
    };
    Score {
        score,
        grade,
        penalty: (penalty * 10.0).round() / 10.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoring() {
        assert_eq!(score([]).score, 100);
        assert_eq!(score([]).grade, "A");
        let s = score([(Severity::High, 10), (Severity::Medium, 1)]);
        assert!(s.score < 75 && s.score > 30, "{}", s.score);
        assert_eq!(score([(Severity::Info, 1000)]).score, 100);
    }

    #[test]
    fn rules_unique() {
        let ids: HashSet<_> = RULES.iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), RULES.len());
    }
}
