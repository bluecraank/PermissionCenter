//! Zusammengeführte Sicht auf Sicherheitsprinzipale aus Client-Auflösung,
//! Active Directory und bekannten SIDs.

use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use tokio_postgres::GenericClient;

use crate::db;
use pc_common::sid::domain_prefix;
use pc_common::{wellknown, PrincipalKind};

#[derive(Debug, Clone)]
pub struct AdUserRow {
    pub sam: String,
    pub upn: Option<String>,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub last_logon: Option<DateTime<Utc>>,
    pub created: Option<DateTime<Utc>>,
    pub is_computer: bool,
    pub pwd_last_set: Option<DateTime<Utc>>,
    pub pwd_never_expires: bool,
    pub spns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AdGroupRow {
    pub sam: String,
    pub description: Option<String>,
    pub scope: Option<String>,
    pub is_security: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrincipalView {
    pub sid: String,
    pub name: String,
    /// user, group, computer, well_known, unknown
    pub kind: String,
    /// active, disabled, inactive, orphaned, system, unknown
    pub status: String,
    pub in_ad: bool,
    pub description: Option<String>,
}

pub struct Directory {
    client: HashMap<String, (Option<String>, Option<String>, PrincipalKind)>,
    pub users: HashMap<String, AdUserRow>,
    pub groups: HashMap<String, AdGroupRow>,
    /// Mitglied → direkte Gruppen
    pub member_of: HashMap<String, Vec<String>>,
    /// Gruppe → direkte Mitglieder
    pub members: HashMap<String, Vec<String>>,
    pub domain: Option<String>,
    pub domain_sid: Option<String>,
    pub ad_loaded: bool,
    pub inactive_before: DateTime<Utc>,
}

impl Directory {
    pub async fn load(c: &impl GenericClient, inactive_days: i64) -> Result<Self> {
        let mut client = HashMap::new();
        for r in c
            .query("SELECT sid, name, domain, kind FROM principals", &[])
            .await?
        {
            let kind: String = r.get(3);
            client.insert(
                r.get::<_, String>(0),
                (r.get(1), r.get(2), PrincipalKind::parse(&kind)),
            );
        }

        let mut users = HashMap::new();
        for r in c
            .query(
                "SELECT sid, sam, upn, display_name, enabled, last_logon, created, is_computer,
                        pwd_last_set, pwd_never_expires, COALESCE(spns, '{}') FROM ad_users",
                &[],
            )
            .await?
        {
            users.insert(
                r.get::<_, String>(0),
                AdUserRow {
                    sam: r.get(1),
                    upn: r.get(2),
                    display_name: r.get(3),
                    enabled: r.get(4),
                    last_logon: r.get(5),
                    created: r.get(6),
                    is_computer: r.get(7),
                    pwd_last_set: r.get(8),
                    pwd_never_expires: r.get(9),
                    spns: r.get(10),
                },
            );
        }

        let mut groups = HashMap::new();
        for r in c
            .query(
                "SELECT sid, sam, description, scope, is_security FROM ad_groups",
                &[],
            )
            .await?
        {
            groups.insert(
                r.get::<_, String>(0),
                AdGroupRow {
                    sam: r.get(1),
                    description: r.get(2),
                    scope: r.get(3),
                    is_security: r.get(4),
                },
            );
        }

        let mut member_of: HashMap<String, Vec<String>> = HashMap::new();
        let mut members: HashMap<String, Vec<String>> = HashMap::new();
        for r in c
            .query("SELECT group_sid, member_sid FROM ad_members", &[])
            .await?
        {
            let (g, m): (String, String) = (r.get(0), r.get(1));
            member_of.entry(m.clone()).or_default().push(g.clone());
            members.entry(g).or_default().push(m);
        }

        let ad_loaded = !users.is_empty() || !groups.is_empty();
        Ok(Self {
            client,
            users,
            groups,
            member_of,
            members,
            domain: db::get_meta(c, "ad_domain").await?,
            domain_sid: db::get_meta(c, "ad_domain_sid").await?,
            ad_loaded,
            inactive_before: Utc::now() - Duration::days(inactive_days),
        })
    }

    pub fn is_user(&self, sid: &str) -> bool {
        if let Some(u) = self.users.get(sid) {
            return !u.is_computer;
        }
        matches!(self.client.get(sid), Some((_, _, PrincipalKind::User)))
    }

    /// AD-Benutzer ist aktiviert, aber seit `inactive_days` nicht angemeldet.
    pub fn is_inactive(&self, u: &AdUserRow) -> bool {
        u.enabled
            && match u.last_logon {
                Some(t) => t < self.inactive_before,
                None => u.created.is_some_and(|c| c < self.inactive_before),
            }
    }

    pub fn is_orphaned(&self, sid: &str) -> bool {
        if wellknown::is_well_known(sid)
            || self.users.contains_key(sid)
            || self.groups.contains_key(sid)
        {
            return false;
        }
        if let Some((_, _, k)) = self.client.get(sid) {
            if k.is_orphaned() {
                return true;
            }
        }
        // AD geladen und SID gehört zur Domäne, ist dort aber unbekannt
        self.ad_loaded
            && self.domain_sid.is_some()
            && domain_prefix(sid) == self.domain_sid.as_deref()
    }

    pub fn view(&self, sid: &str) -> PrincipalView {
        if let Some(u) = self.users.get(sid) {
            let status = if !u.enabled {
                "disabled"
            } else if self.is_inactive(u) {
                "inactive"
            } else {
                "active"
            };
            let dom = self
                .domain
                .as_deref()
                .and_then(|d| d.split('.').next())
                .unwrap_or("");
            let name = if dom.is_empty() {
                u.sam.clone()
            } else {
                format!("{}\\{}", dom.to_uppercase(), u.sam)
            };
            return PrincipalView {
                sid: sid.into(),
                name,
                kind: if u.is_computer { "computer" } else { "user" }.into(),
                status: status.into(),
                in_ad: true,
                description: u.display_name.clone().or_else(|| u.upn.clone()),
            };
        }
        if let Some(g) = self.groups.get(sid) {
            let dom = self
                .domain
                .as_deref()
                .and_then(|d| d.split('.').next())
                .unwrap_or("");
            let name = if g.scope.as_deref() == Some("builtin") || dom.is_empty() {
                g.sam.clone()
            } else {
                format!("{}\\{}", dom.to_uppercase(), g.sam)
            };
            return PrincipalView {
                sid: sid.into(),
                name,
                kind: "group".into(),
                status: if wellknown::is_well_known(sid) {
                    "system"
                } else {
                    "active"
                }
                .into(),
                in_ad: true,
                description: g.description.clone(),
            };
        }
        let orphaned = self.is_orphaned(sid);
        let client = self.client.get(sid);
        let name = client
            .and_then(|(n, d, _)| match (d, n) {
                (Some(d), Some(n)) if !d.is_empty() => Some(format!("{d}\\{n}")),
                (_, Some(n)) => Some(n.clone()),
                _ => None,
            })
            .or_else(|| wellknown::well_known_name(sid).map(str::to_string))
            .unwrap_or_else(|| sid.to_string());
        let kind = match client.map(|c| c.2) {
            Some(PrincipalKind::User) => "user",
            Some(PrincipalKind::Computer) => "computer",
            Some(PrincipalKind::Group | PrincipalKind::Alias) => "group",
            Some(PrincipalKind::WellKnownGroup) => "well_known",
            _ if wellknown::is_well_known(sid) => "well_known",
            _ => "unknown",
        };
        let status = if orphaned {
            "orphaned"
        } else if wellknown::is_well_known(sid) {
            "system"
        } else if client.is_some_and(|c| c.2 != PrincipalKind::Unknown) {
            "active"
        } else {
            "unknown"
        };
        PrincipalView {
            sid: sid.into(),
            name,
            kind: kind.into(),
            status: status.into(),
            in_ad: false,
            description: None,
        }
    }

    /// Alle Gruppen, in denen `sid` (transitiv) Mitglied ist, mit Pfad der Verschachtelung.
    pub fn transitive_groups(&self, sid: &str) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((sid.to_string(), Vec::<String>::new()));
        seen.insert(sid.to_string());
        while let Some((cur, path)) = queue.pop_front() {
            for g in self.member_of.get(&cur).into_iter().flatten() {
                if seen.insert(g.clone()) {
                    let mut p = path.clone();
                    p.push(g.clone());
                    out.push((g.clone(), p.clone()));
                    queue.push_back((g.clone(), p));
                }
            }
        }
        out
    }

    /// Alle (transitiven) Mitglieder einer Gruppe, die Benutzer sind.
    pub fn transitive_user_members(&self, group: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut stack = vec![group.to_string()];
        while let Some(g) = stack.pop() {
            for m in self.members.get(&g).into_iter().flatten() {
                if !seen.insert(m.clone()) {
                    continue;
                }
                if self.groups.contains_key(m) {
                    stack.push(m.clone());
                } else if self.users.get(m).is_some_and(|u| !u.is_computer) {
                    out.push(m.clone());
                }
            }
        }
        out
    }
}
