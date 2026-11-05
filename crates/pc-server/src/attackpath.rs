//! Angriffspfade im Active Directory: Wie kommt ein normales Konto über
//! Gruppenmitgliedschaften und AD-Berechtigungen zur Kontrolle über die Domäne?
//!
//! Das AD wird als gerichteter Graph betrachtet. Eine Kante `A → B` heißt: Wer A
//! kontrolliert, kann auch B kontrollieren. Von den Tier-0-Objekten (Domäne,
//! Domänen-Admins usw.) aus wird rückwärts gesucht. So ist für jedes Objekt der kürzeste
//! Weg bekannt. Einstiegspunkte sind die AD-Berechtigungen, die von außerhalb von
//! Tier 0 auf diesen Wegen liegen; sie sind das, was sich beheben lässt.
//!
//! Bewusst nicht berücksichtigt: Verweigern-Einträge (die Auswertung ist dadurch im
//! Zweifel strenger), Sicherheitsfilter von GPOs, SYSVOL-Rechte, Rechte auf anderen
//! Domänen, Eigenschaftssätze außer „Account Restrictions“.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use anyhow::Result;
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{json, Value};
use tokio_postgres::types::Json as PgJson;
use tokio_postgres::GenericClient;

use crate::api::{ApiResult, AppState};
use crate::directory::{Directory, PrincipalView};
use pc_common::adacl::{parse_gp_link, rights_of, AdAclObject, AdRight};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/attack-paths", get(overview))
        .route("/api/v1/attack-paths/principal/{sid}", get(principal))
        .with_state(state)
}

const AUTHENTICATED_USERS: &str = "S-1-5-11";
const EVERYONE: &str = "S-1-1-0";
const BUILTIN_USERS: &str = "S-1-5-32-545";

/// Art einer Kante im Graphen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    MemberOf,
    Right(AdRight),
    Contains,
    GpoApplies,
}

impl Edge {
    fn id(self) -> &'static str {
        match self {
            Edge::MemberOf => "member_of",
            Edge::Right(r) => r.id(),
            Edge::Contains => "contains",
            Edge::GpoApplies => "gpo_applies",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Edge::MemberOf => "ist Mitglied von",
            Edge::Right(r) => r.label(),
            Edge::Contains => "enthält",
            Edge::GpoApplies => "GPO gilt für",
        }
    }
}

/// Ein Eintrag, den Administratoren beheben können: `trustee` hat `rights` auf `target`.
#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub trustee: String,
    pub target: String,
    pub target_dn: String,
    pub rights: Vec<AdRight>,
    /// Breite Gruppen wie Domänen-Benutzer gelangen an dieses Recht.
    pub broad: bool,
    /// Betroffene aktive Benutzerkonten außerhalb von Tier 0.
    pub exposed_users: usize,
    /// Kanten bis Tier 0, inklusive dieses Rechts.
    pub hops: usize,
}

impl EntryPoint {
    pub fn dcsync(&self) -> bool {
        self.rights.contains(&AdRight::DcSync)
    }
    pub fn rule(&self) -> &'static str {
        if self.dcsync() {
            "AD_DCSYNC_RIGHT"
        } else if self.broad {
            "AD_ATTACK_PATH_BROAD"
        } else {
            "AD_ATTACK_PATH"
        }
    }
    pub fn rights_text(&self) -> String {
        self.rights
            .iter()
            .map(|r| r.label())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Ergebnis der Auswertung.
pub struct AttackGraph {
    /// Berechtigungen wurden überhaupt erfasst.
    pub collected: bool,
    pub tier0: HashSet<String>,
    next: HashMap<String, (String, Edge)>,
    /// Wie `next`, aber ohne Wege über breite Gruppen.
    next_direct: HashMap<String, (String, Edge)>,
    objects: HashMap<String, ObjectInfo>,
    pub entries: Vec<EntryPoint>,
    pub exposed_users: usize,
    pub total_users: usize,
}

#[derive(Clone)]
struct ObjectInfo {
    dn: String,
    kind: String,
    display_name: Option<String>,
}

fn node_id(o: &AdAclObject) -> String {
    o.sid.clone().unwrap_or_else(|| o.dn.to_lowercase())
}

/// Elternobjekt eines DN (beachtet maskierte Kommas).
fn parent_dn(dn: &str) -> Option<&str> {
    let mut escaped = false;
    for (i, c) in dn.char_indices() {
        match c {
            '\\' if !escaped => escaped = true,
            ',' if !escaped => return Some(dn[i + 1..].trim_start()),
            _ => escaped = false,
        }
    }
    None
}

/// Darf diese Art von Recht auf dieser Art von Objekt zur Kontrolle führen?
pub fn applies_to(kind: &str, r: AdRight) -> bool {
    use AdRight::*;
    let general = matches!(
        r,
        GenericAll | GenericWrite | WriteDacl | WriteOwner | Owner
    );
    match kind {
        "user" => {
            general
                || matches!(
                    r,
                    ForceChangePassword | AllExtendedRights | WriteSpn | KeyCredentialLink
                )
        }
        "computer" => general || matches!(r, AllExtendedRights | KeyCredentialLink | Rbcd),
        "group" => general || matches!(r, AddMember | AddSelf),
        "domain" => general || matches!(r, AllExtendedRights | GpLink | DcSync),
        "ou" => general || r == GpLink,
        "container" | "gpo" => general,
        _ => false,
    }
}

/// Wirksame Rechte je Konto auf einem Objekt.
fn effective_rights(o: &AdAclObject) -> BTreeMap<String, BTreeSet<AdRight>> {
    let mut per: BTreeMap<String, BTreeSet<AdRight>> = BTreeMap::new();
    for a in &o.aces {
        for r in rights_of(a) {
            per.entry(a.trustee.clone()).or_default().insert(r);
        }
    }
    if let Some(owner) = &o.owner {
        per.entry(owner.clone()).or_default().insert(AdRight::Owner);
    }
    per.retain(|_, set| {
        // DCSync braucht beide Replikationsrechte zusammen
        if o.kind == "domain"
            && (set.contains(&AdRight::AllExtendedRights)
                || (set.contains(&AdRight::GetChanges) && set.contains(&AdRight::GetChangesAll)))
        {
            set.insert(AdRight::DcSync);
        }
        set.retain(|r| applies_to(&o.kind, *r));
        !set.is_empty()
    });
    per
}

/// Tier 0: Gruppen und Konten mit Kontrolle über die Domäne samt aller Mitglieder.
fn tier0_set(dir: &Directory, objects: &[AdAclObject]) -> HashSet<String> {
    let mut roots: Vec<String> = [
        "S-1-5-32-544",
        "S-1-5-32-548",
        "S-1-5-32-549",
        "S-1-5-32-550",
        "S-1-5-32-551",
        "S-1-5-18",
        "S-1-5-9",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(ds) = &dir.domain_sid {
        roots.push(ds.clone());
        for r in [500, 502, 512, 516, 518, 519, 520, 526, 527] {
            roots.push(format!("{ds}-{r}"));
        }
    }
    for (sid, g) in &dir.groups {
        if g.sam.eq_ignore_ascii_case("DnsAdmins") {
            roots.push(sid.clone());
        }
    }
    for o in objects {
        let dn = o.dn.to_lowercase();
        if o.kind == "domain" || dn.starts_with("cn=adminsdholder,cn=system,") {
            roots.push(node_id(o));
        }
    }
    let mut out = HashSet::new();
    let mut stack = roots;
    while let Some(s) = stack.pop() {
        if out.insert(s.clone()) {
            stack.extend(dir.members.get(&s).into_iter().flatten().cloned());
        }
    }
    out
}

/// Berechnet Angriffspfade aus den geladenen Daten.
pub fn analyze(dir: &Directory, objects: &[AdAclObject]) -> AttackGraph {
    let tier0 = tier0_set(dir, objects);
    let info: HashMap<String, ObjectInfo> = objects
        .iter()
        .map(|o| {
            (
                node_id(o),
                ObjectInfo {
                    dn: o.dn.clone(),
                    kind: o.kind.clone(),
                    display_name: o.display_name.clone(),
                },
            )
        })
        .collect();
    let mut rev: HashMap<String, Vec<(String, Edge)>> = HashMap::new();
    let mut add = |from: &str, to: &str, e: Edge| {
        rev.entry(to.to_string())
            .or_default()
            .push((from.to_string(), e));
    };

    // Mitgliedschaften, dazu die impliziten Gruppen jedes aktiven Kontos
    for (m, groups) in &dir.member_of {
        for g in groups {
            add(m, g, Edge::MemberOf);
        }
    }
    for (sid, u) in &dir.users {
        if u.enabled {
            add(sid, AUTHENTICATED_USERS, Edge::MemberOf);
        }
    }
    add(AUTHENTICATED_USERS, EVERYONE, Edge::MemberOf);

    // AD-Berechtigungen
    let mut acl: Vec<(String, String, String, Vec<AdRight>)> = Vec::new();
    let mut controllable: HashSet<String> = HashSet::new();
    for o in objects {
        let id = node_id(o);
        for (trustee, rights) in effective_rights(o) {
            if dir.is_orphaned(&trustee) || trustee == id {
                continue;
            }
            for r in &rights {
                add(&trustee, &id, Edge::Right(*r));
            }
            controllable.insert(id.clone());
            acl.push((
                trustee,
                id.clone(),
                o.dn.clone(),
                rights.into_iter().collect(),
            ));
        }
    }

    // Wer eine OU oder einen Container kontrolliert, kontrolliert auch den Inhalt,
    // sofern das Objekt die Vererbung nicht abgeschaltet hat.
    let by_dn: HashMap<String, &AdAclObject> =
        objects.iter().map(|o| (o.dn.to_lowercase(), o)).collect();
    let mut children: HashMap<String, Vec<&AdAclObject>> = HashMap::new();
    for o in objects {
        let Some(parent) = parent_dn(&o.dn).map(str::to_lowercase) else {
            continue;
        };
        if let Some(p) = by_dn.get(&parent) {
            if !o.protected && matches!(p.kind.as_str(), "ou" | "container") {
                add(&node_id(p), &node_id(o), Edge::Contains);
            }
            children.entry(parent).or_default().push(o);
        }
    }

    // GPOs wirken auf alle Konten unter der Verknüpfung, auch bei abgeschalteter
    // ACL-Vererbung. Nur für GPOs nötig, die jemand außerhalb von Tier 0 ändern kann.
    for o in objects {
        let Some(raw) = &o.gp_link else { continue };
        for link in parse_gp_link(raw).into_iter().filter(|l| !l.disabled) {
            let Some(gpo) = by_dn.get(&link.dn.to_lowercase()) else {
                continue;
            };
            let gpo_id = node_id(gpo);
            if !controllable.contains(&gpo_id) {
                continue;
            }
            let mut stack = vec![o];
            while let Some(cur) = stack.pop() {
                if matches!(cur.kind.as_str(), "user" | "computer") {
                    add(&gpo_id, &node_id(cur), Edge::GpoApplies);
                }
                for c in children.get(&cur.dn.to_lowercase()).into_iter().flatten() {
                    // Blockierte Vererbung stoppt nur nicht erzwungene Verknüpfungen
                    if link.enforced || c.gp_options & 1 == 0 {
                        stack.push(*c);
                    }
                }
            }
        }
    }

    // Rückwärtssuche ab Tier 0. Für die Einträge zählen nur Wege ohne breite Gruppe: Hat
    // Domänen-Benutzer einen Weg, ist das ein Befund. Das Recht auf irgendeinen Benutzer, der
    // dadurch ebenfalls einen Weg hat, bringt niemandem zusätzliche Rechte.
    let search = |skip: &HashSet<String>| {
        let mut next: HashMap<String, (String, Edge)> = HashMap::new();
        let mut dist: HashMap<String, usize> = HashMap::new();
        let mut queue: VecDeque<String> = tier0.iter().cloned().collect();
        while let Some(n) = queue.pop_front() {
            let d = dist.get(&n).copied().unwrap_or(0);
            for (from, e) in rev.get(&n).into_iter().flatten() {
                if !tier0.contains(from) && !next.contains_key(from) && !skip.contains(from) {
                    next.insert(from.clone(), (n.clone(), *e));
                    dist.insert(from.clone(), d + 1);
                    queue.push_back(from.clone());
                }
            }
        }
        (next, dist)
    };

    // Gruppen, in die breite Gruppen (auch verschachtelt) gelangen
    let mut broad_set: HashSet<String> = [AUTHENTICATED_USERS, EVERYONE, BUILTIN_USERS]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Some(ds) = &dir.domain_sid {
        broad_set.insert(format!("{ds}-513"));
        broad_set.insert(format!("{ds}-515"));
    }
    for b in broad_set.clone() {
        for (g, _) in dir.transitive_groups(&b) {
            broad_set.insert(g);
        }
    }
    let (next, _) = search(&HashSet::new());
    let (next_direct, dist) = search(&broad_set);

    // Aktive Benutzer außerhalb von Tier 0
    let normal: HashSet<&String> = dir
        .users
        .iter()
        .filter(|(sid, u)| u.enabled && !u.is_computer && !tier0.contains(*sid))
        .map(|(sid, _)| sid)
        .collect();
    let exposed_users = normal.iter().filter(|u| next.contains_key(**u)).count();

    let mut entries = Vec::new();
    for (trustee, target, dn, rights) in acl {
        if tier0.contains(&trustee)
            || !(tier0.contains(&target) || next_direct.contains_key(&target))
        {
            continue;
        }
        // Deaktiviertes Konto ohne Kontrolle von außen kann das Recht nicht nutzen
        if dir.users.get(&trustee).is_some_and(|u| !u.enabled) && !next.contains_key(&trustee) {
            continue;
        }
        let exposed = if trustee == AUTHENTICATED_USERS || trustee == EVERYONE {
            normal.len()
        } else if normal.contains(&trustee) {
            1
        } else {
            dir.transitive_user_members(&trustee)
                .iter()
                .filter(|u| normal.contains(*u))
                .count()
        };
        entries.push(EntryPoint {
            broad: broad_set.contains(&trustee),
            exposed_users: exposed,
            hops: 1 + dist.get(&target).copied().unwrap_or(0),
            target_dn: dn,
            trustee,
            target,
            rights,
        });
    }
    entries.sort_by(|a, b| {
        (b.dcsync(), b.broad)
            .cmp(&(a.dcsync(), a.broad))
            .then(a.hops.cmp(&b.hops))
            .then(b.exposed_users.cmp(&a.exposed_users))
            .then(a.target_dn.cmp(&b.target_dn))
            .then(a.trustee.cmp(&b.trustee))
    });

    AttackGraph {
        collected: !objects.is_empty(),
        tier0,
        next,
        next_direct,
        objects: info,
        entries,
        exposed_users,
        total_users: normal.len(),
    }
}

/// Lädt die gespeicherten AD-Berechtigungen.
pub async fn load_objects(c: &impl GenericClient) -> Result<Vec<AdAclObject>> {
    Ok(c.query("SELECT data FROM ad_acl_objects ORDER BY dn", &[])
        .await?
        .iter()
        .map(|r| r.get::<_, PgJson<AdAclObject>>(0).0)
        .collect())
}

/// Ein Knoten für Anzeige und Texte.
#[derive(Serialize, Clone)]
pub struct NodeView {
    pub id: String,
    pub name: String,
    pub kind: String,
    /// Für Konten und Gruppen, damit die Oberfläche verlinken kann.
    pub principal: Option<PrincipalView>,
    pub dn: Option<String>,
    pub tier0: bool,
}

#[derive(Serialize, Clone)]
pub struct PathStep {
    pub from: NodeView,
    pub edge: &'static str,
    pub label: &'static str,
    pub to: NodeView,
}

impl AttackGraph {
    pub fn node(&self, dir: &Directory, id: &str) -> NodeView {
        let obj = self.objects.get(id);
        let dn = obj.map(|o| o.dn.clone());
        let tier0 = self.tier0.contains(id);
        if id.starts_with("S-1-") && obj.is_none_or(|o| o.kind != "domain") {
            let v = dir.view(id);
            return NodeView {
                id: id.to_string(),
                name: v.name.clone(),
                kind: v.kind.clone(),
                principal: Some(v),
                dn,
                tier0,
            };
        }
        let (name, kind) = match obj {
            Some(o) if o.kind == "domain" => (
                format!("Domäne {}", dir.domain.as_deref().unwrap_or(&o.dn)),
                "domain".to_string(),
            ),
            Some(ObjectInfo {
                display_name: Some(n),
                kind,
                ..
            }) if !n.is_empty() => (n.clone(), kind.clone()),
            Some(o) => {
                let rdn = o.dn.split(',').next().unwrap_or(&o.dn);
                let short = rdn.split_once('=').map_or(rdn, |(_, v)| v);
                (short.to_string(), o.kind.clone())
            }
            None => (id.to_string(), "unknown".to_string()),
        };
        NodeView {
            id: id.to_string(),
            name,
            kind,
            principal: None,
            dn,
            tier0,
        }
    }

    /// Weg von `id` nach Tier 0; leer, wenn es keinen gibt.
    pub fn path_from(&self, dir: &Directory, id: &str) -> Vec<PathStep> {
        let mut out = Vec::new();
        let mut cur = id.to_string();
        while let Some((to, e)) = self.next.get(&cur) {
            out.push(PathStep {
                from: self.node(dir, &cur),
                edge: e.id(),
                label: e.label(),
                to: self.node(dir, to),
            });
            cur = to.clone();
        }
        out
    }

    /// Weg über einen bestimmten Einstiegspunkt.
    pub fn entry_path(&self, dir: &Directory, e: &EntryPoint) -> Vec<PathStep> {
        let first = e
            .rights
            .iter()
            .copied()
            .max()
            .map_or(Edge::Right(AdRight::GenericAll), Edge::Right);
        let mut out = vec![PathStep {
            from: self.node(dir, &e.trustee),
            edge: first.id(),
            label: first.label(),
            to: self.node(dir, &e.target),
        }];
        let mut cur = e.target.clone();
        while let Some((to, edge)) = self.next_direct.get(&cur) {
            out.push(PathStep {
                from: self.node(dir, &cur),
                edge: edge.id(),
                label: edge.label(),
                to: self.node(dir, to),
            });
            cur = to.clone();
        }
        out
    }

    /// Weg als Text für Befunde, z. B. `A → (Recht) → B → (Mitglied) → C`.
    pub fn path_text(&self, dir: &Directory, e: &EntryPoint) -> String {
        let steps = self.entry_path(dir, e);
        let mut s = steps
            .first()
            .map(|f| f.from.name.clone())
            .unwrap_or_default();
        for st in &steps {
            s.push_str(&format!(" → ({}) → {}", st.label, st.to.name));
        }
        s
    }
}

async fn overview(State(st): State<AppState>) -> ApiResult {
    let c = st.db.get().await?;
    let dir = Directory::load(&**c, st.cfg.analysis.inactive_days).await?;
    let objects = load_objects(&**c).await?;
    let g = analyze(&dir, &objects);
    let entries: Vec<Value> = g
        .entries
        .iter()
        .take(500)
        .map(|e| {
            json!({
                "trustee": g.node(&dir, &e.trustee),
                "target": g.node(&dir, &e.target),
                "rights": e.rights.iter().map(|r| json!({"id": r.id(), "label": r.label()})).collect::<Vec<_>>(),
                "rule": e.rule(),
                "severity": crate::analysis::rule(e.rule()).map(|r| r.severity.as_str()),
                "broad": e.broad,
                "exposed_users": e.exposed_users,
                "hops": e.hops,
                "path": g.entry_path(&dir, e),
            })
        })
        .collect();
    let mut tier0: Vec<NodeView> = g
        .tier0
        .iter()
        .filter(|id| {
            dir.groups.contains_key(*id)
                || dir.users.contains_key(*id)
                || g.objects.contains_key(*id)
        })
        .map(|id| g.node(&dir, id))
        .collect();
    tier0.sort_by_key(|n| n.name.to_lowercase());
    Ok(Json(json!({
        "collected": g.collected,
        "ad_loaded": dir.ad_loaded,
        "objects": objects.len(),
        "stats": {
            "entries": g.entries.len(),
            "dcsync": g.entries.iter().filter(|e| e.dcsync()).count(),
            "broad": g.entries.iter().filter(|e| e.broad).count(),
            "exposed_users": g.exposed_users,
            "total_users": g.total_users,
            "tier0": tier0.len(),
        },
        "entries": entries,
        "tier0": tier0,
    })))
}

async fn principal(State(st): State<AppState>, Path(sid): Path<String>) -> ApiResult {
    let c = st.db.get().await?;
    let dir = Directory::load(&**c, st.cfg.analysis.inactive_days).await?;
    let objects = load_objects(&**c).await?;
    let g = analyze(&dir, &objects);
    Ok(Json(json!({
        "collected": g.collected,
        "tier0": g.tier0.contains(&sid),
        "path": g.path_from(&dir, &sid),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{AdGroupRow, AdUserRow};
    use chrono::{Duration, Utc};
    use pc_common::adacl::AdAce;

    const DS: &str = "S-1-5-21-1-2-3";
    const DOMAIN_DN: &str = "DC=x,DC=y";

    fn s(rid: u32) -> String {
        format!("{DS}-{rid}")
    }

    fn user_row(sam: &str, enabled: bool) -> AdUserRow {
        AdUserRow {
            sam: sam.into(),
            upn: None,
            display_name: None,
            enabled,
            last_logon: Some(Utc::now()),
            created: None,
            is_computer: false,
            pwd_last_set: None,
            pwd_never_expires: false,
            spns: vec![],
            uac: None,
        }
    }

    fn directory(users: &[(u32, bool)], groups: &[u32], members: &[(u32, u32)]) -> Directory {
        let mut d = Directory::empty_for_tests(Utc::now() - Duration::days(90));
        d.ad_loaded = true;
        d.domain = Some("x.y".into());
        d.domain_sid = Some(DS.into());
        for (r, en) in users {
            d.users.insert(s(*r), user_row(&format!("u{r}"), *en));
        }
        for r in groups {
            d.groups.insert(
                s(*r),
                AdGroupRow {
                    sam: format!("g{r}"),
                    description: None,
                    scope: None,
                    is_security: true,
                },
            );
        }
        for (g, m) in members {
            d.members.entry(s(*g)).or_default().push(s(*m));
            d.member_of.entry(s(*m)).or_default().push(s(*g));
        }
        d
    }

    fn obj(dn: &str, sid: Option<String>, kind: &str, aces: Vec<AdAce>) -> AdAclObject {
        AdAclObject {
            dn: dn.into(),
            sid,
            kind: kind.into(),
            display_name: None,
            owner: None,
            protected: false,
            gp_link: None,
            gp_options: 0,
            aces,
        }
    }

    fn allow(trustee: String, mask: u32, ty: Option<&str>) -> AdAce {
        AdAce {
            trustee,
            mask,
            object_type: ty.map(str::to_string),
            inherited: false,
        }
    }

    const FORCE: &str = "00299570-246d-11d0-a768-00aa006e0529";
    const GET: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
    const GET_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";

    /// u2000 (Helpdesk 3000) darf das Kennwort von Admin 1000 zurücksetzen, der Domänen-Admin ist.
    #[test]
    fn group_member_reaches_domain_admins() {
        let d = directory(
            &[(1000, true), (2000, true), (2001, true)],
            &[512, 3000],
            &[(512, 1000), (3000, 2000)],
        );
        let objects = vec![obj(
            "CN=Admin,CN=Users,DC=x,DC=y",
            Some(s(1000)),
            "user",
            vec![allow(s(3000), 0x100, Some(FORCE))],
        )];
        let g = analyze(&d, &objects);
        assert_eq!(g.entries.len(), 1);
        let e = &g.entries[0];
        assert_eq!(e.trustee, s(3000));
        assert_eq!(e.rule(), "AD_ATTACK_PATH");
        assert_eq!(e.exposed_users, 1);
        assert_eq!(g.exposed_users, 1);
        assert_eq!(g.total_users, 2);
        let path = g.path_from(&d, &s(2000));
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].edge, "member_of");
        assert_eq!(path[1].edge, "force_change_password");
        assert!(g.path_from(&d, &s(2001)).is_empty());
    }

    #[test]
    fn harmless_acl_gives_no_entry() {
        let d = directory(&[(2000, true), (2001, true)], &[512], &[]);
        let objects = vec![obj(
            "CN=Normal,CN=Users,DC=x,DC=y",
            Some(s(2001)),
            "user",
            vec![allow(s(2000), 0xF01FF, None)],
        )];
        assert!(analyze(&d, &objects).entries.is_empty());
    }

    #[test]
    fn dcsync_needs_both_rights() {
        let d = directory(&[(2000, true), (2001, true)], &[512], &[]);
        let objects = vec![obj(
            DOMAIN_DN,
            Some(DS.to_string()),
            "domain",
            vec![
                allow(s(2000), 0x100, Some(GET)),
                allow(s(2000), 0x100, Some(GET_ALL)),
                allow(s(2001), 0x100, Some(GET)),
            ],
        )];
        let g = analyze(&d, &objects);
        assert_eq!(g.entries.len(), 1);
        assert_eq!(g.entries[0].trustee, s(2000));
        assert_eq!(g.entries[0].rule(), "AD_DCSYNC_RIGHT");
    }

    #[test]
    fn domain_users_is_broad_also_when_nested() {
        let d = directory(
            &[(1000, true), (2000, true)],
            &[512, 513, 3000],
            &[(512, 1000), (513, 2000), (3000, 513)],
        );
        let objects = vec![obj(
            "CN=g512,DC=x,DC=y",
            Some(s(512)),
            "group",
            vec![allow(
                s(3000),
                0x20,
                Some("bf9679c0-0de6-11d0-a285-00aa003049e2"),
            )],
        )];
        let g = analyze(&d, &objects);
        assert_eq!(g.entries[0].rule(), "AD_ATTACK_PATH_BROAD");
        assert_eq!(g.entries[0].exposed_users, 1);
    }

    /// Hat eine breite Gruppe einen Weg, ist das Recht auf einen ihrer Benutzer kein eigener Befund.
    #[test]
    fn no_extra_entries_through_broad_groups() {
        let d = directory(
            &[(1000, true), (2000, true), (2001, true)],
            &[512, 513],
            &[(512, 1000), (513, 2000), (513, 2001)],
        );
        let objects = vec![
            obj(
                "CN=Admin,DC=x,DC=y",
                Some(s(1000)),
                "user",
                vec![allow(s(513), 0x40000, None)],
            ),
            obj(
                "CN=u2001,DC=x,DC=y",
                Some(s(2001)),
                "user",
                vec![allow(s(2000), 0xF01FF, None)],
            ),
        ];
        let g = analyze(&d, &objects);
        assert_eq!(g.entries.len(), 1);
        assert_eq!(g.entries[0].trustee, s(513));
        // Der einzelne Benutzer sieht trotzdem seinen Weg
        assert_eq!(g.path_from(&d, &s(2000)).len(), 2);
    }

    #[test]
    fn authenticated_users_reach_everybody() {
        let d = directory(
            &[(1000, true), (2000, true), (2001, false)],
            &[512],
            &[(512, 1000)],
        );
        let objects = vec![obj(
            "CN=Admin,DC=x,DC=y",
            Some(s(1000)),
            "user",
            vec![allow(AUTHENTICATED_USERS.into(), 0x40000, None)],
        )];
        let g = analyze(&d, &objects);
        assert_eq!(g.entries[0].exposed_users, 1);
        assert!(g.entries[0].broad);
        assert_eq!(g.exposed_users, 1);
        assert!(g.path_from(&d, &s(2001)).is_empty(), "deaktiviert");
    }

    /// Wer die OU kontrolliert, erreicht den Admin darin, außer der schützt seine ACL.
    #[test]
    fn ou_control_respects_protected_children() {
        let d = directory(&[(1000, true), (2000, true)], &[512], &[(512, 1000)]);
        let ou = "OU=Admins,DC=x,DC=y";
        let mk = |protected| {
            let mut child = obj(
                "CN=Admin,OU=Admins,DC=x,DC=y",
                Some(s(1000)),
                "user",
                vec![],
            );
            child.protected = protected;
            vec![
                obj(ou, None, "ou", vec![allow(s(2000), 0x40000, None)]),
                child,
            ]
        };
        assert_eq!(analyze(&d, &mk(false)).entries.len(), 1);
        assert!(analyze(&d, &mk(true)).entries.is_empty());
    }

    /// Eine änderbare GPO wirkt über die Verknüpfung auch auf geschützte Konten.
    #[test]
    fn gpo_control_reaches_linked_accounts() {
        let d = directory(&[(1000, true), (2000, true)], &[512], &[(512, 1000)]);
        let gpo_dn = "cn={A},cn=policies,cn=system,DC=x,DC=y";
        let mk = |link: &str, block: i32| {
            let mut top = obj("OU=Top,DC=x,DC=y", None, "ou", vec![]);
            top.gp_link = Some(format!("[LDAP://{gpo_dn};{link}]"));
            let mut inner = obj("OU=Admins,OU=Top,DC=x,DC=y", None, "ou", vec![]);
            inner.gp_options = block;
            let mut admin = obj(
                "CN=Admin,OU=Admins,OU=Top,DC=x,DC=y",
                Some(s(1000)),
                "user",
                vec![],
            );
            admin.protected = true;
            vec![
                obj(gpo_dn, None, "gpo", vec![allow(s(2000), 0xF01FF, None)]),
                top,
                inner,
                admin,
            ]
        };
        assert_eq!(analyze(&d, &mk("0", 0)).entries.len(), 1, "normal");
        assert!(analyze(&d, &mk("1", 0)).entries.is_empty(), "abgeschaltet");
        assert!(analyze(&d, &mk("0", 1)).entries.is_empty(), "blockiert");
        assert_eq!(analyze(&d, &mk("2", 1)).entries.len(), 1, "erzwungen");
    }

    #[test]
    fn owner_counts_as_control() {
        let d = directory(&[(1000, true), (2000, true)], &[512], &[(512, 1000)]);
        let mut o = obj("CN=Admin,DC=x,DC=y", Some(s(1000)), "user", vec![]);
        o.owner = Some(s(2000));
        let g = analyze(&d, &[o]);
        assert_eq!(g.entries[0].rights, [AdRight::Owner]);
    }

    #[test]
    fn tier0_members_and_orphans_are_no_entry_points() {
        let d = directory(&[(1000, true)], &[512], &[(512, 1000)]);
        let objects = vec![obj(
            DOMAIN_DN,
            Some(DS.to_string()),
            "domain",
            vec![
                allow(s(1000), 0xF01FF, None),
                allow(s(9999), 0xF01FF, None), // gelöschtes Konto
            ],
        )];
        assert!(analyze(&d, &objects).entries.is_empty());
    }

    #[test]
    fn cycles_terminate() {
        let d = directory(
            &[(1000, true), (2000, true)],
            &[512, 3000, 3001],
            &[(512, 1000), (3000, 3001), (3001, 3000), (3000, 2000)],
        );
        let objects = vec![obj(
            "CN=Admin,DC=x,DC=y",
            Some(s(1000)),
            "user",
            vec![allow(s(3001), 0xF01FF, None)],
        )];
        let g = analyze(&d, &objects);
        assert_eq!(g.entries.len(), 1);
        assert_eq!(g.entries[0].exposed_users, 1);
        assert_eq!(g.path_from(&d, &s(2000)).last().unwrap().to.id, s(1000));
    }

    #[test]
    fn parent_of_dn_with_escaped_comma() {
        assert_eq!(parent_dn("CN=Müller\\, Anna,OU=X,DC=y"), Some("OU=X,DC=y"));
        assert_eq!(parent_dn("DC=y"), None);
    }
}
