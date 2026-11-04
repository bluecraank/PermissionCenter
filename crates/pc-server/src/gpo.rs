//! Gruppenrichtlinien (GPOs): Ablage, Bewertung der Zuweisung und Suche.
//!
//! Der `gpo-client` liefert Rohdaten ([`GpoSnapshot`]); der Server leitet daraus
//! Zuweisung (Security Filtering) und Befunde ab und speichert je GPO einen
//! JSON-Datensatz. Einstellungen liegen getrennt, damit Listen klein bleiben.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::Result;
use chrono::{Datelike, Utc};
use serde_json::{json, Value};
use tokio_postgres::{GenericClient, Transaction};

use crate::db;
use pc_common::gpo::{GpoItem, GpoPerm, GpoSnapshot};

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS gpos (
    id       TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    data     JSONB NOT NULL,
    settings JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS gpo_groups (
    sid  TEXT PRIMARY KEY,
    data JSONB NOT NULL
);
"#;

/// Breite Gruppen: Jeder, Authentifizierte Benutzer, Domänen-Benutzer/-Gäste/-Computer.
pub fn is_broad(sid: &str) -> bool {
    sid == "S-1-1-0"
        || sid == "S-1-5-11"
        || (sid.starts_with("S-1-5-21-")
            && (sid.ends_with("-513") || sid.ends_with("-514") || sid.ends_with("-515")))
}

fn is_orphan(p: &GpoPerm) -> bool {
    p.name.is_empty()
        || p.name.starts_with("S-1-5-21-")
        || p.sid_type == "Unknown"
        || p.sid_type == "Deleted"
}

fn finding(severity: &str, code: &str, text: String) -> Value {
    json!({ "severity": severity, "code": code, "text": text })
}

/// Zuweisung und Befunde einer GPO.
pub fn analyze(g: &GpoItem) -> (Value, Vec<Value>) {
    let apply: Vec<&GpoPerm> = g
        .permissions
        .iter()
        .filter(|p| p.permission == "GpoApply" && !p.denied)
        .collect();
    let deny: Vec<&GpoPerm> = g.permissions.iter().filter(|p| p.denied).collect();
    let kind = if apply.is_empty() {
        "nobody"
    } else if apply.iter().any(|p| is_broad(&p.sid)) {
        "broad"
    } else {
        "targeted"
    };
    let targeting = json!({ "kind": kind, "apply": apply, "deny": deny });
    let names = |v: &[&GpoPerm]| {
        v.iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut f: Vec<Value> = Vec::new();
    if g.links.is_empty() {
        f.push(finding(
            "warn",
            "unlinked",
            "GPO ist mit keiner OU/Domäne/Site verknüpft.".into(),
        ));
    } else if g.links.iter().all(|l| !l.enabled) {
        f.push(finding(
            "warn",
            "links_disabled",
            "Alle Verknüpfungen sind deaktiviert.".into(),
        ));
    }
    if !g.computer_enabled && !g.user_enabled {
        f.push(finding(
            "warn",
            "disabled",
            "Computer- und Benutzerkonfiguration sind deaktiviert.".into(),
        ));
    }
    if g.settings.is_empty() {
        f.push(finding(
            "warn",
            "empty",
            "GPO enthält keine Einstellungen.".into(),
        ));
    } else {
        let has_c = g.settings.iter().any(|s| s.scope == "Computer");
        let has_u = g.settings.iter().any(|s| s.scope == "Benutzer");
        if g.computer_enabled && !has_c && has_u {
            f.push(finding(
                "info",
                "unused_computer",
                "Computerkonfiguration ist aktiv, enthält aber nichts – könnte deaktiviert werden."
                    .into(),
            ));
        }
        if g.user_enabled && !has_u && has_c {
            f.push(finding(
                "info",
                "unused_user",
                "Benutzerkonfiguration ist aktiv, enthält aber nichts – könnte deaktiviert werden."
                    .into(),
            ));
        }
    }
    match kind {
        "nobody" => f.push(finding("warn", "nobody", "Niemand hat „Gruppenrichtlinie übernehmen“ – die GPO wirkt auf keinen Client/Benutzer.".into())),
        "targeted" => f.push(finding("info", "targeted", format!("Nur zugewiesen an: {}", names(&apply)))),
        _ => {}
    }
    if !deny.is_empty() {
        f.push(finding(
            "info",
            "deny",
            format!("Ausnahmen (Verweigern): {}", names(&deny)),
        ));
    }
    if !g.wmi_filter.is_empty() {
        f.push(finding(
            "info",
            "wmi",
            format!("WMI-Filter: {}", g.wmi_filter),
        ));
    }
    if kind == "targeted" {
        let reads = g.permissions.iter().any(|p| {
            !p.denied
                && (p.sid == "S-1-5-11"
                    || p.sid == "S-1-1-0"
                    || (p.sid.starts_with("S-1-5-21-") && p.sid.ends_with("-515")))
                && (p.permission == "GpoRead"
                    || p.permission == "GpoApply"
                    || p.permission.starts_with("GpoEdit"))
        });
        if !reads && g.settings.iter().any(|s| s.scope == "Benutzer") {
            f.push(finding("warn", "ms16_072", "Weder „Authentifizierte Benutzer“ noch „Domänencomputer“ haben Leserecht – Benutzereinstellungen können seit MS16-072 fehlschlagen.".into()));
        }
    }
    for p in g.permissions.iter().filter(|p| is_orphan(p)) {
        let n = if p.name.is_empty() { &p.sid } else { &p.name };
        f.push(finding(
            "warn",
            "orphan_sid",
            format!("Verwaiste/unauflösbare Berechtigung: {n}"),
        ));
    }
    for l in g.links.iter().filter(|l| l.enforced) {
        f.push(finding(
            "info",
            "enforced",
            format!("Erzwungen verknüpft mit {}", l.som_path),
        ));
    }
    if let Some(y) = g.modified.get(0..4).and_then(|s| s.parse::<i32>().ok()) {
        if Utc::now().year() - y >= 3 {
            f.push(finding(
                "info",
                "stale",
                format!(
                    "Zuletzt geändert {} – seit über 2 Jahren unverändert.",
                    &g.modified[..10.min(g.modified.len())]
                ),
            ));
        }
    }
    let mismatch = |v: &str| {
        let n: Vec<&str> = v
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .collect();
        n.len() >= 2 && n[0] != n[1]
    };
    if mismatch(&g.computer_version) || mismatch(&g.user_version) {
        f.push(finding(
            "warn",
            "version_mismatch",
            "AD- und SYSVOL-Version weichen ab – Replikationsproblem möglich.".into(),
        ));
    }
    (targeting, f)
}

/// Ersetzt den GPO-Stand vollständig.
pub async fn store(tx: &Transaction<'_>, snap: &GpoSnapshot) -> Result<usize> {
    tx.batch_execute("DELETE FROM gpos; DELETE FROM gpo_groups;")
        .await?;
    let ins = tx
        .prepare("INSERT INTO gpos (id, name, data, settings) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING")
        .await?;
    for g in &snap.gpos {
        let (targeting, findings) = analyze(g);
        let mut data = serde_json::to_value(g)?;
        let settings = data
            .as_object_mut()
            .and_then(|m| m.remove("settings"))
            .unwrap_or(json!([]));
        data["settings_count"] = json!(g.settings.len());
        data["targeting"] = targeting;
        data["findings"] = json!(findings);
        tx.execute(&ins, &[&g.id, &g.name, &data, &settings])
            .await?;
    }
    let gins = tx
        .prepare("INSERT INTO gpo_groups (sid, data) VALUES ($1, $2) ON CONFLICT (sid) DO NOTHING")
        .await?;
    for gr in &snap.groups {
        tx.execute(&gins, &[&gr.sid, &serde_json::to_value(gr)?])
            .await?;
    }
    db::set_meta(tx, "gpo_domain", Some(&snap.domain)).await?;
    db::set_meta(tx, "gpo_host", Some(&snap.host)).await?;
    db::set_meta(
        tx,
        "gpo_synced_at",
        Some(&snap.collected_at.unwrap_or_else(Utc::now).to_rfc3339()),
    )
    .await?;
    Ok(snap.gpos.len())
}

/// Liste aller GPOs (ohne Einstellungen) samt Gruppen und Metadaten.
pub async fn overview(c: &impl GenericClient) -> Result<Value> {
    let gpos: Vec<Value> = c
        .query("SELECT data FROM gpos ORDER BY lower(name)", &[])
        .await?
        .iter()
        .map(|r| r.get::<_, Value>(0))
        .collect();
    let groups: BTreeMap<String, Value> = c
        .query("SELECT sid, data FROM gpo_groups", &[])
        .await?
        .iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, Value>(1)))
        .collect();
    Ok(json!({
        "loaded": !gpos.is_empty(),
        "domain": db::get_meta(c, "gpo_domain").await?,
        "host": db::get_meta(c, "gpo_host").await?,
        "synced_at": db::get_meta(c, "gpo_synced_at").await?,
        "gpos": gpos,
        "groups": groups,
    }))
}

/// Eine GPO mit allen Einstellungen.
pub async fn detail(c: &impl GenericClient, id: &str) -> Result<Option<Value>> {
    let id = id.to_lowercase();
    let Some(r) = c
        .query_opt("SELECT data, settings FROM gpos WHERE id = $1", &[&id])
        .await?
    else {
        return Ok(None);
    };
    let mut data: Value = r.get(0);
    data["settings"] = r.get(1);
    Ok(Some(data))
}

/// Einstellungssuche über alle GPOs: Begriffe (UND), `-begriff` schließt aus.
pub async fn search(
    c: &impl GenericClient,
    q: &str,
    scope: &str,
    area: &str,
    limit: usize,
) -> Result<Value> {
    let toks: Vec<String> = q
        .to_lowercase()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let inc: Vec<&str> = toks
        .iter()
        .filter(|t| !t.starts_with('-'))
        .map(String::as_str)
        .collect();
    let exc: Vec<&str> = toks
        .iter()
        .filter(|t| t.starts_with('-') && t.len() > 1)
        .map(|t| &t[1..])
        .collect();
    let rows = c
        .query(
            "SELECT id, name, settings FROM gpos ORDER BY lower(name)",
            &[],
        )
        .await?;
    let mut areas: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<Value> = Vec::new();
    let mut total = 0usize;
    let mut gpo_ids: HashSet<String> = HashSet::new();
    for r in &rows {
        let id: String = r.get(0);
        let name: String = r.get(1);
        let settings: Value = r.get(2);
        for s in settings.as_array().into_iter().flatten() {
            let sarea = s["area"].as_str().unwrap_or("");
            areas.insert(sarea.to_string());
            if !scope.is_empty() && s["scope"].as_str() != Some(scope) {
                continue;
            }
            if !area.is_empty() && sarea != area {
                continue;
            }
            let hay = format!(
                "{} {}",
                s["name"].as_str().unwrap_or(""),
                s["detail"].as_str().unwrap_or("")
            )
            .to_lowercase();
            if !inc.iter().all(|t| hay.contains(t)) || exc.iter().any(|t| hay.contains(t)) {
                continue;
            }
            total += 1;
            gpo_ids.insert(id.clone());
            if out.len() < limit {
                out.push(json!({
                    "gpo_id": id, "gpo_name": name,
                    "scope": s["scope"], "area": s["area"], "name": s["name"], "detail": s["detail"]
                }));
            }
        }
    }
    Ok(json!({ "total": total, "gpos": gpo_ids.len(), "rows": out, "areas": areas }))
}

/// Betroffene GPO-Namen je Befundcode (Grundlage der Prüfregeln).
pub async fn hits(c: &impl GenericClient) -> Result<BTreeMap<String, Vec<String>>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in c
        .query(
            "SELECT name, data->'findings' FROM gpos ORDER BY lower(name)",
            &[],
        )
        .await?
    {
        let name: String = r.get(0);
        let f: Value = r.get(1);
        for x in f.as_array().into_iter().flatten() {
            if let Some(code) = x["code"].as_str() {
                m.entry(code.to_string()).or_default().push(name.clone());
            }
        }
    }
    Ok(m)
}

// ---------------------------------------------------------------------------
// Doppelte und widersprüchliche Einstellungen

/// Schlanke GPO-Sicht für den Vergleich.
pub struct Lite {
    pub id: String,
    pub name: String,
    pub links: Vec<(String, bool)>,
    pub kind: String,
    pub apply_sids: Vec<String>,
    pub settings: Vec<(String, String, String, String)>, // scope, area, name, detail
}

fn norm(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn path_related(a: &str, b: &str) -> bool {
    let sa: Vec<String> = a.to_lowercase().split('/').map(str::to_string).collect();
    let sb: Vec<String> = b.to_lowercase().split('/').map(str::to_string).collect();
    let n = sa.len().min(sb.len());
    sa[..n] == sb[..n]
}

/// 0 = nein, 1 = möglich, 2 = ja
fn overlap(a: &Lite, b: &Lite) -> u8 {
    if a.kind == "nobody" || b.kind == "nobody" {
        return 0;
    }
    let linked = a.links.iter().filter(|l| l.1).any(|la| {
        b.links
            .iter()
            .filter(|l| l.1)
            .any(|lb| path_related(&la.0, &lb.0))
    });
    if !linked {
        return 0;
    }
    if a.kind == "targeted" && b.kind == "targeted" {
        let shared = a.apply_sids.iter().any(|s| b.apply_sids.contains(s));
        return if shared { 2 } else { 1 };
    }
    2
}

/// Findet Einstellungen, die in mehreren GPOs vorkommen (gleicher Bereich und Name).
/// `kind`: `duplicate` (überall derselbe Wert) oder `conflict` (abweichende Werte).
pub fn find_duplicates(gpos: &[Lite]) -> Vec<Value> {
    use std::collections::HashMap;
    let mut map: BTreeMap<(String, String, String), HashMap<usize, Vec<String>>> = BTreeMap::new();
    for (i, g) in gpos.iter().enumerate() {
        for (scope, area, name, detail) in &g.settings {
            map.entry((scope.clone(), area.clone(), name.clone()))
                .or_default()
                .entry(i)
                .or_default()
                .push(detail.clone());
        }
    }
    let mut out = Vec::new();
    for ((scope, area, name), per) in map {
        if per.len() < 2 {
            continue;
        }
        let mut idx: Vec<usize> = per.keys().copied().collect();
        idx.sort();
        let sig = |i: &usize| {
            let mut v: Vec<String> = per[i].iter().map(|d| norm(d)).collect();
            v.sort();
            v.dedup();
            v.join(" || ")
        };
        let sigs: Vec<String> = idx.iter().map(sig).collect();
        let conflict = sigs.iter().any(|s| *s != sigs[0]);
        let kind = if conflict { "conflict" } else { "duplicate" };
        // Bei einem Konflikt zählen nur GPOs mit abweichendem Wert, die zusammen wirken können
        let mut ov = 0u8;
        for x in 0..idx.len() {
            for y in x + 1..idx.len() {
                if !conflict || sigs[x] != sigs[y] {
                    ov = ov.max(overlap(&gpos[idx[x]], &gpos[idx[y]]));
                }
            }
        }
        let overlap_label = ["no", "maybe", "yes"][ov as usize];
        let entries: Vec<Value> = idx
            .iter()
            .map(|i| {
                json!({
                    "gpo_id": gpos[*i].id, "gpo_name": gpos[*i].name,
                    "detail": per[i].join(" ; "),
                    "links": gpos[*i].links.iter().map(|l| l.0.clone()).collect::<Vec<_>>(),
                })
            })
            .collect();
        out.push(json!({
            "scope": scope, "area": area, "name": name, "kind": kind,
            "overlap": overlap_label,
            "gpos": entries,
        }));
    }
    out
}

/// Lädt alle GPOs und liefert Duplikate/Konflikte (Konflikte und überlappende zuerst).
pub async fn duplicates(c: &impl GenericClient) -> Result<Vec<Value>> {
    let rows = c
        .query("SELECT id, name, data, settings FROM gpos", &[])
        .await?;
    let mut lite = Vec::new();
    for r in &rows {
        let data: Value = r.get(2);
        let settings: Value = r.get(3);
        // Deaktivierte Konfigurationsteile wirken nicht und zählen daher nicht
        let active = |scope: &str| match scope {
            "Computer" => data["computer_enabled"].as_bool().unwrap_or(true),
            "Benutzer" => data["user_enabled"].as_bool().unwrap_or(true),
            _ => true,
        };
        lite.push(Lite {
            id: r.get(0),
            name: r.get(1),
            links: data["links"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|l| {
                    (
                        l["som_path"].as_str().unwrap_or("").to_string(),
                        l["enabled"].as_bool().unwrap_or(false),
                    )
                })
                .collect(),
            kind: data["targeting"]["kind"].as_str().unwrap_or("").to_string(),
            apply_sids: data["targeting"]["apply"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p["sid"].as_str().map(str::to_string))
                .collect(),
            settings: settings
                .as_array()
                .into_iter()
                .flatten()
                .filter(|s| active(s["scope"].as_str().unwrap_or("")))
                .map(|s| {
                    let g = |k: &str| s[k].as_str().unwrap_or("").to_string();
                    (g("scope"), g("area"), g("name"), g("detail"))
                })
                .collect(),
        });
    }
    let mut v = find_duplicates(&lite);
    v.sort_by(|a, b| {
        let rank = |x: &Value| {
            (
                x["kind"] != "conflict",
                x["overlap"] == "no",
                x["name"].as_str().unwrap_or("").to_string(),
            )
        };
        rank(a).cmp(&rank(b))
    });
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_common::gpo::{GpoLink, GpoSetting};

    fn perm(sid: &str, name: &str, perm: &str) -> GpoPerm {
        GpoPerm {
            sid: sid.into(),
            name: name.into(),
            permission: perm.into(),
            sid_type: "Group".into(),
            ..Default::default()
        }
    }

    #[test]
    fn targeting_kinds() {
        let mut g = GpoItem {
            computer_enabled: true,
            links: vec![GpoLink {
                som_path: "a/b".into(),
                enabled: true,
                ..Default::default()
            }],
            settings: vec![GpoSetting {
                scope: "Benutzer".into(),
                ..Default::default()
            }],
            permissions: vec![perm("S-1-5-11", "Authenticated Users", "GpoApply")],
            ..Default::default()
        };
        assert_eq!(analyze(&g).0["kind"], "broad");
        g.permissions = vec![perm("S-1-5-21-1-2-3-1105", "GG_Vertrieb", "GpoApply")];
        let (t, f) = analyze(&g);
        assert_eq!(t["kind"], "targeted");
        assert!(f.iter().any(|x| x["code"] == "ms16_072"));
        g.permissions = vec![perm(
            "S-1-5-21-1-2-3-512",
            "Domain Admins",
            "GpoEditDeleteModifySecurity",
        )];
        let (t, f) = analyze(&g);
        assert_eq!(t["kind"], "nobody");
        assert!(f.iter().any(|x| x["code"] == "nobody"));
    }

    fn lite(id: &str, path: &str, detail: &str) -> Lite {
        Lite {
            id: id.into(),
            name: id.into(),
            links: vec![(path.into(), true)],
            kind: "broad".into(),
            apply_sids: vec![],
            settings: vec![(
                "Computer".into(),
                "Registry".into(),
                "Firewall".into(),
                detail.into(),
            )],
        }
    }

    #[test]
    fn duplicates_and_conflicts() {
        let d = find_duplicates(&[
            lite("a", "corp/Server", "State: Enabled"),
            lite("b", "corp/Server/SQL", "state:  enabled"),
        ]);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0]["kind"], "duplicate");
        assert_eq!(d[0]["overlap"], "yes");
        let d = find_duplicates(&[
            lite("a", "corp/Server", "State: Enabled"),
            lite("b", "corp/Server", "State: Disabled"),
        ]);
        assert_eq!(d[0]["kind"], "conflict");
        let d = find_duplicates(&[
            lite("a", "corp/Server", "x"),
            lite("b", "corp/Clients", "y"),
        ]);
        assert_eq!(d[0]["overlap"], "no");
        // a und b überlappen mit gleichem Wert; der abweichende Wert in c wirkt woanders
        let d = find_duplicates(&[
            lite("a", "corp/Server", "x"),
            lite("b", "corp/Server", "x"),
            lite("c", "corp/Clients", "y"),
        ]);
        assert_eq!(d[0]["kind"], "conflict");
        assert_eq!(d[0]["overlap"], "no");
    }
}
