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
    let mut settings: Value = r.get(1);
    for s in settings.as_array_mut().into_iter().flatten() {
        s["weakness"] = crate::weakness::gpo_hint(
            s["name"].as_str().unwrap_or(""),
            s["detail"].as_str().unwrap_or(""),
        );
    }
    data["settings"] = settings;
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
                    "weakness": crate::weakness::gpo_hint(
                        s["name"].as_str().unwrap_or(""),
                        s["detail"].as_str().unwrap_or(""),
                    ),
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
    /// Pfad, aktiv, erzwungen
    pub links: Vec<(String, bool, bool)>,
    pub kind: String,
    pub apply_sids: Vec<String>,
    pub apply_names: Vec<String>,
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

fn active_paths(g: &Lite) -> BTreeSet<String> {
    g.links
        .iter()
        .filter(|l| l.1)
        .map(|l| l.0.to_lowercase())
        .collect()
}

/// Vergleich der Verknüpfungen: 3 = gleich, 2 = teilweise gleich, 1 = verschachtelt, 0 = getrennt.
fn link_relation(a: &Lite, b: &Lite) -> u8 {
    let (pa, pb) = (active_paths(a), active_paths(b));
    if pa.is_empty() || pb.is_empty() {
        return 0;
    }
    if pa == pb {
        3
    } else if pa.intersection(&pb).next().is_some() {
        2
    } else if pa.iter().any(|x| pb.iter().any(|y| path_related(x, y))) {
        1
    } else {
        0
    }
}

/// Vergleich der Sicherheitsfilter.
fn filter_relation(a: &Lite, b: &Lite) -> &'static str {
    if a.kind == "nobody" || b.kind == "nobody" {
        return "none";
    }
    if a.kind != "targeted" && b.kind != "targeted" {
        return "same";
    }
    if a.kind != b.kind {
        return "broad_targeted";
    }
    let (sa, sb): (BTreeSet<&String>, BTreeSet<&String>) =
        (a.apply_sids.iter().collect(), b.apply_sids.iter().collect());
    if sa == sb {
        "same"
    } else if sa.intersection(&sb).next().is_some() {
        "shared"
    } else {
        "different"
    }
}

fn is_enforced(g: &Lite) -> bool {
    g.links.iter().any(|l| l.1 && l.2)
}

/// Pfadtiefe der Verknüpfung: bei erzwungenen die höchste, sonst die tiefste.
fn link_depth(g: &Lite, enforced: bool) -> usize {
    let depths = g
        .links
        .iter()
        .filter(|l| l.1 && (!enforced || l.2))
        .map(|l| l.0.split('/').count());
    if enforced {
        depths.min().unwrap_or(0)
    } else {
        depths.max().unwrap_or(0)
    }
}

/// Welche GPO setzt sich bei einem Konflikt voraussichtlich durch?
///
/// Erzwungene Verknüpfungen gewinnen vor nicht erzwungenen. Unter erzwungenen gewinnt die
/// höchste, sonst die dem Ziel nächste. Bei gleicher Höhe entscheidet die Reihenfolge der
/// Verknüpfungen, die nicht erfasst wird. Blockierte Vererbung ist ebenfalls nicht erfasst.
fn likely_winner(gpos: &[Lite], part: &[usize]) -> (Option<usize>, String) {
    let enforced: Vec<usize> = part
        .iter()
        .copied()
        .filter(|i| is_enforced(&gpos[*i]))
        .collect();
    let unique = |cands: &[usize], depth: &dyn Fn(usize) -> usize, want_min: bool| {
        let best = if want_min {
            cands.iter().map(|i| depth(*i)).min()
        } else {
            cands.iter().map(|i| depth(*i)).max()
        }?;
        let mut top = cands.iter().copied().filter(|i| depth(*i) == best);
        let first = top.next()?;
        top.next().is_none().then_some(first)
    };
    match enforced.len() {
        1 => (
            Some(enforced[0]),
            format!(
                "{} setzt sich durch, weil nur diese GPO erzwungen ist.",
                gpos[enforced[0]].name
            ),
        ),
        0 => match unique(part, &|i| link_depth(&gpos[i], false), false) {
            Some(w) => (
                Some(w),
                format!(
                    "Keine GPO ist erzwungen. {} setzt sich durch, weil sie am nächsten am Ziel verknüpft ist.",
                    gpos[w].name
                ),
            ),
            None => (
                None,
                "Keine GPO ist erzwungen und alle sind gleich tief verknüpft. Die Reihenfolge der Verknüpfungen entscheidet."
                    .to_string(),
            ),
        },
        _ => match unique(&enforced, &|i| link_depth(&gpos[i], true), true) {
            Some(w) => (
                Some(w),
                format!(
                    "Mehrere GPOs sind erzwungen. {} setzt sich durch, weil sie am höchsten verknüpft ist.",
                    gpos[w].name
                ),
            ),
            None => (
                None,
                "Mehrere GPOs sind erzwungen und gleich hoch verknüpft. Die Reihenfolge der Verknüpfungen entscheidet."
                    .to_string(),
            ),
        },
    }
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
        let mut best = (0u8, 0u8);
        let mut relation = (0u8, "none");
        let mut part: BTreeSet<usize> = BTreeSet::new();
        for x in 0..idx.len() {
            for y in x + 1..idx.len() {
                if !conflict || sigs[x] != sigs[y] {
                    let (a, b) = (&gpos[idx[x]], &gpos[idx[y]]);
                    let pair_ov = overlap(a, b);
                    ov = ov.max(pair_ov);
                    if pair_ov > 0 {
                        part.insert(idx[x]);
                        part.insert(idx[y]);
                    }
                    // Angezeigt wird das Paar, das am stärksten zusammenwirkt
                    let links = link_relation(a, b);
                    if (pair_ov, links) >= best {
                        best = (pair_ov, links);
                        relation = (links, filter_relation(a, b));
                    }
                }
            }
        }
        let overlap_label = ["no", "maybe", "yes"][ov as usize];
        let (winner, effect) = if conflict && ov > 0 {
            let part: Vec<usize> = part.into_iter().collect();
            let (w, text) = likely_winner(gpos, &part);
            (w.map(|i| gpos[i].id.clone()), Some(text))
        } else {
            (None, None)
        };
        let enforced_count = idx.iter().filter(|i| is_enforced(&gpos[**i])).count();
        let link_label = ["none", "nested", "partial", "same"][relation.0 as usize];
        let entries: Vec<Value> = idx
            .iter()
            .map(|i| {
                json!({
                    "gpo_id": gpos[*i].id, "gpo_name": gpos[*i].name,
                    "detail": per[i].join(" ; "),
                    "enforced": is_enforced(&gpos[*i]),
                    "links": gpos[*i].links.iter().map(|l| json!({
                        "path": l.0, "enabled": l.1, "enforced": l.2,
                    })).collect::<Vec<_>>(),
                    "filter_kind": gpos[*i].kind,
                    "filter": gpos[*i].apply_names,
                })
            })
            .collect();
        out.push(json!({
            "scope": scope, "area": area, "name": name, "kind": kind,
            "overlap": overlap_label,
            "link_relation": link_label,
            "filter_relation": relation.1,
            "enforced_count": enforced_count,
            "winner": winner,
            "effect": effect,
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
                        l["enforced"].as_bool().unwrap_or(false),
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
            apply_names: data["targeting"]["apply"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| {
                    p["name"]
                        .as_str()
                        .filter(|n| !n.is_empty())
                        .or(p["sid"].as_str())
                        .unwrap_or("")
                        .to_string()
                })
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
                x["enforced_count"].as_u64().unwrap_or(0) == 0,
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
            links: vec![(path.into(), true, false)],
            kind: "broad".into(),
            apply_sids: vec![],
            apply_names: vec![],
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

    fn enforced(mut l: Lite) -> Lite {
        l.links[0].2 = true;
        l
    }

    #[test]
    fn relation_of_links_and_filters() {
        let d = find_duplicates(&[lite("a", "corp/Server", "x"), lite("b", "corp/Server", "x")]);
        assert_eq!(d[0]["link_relation"], "same");
        assert_eq!(d[0]["filter_relation"], "same");
        let d = find_duplicates(&[
            lite("a", "corp/Server", "x"),
            lite("b", "corp/Server/SQL", "x"),
        ]);
        assert_eq!(d[0]["link_relation"], "nested");
        let mut b = lite("b", "corp/Server", "x");
        b.links.push(("corp/Clients".into(), true, false));
        let d = find_duplicates(&[lite("a", "corp/Server", "x"), b]);
        assert_eq!(d[0]["link_relation"], "partial");
        let mut b = lite("b", "corp/Server", "x");
        b.kind = "targeted".into();
        b.apply_sids = vec!["S-1".into()];
        let d = find_duplicates(&[lite("a", "corp/Server", "x"), b]);
        assert_eq!(d[0]["filter_relation"], "broad_targeted");
        let d = find_duplicates(&[lite("a", "corp/A", "x"), lite("b", "corp/B", "x")]);
        assert_eq!(d[0]["link_relation"], "none");
    }

    #[test]
    fn enforced_gpo_wins_conflict() {
        // Nicht erzwungen: die dem Ziel nächste Verknüpfung gewinnt
        let d = find_duplicates(&[
            lite("oben", "corp/Server", "x"),
            lite("unten", "corp/Server/SQL", "y"),
        ]);
        assert_eq!(d[0]["winner"], "unten");
        assert_eq!(d[0]["enforced_count"], 0);
        // Erzwungen schlägt die tiefere Verknüpfung
        let d = find_duplicates(&[
            enforced(lite("oben", "corp/Server", "x")),
            lite("unten", "corp/Server/SQL", "y"),
        ]);
        assert_eq!(d[0]["winner"], "oben");
        assert_eq!(d[0]["enforced_count"], 1);
        assert_eq!(d[0]["gpos"][0]["enforced"], true);
        // Beide erzwungen: die höhere gewinnt
        let d = find_duplicates(&[
            enforced(lite("oben", "corp/Server", "x")),
            enforced(lite("unten", "corp/Server/SQL", "y")),
        ]);
        assert_eq!(d[0]["winner"], "oben");
        // Gleiche OU: Reihenfolge ist nicht erfasst, also keine Aussage
        let d = find_duplicates(&[lite("a", "corp/Server", "x"), lite("b", "corp/Server", "y")]);
        assert!(d[0]["winner"].is_null());
        assert!(d[0]["effect"].as_str().unwrap().contains("Reihenfolge"));
        // Erzwungen an deaktivierter Verknüpfung zählt nicht
        let mut a = enforced(lite("a", "corp/Server", "x"));
        a.links[0].1 = false;
        a.links.push(("corp/Server".into(), true, false));
        let d = find_duplicates(&[a, lite("b", "corp/Server", "y")]);
        assert_eq!(d[0]["enforced_count"], 0);
        // Duplikat: niemand muss gewinnen
        let d = find_duplicates(&[lite("a", "corp/S", "x"), lite("b", "corp/S", "x")]);
        assert!(d[0]["effect"].is_null());
    }
}
