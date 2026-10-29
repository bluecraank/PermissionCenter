//! CSV-Exporte (Excel-tauglich: UTF-8 mit BOM, Semikolon, CRLF).

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use chrono::Local;
use serde_json::Value;

use crate::api::{self, ApiError, AppState, FindingQuery};
use crate::db::query_json;
use crate::directory::Directory;
use crate::insights::{self, ChangeQuery};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/export/findings.csv", get(findings))
        .route("/api/v1/export/audit.csv", get(audit))
        .route("/api/v1/export/permissions.csv", get(permissions))
        .route("/api/v1/export/changes.csv", get(changes))
        .route("/api/v1/export/principal/{sid}", get(principal))
        .with_state(state)
}

/// Feld für CSV mit Semikolon als Trenner.
fn field(s: &str) -> String {
    if s.contains([';', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Text eines JSON-Werts (Zahlen, Wahrheitswerte, Zeichenketten).
fn text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "ja" } else { "nein" }.into(),
        other => other.to_string(),
    }
}

pub fn csv_response(name: &str, header: &[&str], rows: Vec<Vec<String>>) -> Response {
    let mut out = String::from("\u{feff}");
    out.push_str(
        &header
            .iter()
            .map(|h| field(h))
            .collect::<Vec<_>>()
            .join(";"),
    );
    out.push_str("\r\n");
    for r in rows {
        out.push_str(&r.iter().map(|c| field(c)).collect::<Vec<_>>().join(";"));
        out.push_str("\r\n");
    }
    let file = format!("{name}-{}.csv", Local::now().format("%Y%m%d"));
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file}\""),
            ),
        ],
        out,
    )
        .into_response()
}

fn pick(v: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .map(|k| {
            let t = text(&v[*k]);
            match *k {
                "severity" => severity_de(&t).into(),
                "scope" => if t == "ad" {
                    "Active Directory"
                } else {
                    "Dateisystem"
                }
                .into(),
                _ => t,
            }
        })
        .collect()
}

pub fn severity_de(s: &str) -> &str {
    match s {
        "critical" => "Kritisch",
        "high" => "Hoch",
        "medium" => "Mittel",
        "low" => "Niedrig",
        "info" => "Info",
        other => other,
    }
}

pub fn status_de(s: &str) -> &str {
    match s {
        "active" => "Aktiv",
        "disabled" => "Deaktiviert",
        "inactive" => "Inaktiv",
        "orphaned" => "Verwaist",
        "system" => "System",
        "unknown" => "Unbekannt",
        other => other,
    }
}

pub fn kind_de(s: &str) -> &str {
    match s {
        "user" => "Benutzer",
        "group" => "Gruppe",
        "computer" => "Computer",
        "well_known" => "Integriert",
        other => other,
    }
}

async fn findings(
    State(st): State<AppState>,
    Query(mut q): Query<FindingQuery>,
) -> Result<Response, ApiError> {
    let mut rows = Vec::new();
    q.limit = Some(1000);
    let mut offset = 0;
    loop {
        q.offset = Some(offset);
        let page = api::findings(
            State(st.clone()),
            Query(FindingQuery {
                system_id: q.system_id,
                severity: q.severity.clone(),
                rule: q.rule.clone(),
                sid: q.sid.clone(),
                scope: q.scope.clone(),
                q: q.q.clone(),
                limit: q.limit,
                offset: q.offset,
            }),
        )
        .await?
        .0;
        let items = page["items"].as_array().cloned().unwrap_or_default();
        let n = items.len() as i64;
        for v in items {
            let mut r = pick(
                &v,
                &[
                    "severity",
                    "hostname",
                    "rule_title",
                    "title",
                    "path",
                    "sid",
                    "affected",
                    "detail",
                ],
            );
            if r[1].is_empty() {
                r[1] = "Active Directory".into();
            }
            r.push(match v["assist_status"].as_str() {
                Some("accepted") => "Ausnahme".into(),
                Some("fixed") => "erledigt, Scan ausstehend".into(),
                _ => "offen".into(),
            });
            rows.push(r);
        }
        offset += n;
        if n < 1000 || offset >= 200_000 {
            break;
        }
    }
    Ok(csv_response(
        "befunde",
        &[
            "Schwere",
            "System",
            "Regel",
            "Befund",
            "Pfad",
            "SID",
            "Betroffen",
            "Details",
            "Status",
        ],
        rows,
    ))
}

async fn audit(State(st): State<AppState>) -> Result<Response, ApiError> {
    let a = api::audit(State(st)).await?.0;
    let rows = a["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            let mut r = vec![if c["passed"] == true {
                "bestanden".to_string()
            } else {
                "nicht bestanden".to_string()
            }];
            r.extend(pick(
                c,
                &[
                    "scope",
                    "severity",
                    "title",
                    "findings",
                    "affected",
                    "accepted",
                    "recommendation",
                ],
            ));
            r
        })
        .collect();
    Ok(csv_response(
        "audit",
        &[
            "Ergebnis",
            "Bereich",
            "Schwere",
            "Prüfung",
            "Befunde",
            "Objekte",
            "Ausnahmen",
            "Empfehlung",
        ],
        rows,
    ))
}

#[derive(serde::Deserialize)]
struct PermQuery {
    system_id: Option<i64>,
}

/// Alle expliziten Berechtigungen (Ordner und Freigaben).
async fn permissions(
    State(st): State<AppState>,
    Query(q): Query<PermQuery>,
) -> Result<Response, ApiError> {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let list = query_json(
        c,
        "SELECT y.hostname, 'Ordner' AS kind, f.path, a.sid, a.ace_type, a.rights, a.flags, f.protected AS protected
         FROM aces a JOIN folders f ON f.system_id = a.system_id AND f.local_id = a.folder_local_id
         JOIN systems y ON y.id = a.system_id
         WHERE NOT a.inherited AND a.ace_type IN ('allow','deny') AND ($1::bigint IS NULL OR a.system_id = $1)
         UNION ALL
         SELECT y.hostname, 'Freigabe', '\\\\' || y.hostname || '\\' || s.name, x.sid, x.ace_type, x.rights, NULL, NULL
         FROM share_aces x JOIN shares s ON s.id = x.share_id JOIN systems y ON y.id = s.system_id
         WHERE NOT s.is_special AND ($1::bigint IS NULL OR s.system_id = $1)
         ORDER BY 1, 3, 4",
        &[&q.system_id],
    )
    .await?;
    let owners = crate::owners::load_all(c).await?;
    let rows = list
        .iter()
        .map(|v| {
            let sid = v["sid"].as_str().unwrap_or("");
            let p = dir.view(sid);
            let path = v["path"].as_str().unwrap_or("");
            let owner =
                crate::owners::effective(&owners, v["hostname"].as_str().unwrap_or(""), path);
            vec![
                text(&v["hostname"]),
                text(&v["kind"]),
                path.to_string(),
                p.name,
                sid.to_string(),
                kind_de(&p.kind).into(),
                status_de(&p.status).into(),
                if v["ace_type"] == "deny" {
                    "Verweigern"
                } else {
                    "Zulassen"
                }
                .into(),
                pc_common::rights::Rights::parse(v["rights"].as_str().unwrap_or(""))
                    .label_de()
                    .into(),
                v["flags"]
                    .as_i64()
                    .map(|f| {
                        if f & 0x3 == 0 {
                            "nur dieser Ordner"
                        } else {
                            "mit Unterordnern"
                        }
                        .to_string()
                    })
                    .unwrap_or_default(),
                text(&v["protected"]),
                owner.unwrap_or_default(),
            ]
        })
        .collect();
    Ok(csv_response(
        "berechtigungen",
        &[
            "System",
            "Art",
            "Pfad",
            "Prinzipal",
            "SID",
            "Typ",
            "Status",
            "Zugriff",
            "Rechte",
            "Gilt für",
            "Vererbung unterbrochen",
            "Dateneigentümer",
        ],
        rows,
    ))
}

async fn changes(
    State(st): State<AppState>,
    Query(q): Query<ChangeQuery>,
) -> Result<Response, ApiError> {
    let (_, items) = insights::load_changes(&st, &q, 100_000).await?;
    let rows = items
        .iter()
        .map(|v| {
            vec![
                text(&v["detected_at"]),
                text(&v["hostname"]),
                text(&v["change_label"]),
                text(&v["path"]),
                text(&v["principal"]["name"]),
                text(&v["sid"]),
                text(&v["old_value"]),
                text(&v["new_value"]),
            ]
        })
        .collect();
    Ok(csv_response(
        "aenderungen",
        &[
            "Erkannt",
            "System",
            "Änderung",
            "Objekt",
            "Prinzipal",
            "SID",
            "Vorher",
            "Nachher",
        ],
        rows,
    ))
}

/// Zugriffsbericht eines Benutzers bzw. einer Gruppe (direkt und über Gruppen).
async fn principal(
    State(st): State<AppState>,
    Path(sid): Path<String>,
) -> Result<Response, ApiError> {
    let sid = sid.trim_end_matches(".csv").to_string();
    let d = api::principal_detail(State(st), Path(sid.clone())).await?.0;
    let mut rows = Vec::new();
    for (key, how) in [
        ("direct_access", "direkt"),
        ("indirect_access", "über Gruppe"),
    ] {
        for a in d[key].as_array().into_iter().flatten() {
            rows.push(vec![
                text(&a["hostname"]),
                if a["kind"] == "share" {
                    "Freigabe"
                } else {
                    "Ordner"
                }
                .into(),
                text(&a["path"]),
                if a["ace_type"] == "deny" {
                    "Verweigern"
                } else {
                    "Zulassen"
                }
                .into(),
                text(&a["rights_label"]),
                how.into(),
                text(&a["via"]["name"]),
            ]);
        }
    }
    let name = d["principal"]["name"]
        .as_str()
        .unwrap_or(&sid)
        .replace(['\\', '/', ' '], "_");
    Ok(csv_response(
        &format!("zugriffe-{name}"),
        &[
            "System",
            "Art",
            "Pfad",
            "Zugriff",
            "Rechte",
            "Herkunft",
            "Über Gruppe",
        ],
        rows,
    ))
}
