//! Zugriffsprüfung: „Wer hat Zugriff auf diesen Pfad?“ – mit Auflösung
//! verschachtelter Gruppen bis zum einzelnen Benutzer.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_postgres::GenericClient;

use crate::api::{ApiError, ApiResult, AppState};
use crate::directory::Directory;
use crate::export::csv_response;
use pc_common::rights::{classify, Rights};
use pc_common::wellknown;

/// Höchstzahl aufgelöster Benutzer in der Antwort.
const MAX_USERS: usize = 5000;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/access", get(access))
        .route("/api/v1/export/access.csv", get(access_csv))
        .with_state(state)
}

#[derive(Deserialize)]
pub struct AccessQuery {
    pub system_id: Option<i64>,
    pub path: String,
}

struct AceRow {
    sid: String,
    ace_type: String,
    mask: i64,
    flags: i32,
    inherited: bool,
}

/// Zuordnung eines UNC-Pfads (`\\host\freigabe\…`) zu System und lokalem Pfad.
async fn resolve_unc(
    c: &impl GenericClient,
    path: &str,
) -> anyhow::Result<Option<(i64, String, String)>> {
    let rest = path.trim_start_matches('\\');
    let mut parts = rest.splitn(3, '\\');
    let (Some(host), Some(share)) = (parts.next(), parts.next()) else {
        return Ok(None);
    };
    let tail = parts.next().unwrap_or("");
    let host_short = host.split('.').next().unwrap_or(host);
    let row = c
        .query_opt(
            "SELECT s.system_id, s.path, s.name FROM shares s JOIN systems y ON y.id = s.system_id
             WHERE lower(y.hostname) = lower($1) AND lower(s.name) = lower($2) LIMIT 1",
            &[&host_short, &share],
        )
        .await?;
    Ok(row.map(|r| {
        let base: String = r.get(1);
        let local = if tail.is_empty() {
            base
        } else {
            format!("{}\\{tail}", base.trim_end_matches('\\'))
        };
        (r.get(0), local, r.get(2))
    }))
}

pub async fn evaluate(st: &AppState, q: &AccessQuery) -> Result<Value, ApiError> {
    let c = st.db.get().await?;
    let c = &**c;
    let input = q.path.trim().replace('/', "\\");
    if input.is_empty() {
        return Err(ApiError::bad_request("Pfad angeben"));
    }
    let (system_id, path, via_share) = if input.starts_with("\\\\") {
        match resolve_unc(c, &input).await? {
            Some((s, p, share)) => (s, p, Some(share)),
            None => {
                return Err(ApiError::bad_request(
                    "Freigabe unbekannt – System und lokalen Pfad angeben oder zuerst scannen",
                ))
            }
        }
    } else {
        let s = q
            .system_id
            .ok_or_else(|| ApiError::bad_request("System auswählen oder UNC-Pfad angeben"))?;
        (s, input.clone(), None)
    };
    let path = if path.len() > 3 {
        path.trim_end_matches('\\').to_string()
    } else {
        path
    };

    let host: String = c
        .query_opt("SELECT hostname FROM systems WHERE id = $1", &[&system_id])
        .await?
        .ok_or_else(|| ApiError::not_found("System"))?
        .get(0);
    // Tiefster gemeldeter Ordner auf dem Weg (nicht gemeldete Ordner erben exakt)
    let folder = c
        .query_opt(
            "SELECT local_id, path, protected, acl_source_local_id FROM folders
             WHERE system_id = $1 AND (lower(path) = lower($2)
                   OR starts_with(lower($2), lower(rtrim(path, '\\')) || '\\'))
             ORDER BY length(path) DESC LIMIT 1",
            &[&system_id, &path],
        )
        .await?
        .ok_or_else(|| ApiError::not_found("Pfad im letzten Scan"))?;
    let (local_id, folder_path, protected, source): (i64, String, bool, Option<i64>) =
        (folder.get(0), folder.get(1), folder.get(2), folder.get(3));
    let exact = folder_path
        .trim_end_matches('\\')
        .eq_ignore_ascii_case(path.trim_end_matches('\\'));
    // Tiefe unterhalb des gemeldeten Ordners (für „nur nächste Ebene“)
    let extra_depth = if exact {
        0
    } else {
        path[folder_path.trim_end_matches('\\').len()..]
            .trim_matches('\\')
            .split('\\')
            .count()
    };
    let source_path: Option<String> = match source {
        Some(s) if s != local_id => c
            .query_opt(
                "SELECT path FROM folders WHERE system_id = $1 AND local_id = $2",
                &[&system_id, &s],
            )
            .await?
            .map(|r| r.get(0)),
        _ => None,
    };

    let aces: Vec<AceRow> = c
        .query(
            "SELECT sid, ace_type, mask, flags, inherited FROM aces
             WHERE system_id = $1 AND folder_local_id = $2 AND ace_type IN ('allow', 'deny')",
            &[&system_id, &local_id],
        )
        .await?
        .iter()
        .map(|r| AceRow {
            sid: r.get(0),
            ace_type: r.get(1),
            mask: r.get(2),
            flags: r.get(3),
            inherited: r.get(4),
        })
        .filter(|a| {
            if exact {
                a.flags & 0x8 == 0 // „nur Unterobjekte“ gilt nicht für den Ordner selbst
            } else {
                // Unterordner erhalten nur Container-vererbbare Einträge; NP nur eine Ebene tief
                a.flags & 0x2 != 0 && (a.flags & 0x4 == 0 || extra_depth == 1)
            }
        })
        .collect();

    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let local_admins: Vec<String> = c
        .query(
            "SELECT sid FROM local_admins WHERE system_id = $1",
            &[&system_id],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();

    // Benutzer → (Masken erlauben, Masken verweigern, über)
    let mut users: BTreeMap<String, (u32, u32, BTreeSet<String>, bool)> = BTreeMap::new();
    let mut everyone: Vec<Value> = Vec::new();
    let mut unresolved: Vec<Value> = Vec::new();
    let mut ace_out = Vec::new();
    for a in &aces {
        let p = dir.view(&a.sid);
        ace_out.push(json!({
            "principal": p,
            "ace_type": a.ace_type,
            "rights_label": classify(a.mask as u32).label_de(),
            "inherited": a.inherited,
        }));
        let allow = a.ace_type == "allow";
        let mut add = |user: &str, via: Option<&str>| {
            let e = users.entry(user.to_string()).or_default();
            if allow {
                e.0 |= a.mask as u32;
            } else {
                e.1 |= a.mask as u32;
            }
            match via {
                Some(v) => {
                    e.2.insert(v.to_string());
                }
                None => e.3 = true,
            }
        };
        if wellknown::is_broad_principal(&a.sid) {
            everyone.push(json!({ "principal": p, "ace_type": a.ace_type,
                "rights_label": classify(a.mask as u32).label_de() }));
        } else if dir.groups.contains_key(&a.sid) {
            for u in dir.transitive_user_members(&a.sid) {
                add(&u, Some(&p.name));
            }
        } else if a.sid == wellknown::BUILTIN_ADMINISTRATORS && !local_admins.is_empty() {
            for m in &local_admins {
                if dir.groups.contains_key(m) {
                    for u in dir.transitive_user_members(m) {
                        add(&u, Some(&p.name));
                    }
                } else {
                    add(m, Some(&p.name));
                }
            }
        } else if dir.is_user(&a.sid) {
            add(&a.sid, None);
        } else if !wellknown::is_well_known(&a.sid) || a.sid.starts_with("S-1-5-32-") {
            unresolved.push(json!({ "principal": p, "ace_type": a.ace_type,
                "rights_label": classify(a.mask as u32).label_de() }));
        }
    }
    let total_users = users.len();
    let user_list: Vec<Value> = users
        .into_iter()
        .take(MAX_USERS)
        .map(|(sid, (allow, deny, via, direct))| {
            let r: Rights = classify(allow);
            json!({
                "principal": dir.view(&sid),
                "rights_label": if allow == 0 { "–" } else { r.label_de() },
                "can_write": r.can_write(),
                "denied": deny != 0,
                "deny_label": (deny != 0).then(|| classify(deny).label_de()),
                "direct": direct,
                "via": via.into_iter().collect::<Vec<_>>(),
            })
        })
        .collect();

    // Freigaben, über die der Pfad erreichbar ist
    let mut shares = Vec::new();
    for r in c
        .query(
            "SELECT id, name, path, has_sd FROM shares WHERE system_id = $1 AND NOT is_special
               AND (lower(rtrim(path, '\\')) = lower(rtrim($2, '\\')) OR starts_with(lower($2), lower(rtrim(path, '\\')) || '\\'))
             ORDER BY length(path) DESC",
            &[&system_id, &path],
        )
        .await?
    {
        let (id, name, has_sd): (i64, String, bool) = (r.get(0), r.get(1), r.get(3));
        let perms: Vec<Value> = c
            .query(
                "SELECT sid, ace_type, mask FROM share_aces WHERE share_id = $1",
                &[&id],
            )
            .await?
            .iter()
            .map(|x| {
                json!({
                    "principal": dir.view(x.get::<_, &str>(0)),
                    "ace_type": x.get::<_, String>(1),
                    "rights_label": classify(x.get::<_, i64>(2) as u32).label_de(),
                })
            })
            .collect();
        shares.push(json!({
            "name": name,
            "unc": format!("\\\\{host}\\{name}"),
            "no_security": !has_sd,
            "permissions": perms,
        }));
    }

    let owners = crate::owners::load_all(c).await?;
    let owner = crate::owners::effective_row(&owners, system_id, &path).map(crate::owners::to_json);
    Ok(json!({
        "system_id": system_id,
        "hostname": host,
        "path": path,
        "via_share": via_share,
        "folder": {
            "local_id": local_id,
            "path": folder_path,
            "exact": exact,
            "protected": protected,
            "acl_source_path": source_path,
        },
        "owner": owner,
        "aces": ace_out,
        "everyone": everyone,
        "unresolved": unresolved,
        "users": user_list,
        "users_total": total_users,
        "shares": shares,
    }))
}

async fn access(State(st): State<AppState>, Query(q): Query<AccessQuery>) -> ApiResult {
    Ok(Json(evaluate(&st, &q).await?))
}

async fn access_csv(
    State(st): State<AppState>,
    Query(q): Query<AccessQuery>,
) -> Result<Response, ApiError> {
    let v = evaluate(&st, &q).await?;
    let t = |x: &Value| x.as_str().unwrap_or("").to_string();
    let mut rows = Vec::new();
    for e in v["everyone"].as_array().into_iter().flatten() {
        rows.push(vec![
            t(&e["principal"]["name"]),
            t(&e["principal"]["sid"]),
            "alle Benutzer".into(),
            t(&e["rights_label"]),
            String::new(),
            String::new(),
        ]);
    }
    for u in v["users"].as_array().into_iter().flatten() {
        rows.push(vec![
            t(&u["principal"]["name"]),
            t(&u["principal"]["sid"]),
            crate::export::status_de(u["principal"]["status"].as_str().unwrap_or("")).into(),
            t(&u["rights_label"]),
            u["deny_label"]
                .as_str()
                .map(|d| format!("Verweigern: {d}"))
                .unwrap_or_default(),
            u["direct"]
                .as_bool()
                .filter(|d| *d)
                .map(|_| "direkt".to_string())
                .into_iter()
                .chain(u["via"].as_array().into_iter().flatten().map(t))
                .collect::<Vec<_>>()
                .join(", "),
        ]);
    }
    Ok(csv_response(
        "zugriffspruefung",
        &[
            "Benutzer",
            "SID",
            "Status",
            "Rechte (NTFS)",
            "Verweigert",
            "Über",
        ],
        rows,
    ))
}
