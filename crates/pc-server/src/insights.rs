//! API für Änderungsverlauf und Bewertungstrend.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_postgres::types::ToSql;

use crate::api::{ApiResult, AppState};
use crate::db::{count, query_json};
use crate::directory::Directory;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/changes", get(changes))
        .route("/api/v1/history", get(history))
        .route("/api/v1/notify/test", post(notify_test))
        .route("/api/v1/systems/{id}/local-admins", get(local_admins))
        .route(
            "/api/v1/systems/{id}/scan-request",
            get(scan_request_status).post(scan_request),
        )
        .route("/api/v1/client/tasks", get(client_tasks))
        .route(
            "/api/v1/systems/{id}/folders/{local_id}/files",
            get(folder_files),
        )
        .route("/api/v1/notify/weekly", post(notify_weekly))
        .with_state(state)
}

pub const CHANGE_LABELS: &[(&str, &str)] = &[
    ("ace_added", "Berechtigung hinzugefügt"),
    ("ace_removed", "Berechtigung entfernt"),
    ("ace_changed", "Berechtigung geändert"),
    ("inheritance_disabled", "Vererbung unterbrochen"),
    ("inheritance_enabled", "Vererbung aktiviert"),
    ("owner_changed", "Besitzer geändert"),
    ("folder_removed", "Ordner mit eigenen Rechten entfernt"),
    ("share_added", "Freigabe hinzugefügt"),
    ("share_removed", "Freigabe entfernt"),
];

pub fn change_label(c: &str) -> &str {
    CHANGE_LABELS
        .iter()
        .find(|(k, _)| *k == c)
        .map(|x| x.1)
        .unwrap_or(c)
}

#[derive(Deserialize, Default)]
pub struct ChangeQuery {
    pub system_id: Option<i64>,
    pub sid: Option<String>,
    pub change: Option<String>,
    pub q: Option<String>,
    /// Zeitraum in Tagen (Standard 30)
    pub days: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

const CHANGE_WHERE: &str = "($1::bigint IS NULL OR c.system_id = $1)
    AND ($2::text IS NULL OR c.sid = $2)
    AND ($3::text IS NULL OR c.change = $3)
    AND ($4::text IS NULL OR c.path ILIKE $4 OR y.hostname ILIKE $4)
    AND c.detected_at >= now() - make_interval(days => $5::int)";

/// Lädt Änderungen inkl. Prinzipal-Namen (auch für den CSV-Export).
pub async fn load_changes(
    st: &AppState,
    q: &ChangeQuery,
    limit: i64,
) -> anyhow::Result<(i64, Vec<Value>)> {
    let c = st.db.get().await?;
    let c = &**c;
    let some = |s: &Option<String>| s.clone().filter(|v| !v.is_empty());
    let like = some(&q.q).map(|s| format!("%{s}%"));
    let days = q.days.unwrap_or(30).clamp(1, 3650) as i32;
    let (sid, change) = (some(&q.sid), some(&q.change));
    let params: [&(dyn ToSql + Sync); 5] = [&q.system_id, &sid, &change, &like, &days];
    let total = count(
        c,
        &format!("SELECT COUNT(*) FROM changes c JOIN systems y ON y.id = c.system_id WHERE {CHANGE_WHERE}"),
        &params,
    )
    .await?;
    let offset = q.offset.unwrap_or(0).max(0);
    let mut items = query_json(
        c,
        &format!(
            "SELECT c.id, c.system_id, y.hostname, c.detected_at, c.object_kind, c.path, c.change, c.sid,
                    c.old_value, c.new_value
             FROM changes c JOIN systems y ON y.id = c.system_id WHERE {CHANGE_WHERE}
             ORDER BY c.detected_at DESC, c.id LIMIT {limit} OFFSET {offset}"
        ),
        &params,
    )
    .await?;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    for v in items.iter_mut() {
        if let Some(sid) = v["sid"].as_str() {
            v["principal"] = json!(dir.view(sid));
        }
        if v["change"] == "owner_changed" {
            if let Some(o) = v["old_value"].as_str() {
                v["old_value"] = json!(dir.view(o).name);
            }
            if let Some(n) = v["new_value"].as_str() {
                v["new_value"] = json!(dir.view(n).name);
            }
        }
        let label = change_label(v["change"].as_str().unwrap_or(""));
        v["change_label"] = json!(label);
    }
    Ok((total, items))
}

async fn changes(State(st): State<AppState>, Query(q): Query<ChangeQuery>) -> ApiResult {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let (total, items) = load_changes(&st, &q, limit).await?;
    let c = st.db.get().await?;
    // Anzahl je Tag für das Diagramm
    let per_day = query_json(
        &**c,
        "SELECT to_char(date_trunc('day', detected_at), 'YYYY-MM-DD') AS day, COUNT(*) AS changes
         FROM changes WHERE ($1::bigint IS NULL OR system_id = $1)
           AND detected_at >= now() - make_interval(days => $2::int)
         GROUP BY 1 ORDER BY 1",
        &[&q.system_id, &(q.days.unwrap_or(30).clamp(1, 3650) as i32)],
    )
    .await?;
    let labels: serde_json::Map<String, Value> = CHANGE_LABELS
        .iter()
        .map(|(k, v)| (k.to_string(), json!(v)))
        .collect();
    Ok(Json(json!({
        "total": total,
        "items": items,
        "per_day": per_day,
        "labels": labels,
    })))
}

/// „Jetzt scannen“ anfordern – der Client-Dienst holt den Auftrag ab.
async fn scan_request(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    let c = st.db.get().await?;
    c.execute(
        "INSERT INTO scan_requests (system_id, requested_at) VALUES ($1, now())
         ON CONFLICT (system_id) DO UPDATE SET requested_at = now(), picked_at = NULL",
        &[&id],
    )
    .await?;
    scan_request_status(State(st.clone()), Path(id)).await
}

async fn scan_request_status(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    let c = st.db.get().await?;
    let v = crate::db::query_one_json(
        &**c,
        "SELECT r.requested_at, r.picked_at, s.received_at AS last_scan_received
         FROM systems y LEFT JOIN scan_requests r ON r.system_id = y.id
         LEFT JOIN scans s ON s.id = y.last_scan_id WHERE y.id = $1",
        &[&id],
    )
    .await?;
    Ok(Json(v.unwrap_or(Value::Null)))
}

#[derive(Deserialize)]
struct TaskQuery {
    hostname: String,
}

/// Abfrage des Client-Dienstes: liegt ein Scan-Auftrag vor?
async fn client_tasks(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TaskQuery>,
) -> ApiResult {
    crate::api::check_token(&st, &headers)?;
    let c = st.db.get().await?;
    let picked = c
        .query_opt(
            "UPDATE scan_requests r SET picked_at = now()
             FROM systems y WHERE y.id = r.system_id AND lower(y.hostname) = lower($1) AND r.picked_at IS NULL
             RETURNING r.requested_at",
            &[&q.hostname],
        )
        .await?;
    if picked.is_some() {
        tracing::info!("Scan-Auftrag für {} abgeholt", q.hostname);
    }
    Ok(Json(json!({ "scan": picked.is_some() })))
}

async fn local_admins(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let rows: Vec<Value> = c
        .query("SELECT sid FROM local_admins WHERE system_id = $1", &[&id])
        .await?
        .iter()
        .map(|r| {
            let sid: String = r.get(0);
            let mut members = Vec::new();
            if dir.groups.contains_key(&sid) {
                members = dir
                    .transitive_user_members(&sid)
                    .iter()
                    .map(|u| json!(dir.view(u)))
                    .collect();
            }
            json!({ "principal": dir.view(&sid), "members": members })
        })
        .collect();
    Ok(Json(json!(rows)))
}

async fn folder_files(
    State(st): State<AppState>,
    Path((id, local_id)): Path<(i64, i64)>,
) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let files = c
        .query(
            "SELECT file_id, path, protected, owner_sid FROM files
             WHERE system_id = $1 AND folder_local_id = $2 ORDER BY lower(path)",
            &[&id, &local_id],
        )
        .await?;
    let mut out = Vec::new();
    for f in &files {
        let file_id: i64 = f.get(0);
        let aces: Vec<Value> = c
            .query(
                "SELECT sid, ace_type, rights, inherited FROM file_aces
                 WHERE system_id = $1 AND file_id = $2 ORDER BY inherited, sid",
                &[&id, &file_id],
            )
            .await?
            .iter()
            .map(|a| {
                json!({
                    "principal": dir.view(a.get::<_, &str>(0)),
                    "ace_type": a.get::<_, String>(1),
                    "rights_label": pc_common::rights::Rights::parse(a.get(2)).label_de(),
                    "inherited": a.get::<_, bool>(3),
                })
            })
            .collect();
        let path: String = f.get(1);
        out.push(json!({
            "name": path.rsplit('\\').next().unwrap_or(&path),
            "path": path,
            "protected": f.get::<_, bool>(2),
            "owner": f.get::<_, Option<String>>(3).map(|o| dir.view(&o)),
            "aces": aces,
        }));
    }
    Ok(Json(json!(out)))
}

async fn notify_test(State(st): State<AppState>) -> ApiResult {
    if !st.cfg.notify.any_channel() {
        return Err(crate::api::ApiError::bad_request(
            "Keine Benachrichtigungskanäle konfiguriert (SMTP oder Webhooks)",
        ));
    }
    let note = crate::notify::Note {
        subject: "PermissionCenter: Testnachricht".into(),
        intro: "Die Benachrichtigungen sind richtig eingerichtet.".into(),
        lines: vec!["Neue kritische und hohe Befunde, Verschlechterungen der Note und der Wochenbericht kommen auf diesem Weg.".into()],
        link: Some("/settings".into()),
    };
    Ok(Json(json!(
        crate::notify::send(&st.cfg.notify, &note).await
    )))
}

async fn notify_weekly(State(st): State<AppState>) -> ApiResult {
    let note = crate::notify::weekly_note(&st).await?;
    let sent = if st.cfg.notify.any_channel() {
        crate::notify::send(&st.cfg.notify, &note).await
    } else {
        Vec::new()
    };
    Ok(Json(json!({ "note": note, "deliveries": sent })))
}

#[derive(Deserialize)]
struct HistoryQuery {
    system_id: Option<i64>,
    days: Option<i64>,
}

async fn history(State(st): State<AppState>, Query(q): Query<HistoryQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let days = q.days.unwrap_or(90).clamp(1, 3650) as i32;
    let rows = query_json(
        &**c,
        "SELECT to_char(day, 'YYYY-MM-DD') AS day, scope, system_id, score, grade, critical, high, medium, low, info
         FROM score_history
         WHERE day >= current_date - $2::int
           AND (($1::bigint IS NULL AND scope IN ('total', 'infra', 'ad'))
                OR ($1::bigint IS NOT NULL AND scope = 'system' AND system_id = $1))
         ORDER BY day, scope",
        &[&q.system_id, &days],
    )
    .await?;
    Ok(Json(json!(rows)))
}
