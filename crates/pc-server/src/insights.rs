//! API für Änderungsverlauf und Bewertungstrend.

use axum::extract::{Query, State};
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
