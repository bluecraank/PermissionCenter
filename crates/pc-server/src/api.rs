//! REST-API (`/api/v1/...`) für Clients und Web-Oberfläche.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_postgres::types::ToSql;
use tokio_postgres::GenericClient;
use tracing::{info, warn};

use crate::analysis::{self, Severity, RULES};
use crate::config::ServerConfig;
use crate::db::{self, count, query_json, query_one_json, Db};
use crate::directory::Directory;
use crate::{ad, assist, ingest, releases};
use pc_common::rights::Rights;
use pc_common::{wellknown, AdSnapshot, ScanReport, UploadResponse};

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub cfg: Arc<ServerConfig>,
    pub ad_lock: Arc<tokio::sync::Mutex<()>>,
}

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn not_found(what: &str) -> Self {
        Self(StatusCode::NOT_FOUND, format!("{what} nicht gefunden"))
    }
    fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

impl From<tokio_postgres::Error> for ApiError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Datenbankfehler: {e}"),
        )
    }
}

impl From<deadpool_postgres::PoolError> for ApiError {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Datenbank nicht verfügbar: {e}"),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.0.is_server_error() {
            warn!("API-Fehler: {}", self.1);
        }
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult<T = Value> = Result<Json<T>, ApiError>;

/// Befunde ohne akzeptierte Ausnahme (Audit-Assist); nur diese zählen in Bewertung und Statistik.
const NOT_ACCEPTED: &str = "NOT EXISTS (SELECT 1 FROM finding_states fs WHERE fs.fingerprint = findings.fingerprint AND fs.status = 'accepted')";

const SEV_ORDER: &str =
    "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END";

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/settings", get(settings))
        .route("/api/v1/reports", post(upload_report))
        .route("/api/v1/dashboard", get(dashboard))
        .route("/api/v1/systems", get(systems))
        .route(
            "/api/v1/systems/{id}",
            get(system_detail).delete(system_delete),
        )
        .route("/api/v1/systems/{id}/folders", get(folder_children))
        .route(
            "/api/v1/systems/{id}/folders/{local_id}",
            get(folder_detail),
        )
        .route("/api/v1/systems/{id}/shares", get(system_shares))
        .route("/api/v1/systems/{id}/scans", get(system_scans))
        .route("/api/v1/findings", get(findings))
        .route("/api/v1/recommendations", get(recommendations))
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/rules", get(rules))
        .route("/api/v1/assist", get(assist_overview))
        .route(
            "/api/v1/assist/{fingerprint}",
            get(assist_detail).post(assist_update),
        )
        .route("/api/v1/principals", get(principals))
        .route("/api/v1/principals/{sid}", get(principal_detail))
        .route("/api/v1/ad/summary", get(ad_summary))
        .route("/api/v1/ad/users", get(ad_users))
        .route("/api/v1/ad/groups", get(ad_groups))
        .route("/api/v1/ad/sync", post(ad_sync))
        .route("/api/v1/ad/import", post(ad_import))
        .route("/api/v1/analyze", post(analyze))
        .route("/api/v1/graph", get(graph))
        .route("/api/v1/client/latest", get(client_latest))
        .route(
            "/api/v1/client/releases",
            get(client_releases).post(client_publish),
        )
        .route(
            "/api/v1/client/releases/{version}/download",
            get(client_download),
        )
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Allgemein

async fn health(State(st): State<AppState>) -> ApiResult {
    let db_ok = match st.db.get().await {
        Ok(c) => c.query_one("SELECT 1", &[]).await.is_ok(),
        Err(_) => false,
    };
    Ok(Json(
        json!({ "status": if db_ok { "ok" } else { "degraded" }, "database": db_ok, "version": env!("CARGO_PKG_VERSION") }),
    ))
}

async fn auth_status(State(st): State<AppState>) -> ApiResult {
    Ok(Json(json!({
        "mode": st.cfg.auth.mode,
        "login_required": false,
        "user": null,
        "note": "Login ist vorbereitet (AD/LDAP), aber laut Aufgabenstellung noch nicht aktiviert."
    })))
}

async fn settings(State(st): State<AppState>) -> ApiResult {
    let c = &st.cfg;
    // Passwort aus der Verbindungs-URL nicht ausgeben
    let db_url = match c.database_url.split_once('@') {
        Some((cred, host)) => format!(
            "{}:***@{host}",
            cred.rsplit_once(':').map(|x| x.0).unwrap_or(cred)
        ),
        None => c.database_url.clone(),
    };
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "listen": c.listen,
        "database": db_url,
        "upload_token_required": !c.api_tokens.is_empty(),
        "auth_mode": c.auth.mode,
        "ldap": {
            "configured": c.ldap.is_configured(),
            "url": c.ldap.url,
            "base_dn": c.ldap.base_dn,
            "bind_dn": c.ldap.bind_dn,
            "sync_interval_minutes": c.ldap.sync_interval_minutes,
        },
        "analysis": c.analysis,
    })))
}

// ---------------------------------------------------------------------------
// Client-Upload

async fn upload_report(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<UploadResponse> {
    check_token(&st, &headers)?;
    let report: ScanReport = serde_json::from_slice(&body)
        .map_err(|e| ApiError::bad_request(format!("Report ungültig: {e}")))?;
    let mut client = st.db.get().await?;
    let tx = client.transaction().await?;
    let res = ingest::ingest(&tx, &report).await?;
    if !res.duplicate {
        analysis::run(&tx, &st.cfg.analysis).await?;
    }
    let findings = count(
        &*tx,
        "SELECT COUNT(*) FROM findings WHERE system_id = $1",
        &[&res.system_id],
    )
    .await?;
    tx.commit().await?;
    info!(
        "Report von {} empfangen (Scan {}{}), {findings} Befunde",
        report.host.hostname,
        report.scan_id,
        if res.duplicate {
            ", bereits bekannt"
        } else {
            ""
        }
    );
    Ok(Json(UploadResponse {
        accepted: true,
        system_id: res.system_id,
        scan_id: report.scan_id,
        findings: findings as u64,
        message: res
            .duplicate
            .then(|| "Scan war bereits vorhanden".to_string()),
    }))
}

/// Prüft den Client-Token (Header `X-Api-Key`), sofern Tokens konfiguriert sind.
fn check_token(st: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    if st.cfg.api_tokens.is_empty() {
        return Ok(());
    }
    let token = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if st.cfg.api_tokens.iter().any(|t| t == token) {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "Ungültiges oder fehlendes API-Token".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Client-Updates (OTA)

async fn client_latest(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    check_token(&st, &headers)?;
    let dir = st.cfg.client_releases_dir.clone();
    match tokio::task::spawn_blocking(move || releases::latest(&dir))
        .await
        .map_err(|e| anyhow::anyhow!(e))??
    {
        Some(r) => Ok(Json(r).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn client_download(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(version): Path<String>,
) -> Result<Response, ApiError> {
    check_token(&st, &headers)?;
    let path = releases::exe_path(&st.cfg.client_releases_dir, &version)
        .ok_or_else(|| ApiError::not_found("Release"))?;
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/octet-stream".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"pc-client-{version}.exe\""),
            ),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Deserialize)]
struct PublishQuery {
    version: String,
    signature: Option<String>,
    notes: Option<String>,
}

/// Veröffentlicht ein Release per API (z. B. aus einer CI-Pipeline). Erfordert konfigurierte Tokens.
async fn client_publish(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PublishQuery>,
    body: Bytes,
) -> ApiResult<pc_common::release::ClientRelease> {
    if st.cfg.api_tokens.is_empty() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "Veröffentlichen per API nur mit konfiguriertem api_token möglich – alternativ `pc-server publish-client`".into(),
        ));
    }
    check_token(&st, &headers)?;
    let cfg = st.cfg.clone();
    let r = tokio::task::spawn_blocking(move || {
        releases::publish(
            &cfg.client_releases_dir,
            &q.version,
            &body,
            q.signature,
            q.notes,
            cfg.client_update_public_key.as_deref(),
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?
    .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    info!("Client-Release {} veröffentlicht", r.version);
    Ok(Json(r))
}

/// Übersicht für die Oberfläche: Releases und Client-Versionen der Systeme.
async fn client_releases(State(st): State<AppState>) -> ApiResult {
    let dir = st.cfg.client_releases_dir.clone();
    let list = tokio::task::spawn_blocking(move || releases::list(&dir))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    let c = st.db.get().await?;
    let latest = list.first().map(|r| r.version.clone());
    let systems: Vec<Value> = query_json(
        &**c,
        "SELECT id, hostname, client_version, last_seen FROM systems ORDER BY lower(hostname)",
        &[],
    )
    .await?
    .into_iter()
    .map(|mut v| {
        let cur = v["client_version"].as_str().unwrap_or("0").to_string();
        v["outdated"] = json!(latest.as_deref().is_some_and(
            |l| pc_common::release::compare_versions(&cur, l) == std::cmp::Ordering::Less
        ));
        v
    })
    .collect();
    Ok(Json(json!({
        "releases": list,
        "latest": latest,
        "signature_required": st.cfg.client_update_public_key.is_some(),
        "public_key": st.cfg.client_update_public_key,
        "systems": systems,
    })))
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen

async fn severity_counts(
    c: &impl GenericClient,
    filter: &str,
    params: &[&(dyn ToSql + Sync)],
) -> anyhow::Result<Value> {
    let mut m = serde_json::Map::new();
    for s in ["critical", "high", "medium", "low", "info"] {
        m.insert(s.into(), json!(0));
    }
    let sql = format!(
        "SELECT severity, COUNT(*) FROM findings WHERE {NOT_ACCEPTED} AND ({filter}) GROUP BY severity"
    );
    for r in c.query(&sql, params).await? {
        m.insert(r.get::<_, String>(0), json!(r.get::<_, i64>(1)));
    }
    Ok(Value::Object(m))
}

async fn score_for(
    c: &impl GenericClient,
    filter: &str,
    params: &[&(dyn ToSql + Sync)],
) -> anyhow::Result<analysis::Score> {
    let sql =
        format!("SELECT severity, affected FROM findings WHERE {NOT_ACCEPTED} AND ({filter})");
    let items: Vec<(Severity, i64)> = c
        .query(&sql, params)
        .await?
        .iter()
        .map(|r| (Severity::parse(r.get(0)), r.get(1)))
        .collect();
    Ok(analysis::score(items))
}

async fn system_summaries(c: &impl GenericClient, only: Option<i64>) -> anyhow::Result<Vec<Value>> {
    let mut rows = query_json(
        c,
        "SELECT y.id, y.hostname, y.domain, y.os_name, y.os_version, y.os_build, y.is_dc, y.client_version, y.first_seen, y.last_seen,
                s.finished_at AS last_scan_at, s.folders_scanned, s.folders_reported, s.folders_excluded, s.errors,
                s.orphaned_aces, s.duration_ms, s.explicit_folders, s.protected_folders, s.report_mode,
                (SELECT COUNT(*) FROM shares x WHERE x.system_id = y.id AND NOT x.is_special AND (x.share_type & 255) = 0) AS shares
         FROM systems y LEFT JOIN scans s ON s.id = y.last_scan_id
         WHERE $1::bigint IS NULL OR y.id = $1
         ORDER BY lower(y.hostname)",
        &[&only],
    )
    .await?;
    for v in rows.iter_mut() {
        let id = v["id"].as_i64().unwrap_or_default();
        v["score"] = json!(score_for(c, "system_id = $1", &[&id]).await?);
        v["findings"] = severity_counts(c, "system_id = $1", &[&id]).await?;
    }
    Ok(rows)
}

async fn ad_info(c: &impl GenericClient) -> anyhow::Result<Value> {
    let users = count(
        c,
        "SELECT COUNT(*) FROM ad_users WHERE NOT is_computer",
        &[],
    )
    .await?;
    let computers = count(c, "SELECT COUNT(*) FROM ad_users WHERE is_computer", &[]).await?;
    let groups = count(c, "SELECT COUNT(*) FROM ad_groups", &[]).await?;
    Ok(json!({
        "loaded": users + groups > 0,
        "domain": db::get_meta(c, "ad_domain").await?,
        "domain_sid": db::get_meta(c, "ad_domain_sid").await?,
        "synced_at": db::get_meta(c, "ad_synced_at").await?,
        "source": db::get_meta(c, "ad_source").await?,
        "users": users,
        "computers": computers,
        "groups": groups,
    }))
}

fn rights_label(r: &str) -> &'static str {
    Rights::parse(r).label_de()
}

// ---------------------------------------------------------------------------
// Dashboard und Systeme

async fn dashboard(State(st): State<AppState>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let systems = system_summaries(c, None).await?;
    let totals = query_one_json(
        c,
        "SELECT COALESCE(SUM(s.folders_scanned),0)::bigint AS folders_scanned,
                COALESCE(SUM(s.folders_reported),0)::bigint AS folders_reported,
                COALESCE(SUM(s.explicit_folders),0)::bigint AS explicit_folders,
                COALESCE(SUM(s.errors),0)::bigint AS scan_errors,
                (SELECT COUNT(*) FROM shares WHERE NOT is_special AND (share_type & 255) = 0) AS shares,
                (SELECT COUNT(*) FROM (SELECT sid FROM aces WHERE NOT inherited UNION SELECT sid FROM share_aces) x) AS principals
         FROM systems y JOIN scans s ON s.id = y.last_scan_id",
        &[],
    )
    .await?
    .unwrap_or(json!({}));
    let mut totals = totals;
    totals["systems"] = json!(systems.len());
    let top: Vec<Value> = query_json(
        c,
        &format!(
            "SELECT rule, severity, COUNT(*) AS findings, SUM(affected)::bigint AS affected FROM findings
             WHERE {NOT_ACCEPTED} GROUP BY rule, severity ORDER BY {SEV_ORDER}, SUM(affected) DESC"
        ),
        &[],
    )
    .await?
    .into_iter()
    .map(|mut v| {
        v["title"] = json!(analysis::rule(v["rule"].as_str().unwrap_or("")).map(|r| r.title));
        v
    })
    .collect();
    let recent = query_json(
        c,
        "SELECT y.id AS system_id, y.hostname, s.received_at, s.folders_scanned, s.errors FROM scans s
         JOIN systems y ON y.id = s.system_id ORDER BY s.id DESC LIMIT 8",
        &[],
    )
    .await?;
    Ok(Json(json!({
        "score": score_for(c, "TRUE", &[]).await?,
        "infrastructure_score": score_for(c, "system_id IS NOT NULL", &[]).await?,
        "ad_score": score_for(c, "system_id IS NULL", &[]).await?,
        "totals": totals,
        "findings": severity_counts(c, "TRUE", &[]).await?,
        "top_rules": top,
        "systems": systems,
        "recent_scans": recent,
        "ad": ad_info(c).await?,
        "analysis_at": db::get_meta(c, "analysis_at").await?,
    })))
}

async fn systems(State(st): State<AppState>) -> ApiResult {
    let c = st.db.get().await?;
    Ok(Json(json!(system_summaries(&**c, None).await?)))
}

async fn system_detail(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let Some(mut sys) = system_summaries(c, Some(id)).await?.into_iter().next() else {
        return Err(ApiError::not_found("System"));
    };
    sys["scan"] = query_one_json(
        c,
        "SELECT s.uuid, s.report_mode, s.started_at, s.finished_at, s.roots,
                (SELECT jsonb_agg(e) FROM (SELECT e FROM jsonb_array_elements(s.error_list) e LIMIT 200) x) AS errors
         FROM systems y JOIN scans s ON s.id = y.last_scan_id WHERE y.id = $1",
        &[&id],
    )
    .await?
    .unwrap_or(Value::Null);
    Ok(Json(sys))
}

async fn system_delete(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    let mut client = st.db.get().await?;
    let tx = client.transaction().await?;
    let n = tx
        .execute("DELETE FROM systems WHERE id = $1", &[&id])
        .await?;
    if n == 0 {
        return Err(ApiError::not_found("System"));
    }
    analysis::run(&tx, &st.cfg.analysis).await?;
    tx.commit().await?;
    Ok(Json(json!({ "deleted": true })))
}

async fn system_scans(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    let c = st.db.get().await?;
    let rows = query_json(
        &**c,
        "SELECT uuid, started_at, finished_at, received_at, report_mode, folders_scanned, folders_reported,
                folders_excluded, explicit_folders, protected_folders, errors, orphaned_aces, duration_ms
         FROM scans WHERE system_id = $1 ORDER BY id DESC LIMIT 100",
        &[&id],
    )
    .await?;
    Ok(Json(json!(rows)))
}

// ---------------------------------------------------------------------------
// Ordnerbaum

#[derive(Deserialize)]
struct FolderQuery {
    parent: Option<i64>,
}

const FOLDER_SELECT: &str = "SELECT f.local_id, f.parent_local_id, f.name, f.path, f.depth, f.owner_sid, f.protected, f.explicit,
        f.acl_source_local_id, f.subfolder_total, f.file_count, f.file_bytes, f.is_root, f.error,
        (SELECT COUNT(*) FROM folders c WHERE c.system_id = f.system_id AND c.parent_local_id = f.local_id) AS children,
        (SELECT COUNT(*) FROM aces a WHERE a.system_id = f.system_id AND a.folder_local_id = f.local_id AND NOT a.inherited) AS explicit_aces,
        (SELECT COUNT(*) FROM findings x WHERE x.system_id = f.system_id AND x.path = f.path) AS findings
     FROM folders f";

async fn folder_children(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<FolderQuery>,
) -> ApiResult {
    let c = st.db.get().await?;
    let rows = match q.parent {
        Some(p) => {
            query_json(
                &**c,
                &format!("{FOLDER_SELECT} WHERE f.system_id = $1 AND f.parent_local_id = $2 ORDER BY lower(f.name)"),
                &[&id, &p],
            )
            .await?
        }
        None => {
            query_json(
                &**c,
                &format!("{FOLDER_SELECT} WHERE f.system_id = $1 AND f.is_root ORDER BY f.path"),
                &[&id],
            )
            .await?
        }
    };
    Ok(Json(json!(rows)))
}

async fn ace_list(
    c: &impl GenericClient,
    dir: &Directory,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> anyhow::Result<Vec<Value>> {
    Ok(c.query(sql, params)
        .await?
        .iter()
        .map(|r| {
            let sid: String = r.get("sid");
            let rights: String = r.get("rights");
            let mask: i64 = r.get("mask");
            let flags: Option<i32> = r.try_get("flags").ok();
            json!({
                "principal": dir.view(&sid),
                "ace_type": r.get::<_, String>("ace_type"),
                "mask": format!("0x{:08X}", mask as u32),
                "rights": rights,
                "rights_label": rights_label(&rights),
                "inherited": r.try_get::<_, bool>("inherited").ok(),
                "flags": flags,
                "applies_to": flags.map(|f| applies_to(f as u8)),
            })
        })
        .collect())
}

fn applies_to(flags: u8) -> &'static str {
    let oi = flags & 0x1 != 0;
    let ci = flags & 0x2 != 0;
    let io = flags & 0x8 != 0;
    match (io, ci, oi) {
        (false, true, true) => "Dieser Ordner, Unterordner und Dateien",
        (false, true, false) => "Dieser Ordner und Unterordner",
        (false, false, true) => "Dieser Ordner und Dateien",
        (false, false, false) => "Nur dieser Ordner",
        (true, true, true) => "Nur Unterordner und Dateien",
        (true, true, false) => "Nur Unterordner",
        (true, false, true) => "Nur Dateien",
        (true, false, false) => "—",
    }
}

async fn folder_detail(
    State(st): State<AppState>,
    Path((id, local_id)): Path<(i64, i64)>,
) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let Some(mut folder) = query_one_json(
        c,
        &format!("{FOLDER_SELECT} WHERE f.system_id = $1 AND f.local_id = $2"),
        &[&id, &local_id],
    )
    .await?
    else {
        return Err(ApiError::not_found("Ordner"));
    };
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    folder["aces"] = json!(
        ace_list(
            c,
            &dir,
            "SELECT sid, ace_type, mask, rights, inherited, flags FROM aces
             WHERE system_id = $1 AND folder_local_id = $2 ORDER BY inherited, ace_type DESC",
            &[&id, &local_id],
        )
        .await?
    );
    if let Some(o) = folder["owner_sid"].as_str() {
        folder["owner"] = json!(dir.view(o));
    }
    // Brotkrumen über die Elternkette (rekursive CTE)
    folder["breadcrumbs"] = json!(
        query_json(
            c,
            "WITH RECURSIVE chain AS (
                SELECT local_id, parent_local_id, name, 0 AS lvl FROM folders WHERE system_id = $1 AND local_id = $2
                UNION ALL
                SELECT f.local_id, f.parent_local_id, f.name, chain.lvl + 1 FROM folders f
                JOIN chain ON f.system_id = $1 AND f.local_id = chain.parent_local_id WHERE chain.lvl < 200
             ) SELECT local_id, name FROM chain WHERE lvl > 0 ORDER BY lvl DESC",
            &[&id, &local_id],
        )
        .await?
    );
    if let Some(src) = folder["acl_source_local_id"].as_i64() {
        folder["acl_source_path"] = json!(c
            .query_opt(
                "SELECT path FROM folders WHERE system_id = $1 AND local_id = $2",
                &[&id, &src]
            )
            .await?
            .map(|r| r.get::<_, String>(0)));
    }
    let shares: Vec<String> = c
        .query(
            "SELECT name FROM shares WHERE system_id = $1 AND folder_local_id = $2",
            &[&id, &local_id],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    folder["shares"] = json!(shares);
    let path = folder["path"].as_str().unwrap_or_default().to_string();
    folder["finding_list"] = json!(
        query_json(
            c,
            "SELECT id, rule, severity, title FROM findings WHERE system_id = $1 AND path = $2",
            &[&id, &path],
        )
        .await?
    );
    Ok(Json(folder))
}

async fn system_shares(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let mut rows = query_json(
        c,
        "SELECT id, name, path, remark, share_type, is_special, has_sd, folder_local_id FROM shares
         WHERE system_id = $1 ORDER BY is_special, lower(name)",
        &[&id],
    )
    .await?;
    for v in rows.iter_mut() {
        let sid = v["id"].as_i64().unwrap_or_default();
        v["permissions"] = json!(
            ace_list(
                c,
                &dir,
                "SELECT sid, ace_type, mask, rights FROM share_aces WHERE share_id = $1",
                &[&sid]
            )
            .await?
        );
    }
    Ok(Json(json!(rows)))
}

// ---------------------------------------------------------------------------
// Befunde, Empfehlungen, Audit

#[derive(Deserialize)]
struct FindingQuery {
    system_id: Option<i64>,
    severity: Option<String>,
    rule: Option<String>,
    sid: Option<String>,
    scope: Option<String>,
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn findings(State(st): State<AppState>, Query(q): Query<FindingQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let like =
        q.q.as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{s}%"));
    let none = |s: &Option<String>| s.clone().filter(|v| !v.is_empty());
    let (sev, rule, sid) = (none(&q.severity), none(&q.rule), none(&q.sid));
    let scope = q.scope.clone().unwrap_or_default();
    let where_ = "($1::bigint IS NULL OR f.system_id = $1)
        AND ($2::text IS NULL OR f.severity = $2)
        AND ($3::text IS NULL OR f.rule = $3)
        AND ($4::text IS NULL OR f.sid = $4)
        AND ($5::text IS NULL OR f.title ILIKE $5 OR f.path ILIKE $5 OR f.detail ILIKE $5 OR y.hostname ILIKE $5)
        AND ($6 = '' OR ($6 = 'ad' AND f.system_id IS NULL) OR ($6 = 'system' AND f.system_id IS NOT NULL))";
    let params: [&(dyn ToSql + Sync); 6] = [&q.system_id, &sev, &rule, &sid, &like, &scope];
    let total = count(
        c,
        &format!("SELECT COUNT(*) FROM findings f LEFT JOIN systems y ON y.id = f.system_id WHERE {where_}"),
        &params,
    )
    .await?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let offset = q.offset.unwrap_or(0).max(0);
    let items: Vec<Value> = query_json(
        c,
        &format!(
            "SELECT f.id, f.system_id, y.hostname, f.rule, f.severity, f.title, f.detail, f.path, f.sid, f.affected, f.created_at,
                    f.fingerprint, fs.status AS assist_status
             FROM findings f LEFT JOIN systems y ON y.id = f.system_id
             LEFT JOIN finding_states fs ON fs.fingerprint = f.fingerprint WHERE {where_}
             ORDER BY {}, f.affected DESC, f.id LIMIT {limit} OFFSET {offset}",
            SEV_ORDER.replace("severity", "f.severity")
        ),
        &params,
    )
    .await?
    .into_iter()
    .map(|mut v| {
        let r = analysis::rule(v["rule"].as_str().unwrap_or(""));
        v["rule_title"] = json!(r.map(|x| x.title));
        v["recommendation"] = json!(r.map(|x| x.recommendation));
        v
    })
    .collect();
    Ok(Json(json!({ "total": total, "items": items })))
}

async fn rules() -> ApiResult {
    Ok(Json(json!(RULES)))
}

async fn recommendations(State(st): State<AppState>) -> ApiResult {
    let c = st.db.get().await?;
    let rows = c
        .query(
            &format!(
                "SELECT findings.rule, COUNT(*), SUM(findings.affected)::bigint,
                        COALESCE(array_agg(DISTINCT y.hostname) FILTER (WHERE y.hostname IS NOT NULL), '{{}}')
                 FROM findings LEFT JOIN systems y ON y.id = findings.system_id
                 WHERE {NOT_ACCEPTED} GROUP BY findings.rule"
            ),
            &[],
        )
        .await?;
    let mut items: Vec<(Severity, i64, Value)> = rows
        .iter()
        .filter_map(|r| {
            let rule = analysis::rule(r.get(0))?;
            if rule.severity == Severity::Info
                && !matches!(rule.id, "SCAN_ERRORS" | "AD_UNUSED_GROUP")
            {
                return None;
            }
            let n: i64 = r.get(1);
            let affected: i64 = r.get(2);
            let systems: Vec<String> = r.get(3);
            let effort = match affected {
                0..=5 => "gering",
                6..=50 => "mittel",
                _ => "hoch",
            };
            Some((
                rule.severity,
                affected,
                json!({
                    "rule": rule.id,
                    "severity": rule.severity,
                    "scope": rule.scope,
                    "title": rule.title,
                    "description": rule.description,
                    "recommendation": rule.recommendation,
                    "findings": n,
                    "affected": affected,
                    "systems": systems,
                    "effort": effort,
                }),
            ))
        })
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let list: Vec<Value> = items
        .into_iter()
        .enumerate()
        .map(|(i, (_, _, mut v))| {
            v["priority"] = json!(i + 1);
            v
        })
        .collect();
    Ok(Json(json!(list)))
}

async fn audit(State(st): State<AppState>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let systems = system_summaries(c, None).await?;
    let counts: HashMap<String, (i64, i64, i64)> = c
        .query(
            &format!(
                "SELECT rule, COUNT(*), SUM(affected)::bigint, COUNT(DISTINCT system_id) FROM findings
                 WHERE {NOT_ACCEPTED} GROUP BY rule"
            ),
            &[],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), (r.get(1), r.get(2), r.get(3))))
        .collect();
    let accepted: HashMap<String, i64> = c
        .query(
            "SELECT f.rule, COUNT(*) FROM findings f
             JOIN finding_states fs ON fs.fingerprint = f.fingerprint AND fs.status = 'accepted' GROUP BY f.rule",
            &[],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let checks: Vec<Value> = RULES
        .iter()
        .map(|r| {
            let (n, affected, sys) = counts.get(r.id).copied().unwrap_or((0, 0, 0));
            json!({
                "rule": r.id,
                "title": r.title,
                "description": r.description,
                "recommendation": r.recommendation,
                "severity": r.severity,
                "scope": r.scope,
                "passed": n == 0,
                "findings": n,
                "affected": affected,
                "systems_failed": sys,
                "systems_total": systems.len(),
                "accepted": accepted.get(r.id).copied().unwrap_or(0),
            })
        })
        .collect();
    Ok(Json(json!({
        "score": score_for(c, "TRUE", &[]).await?,
        "ad_score": score_for(c, "system_id IS NULL", &[]).await?,
        "ad": ad_info(c).await?,
        "systems": systems,
        "checks": checks,
        "analysis_at": db::get_meta(c, "analysis_at").await?,
    })))
}

async fn analyze(State(st): State<AppState>) -> ApiResult {
    let mut client = st.db.get().await?;
    let tx = client.transaction().await?;
    let n = analysis::run(&tx, &st.cfg.analysis).await?.findings;
    tx.commit().await?;
    Ok(Json(json!({ "findings": n })))
}

// ---------------------------------------------------------------------------
// Audit-Assist

#[derive(Deserialize)]
struct AssistQuery {
    system_id: Option<i64>,
    scope: Option<String>,
}

type Ts = chrono::DateTime<chrono::Utc>;

/// Bearbeitungsstand eines Befunds. Ein als behoben markierter Befund, der nach
/// neueren Scan- bzw. AD-Daten weiterhin besteht, gilt als nicht bestätigt (`failed`).
fn assist_status(status: Option<&str>, updated: Option<Ts>, data_at: Option<Ts>) -> &'static str {
    match status {
        Some("accepted") => "accepted",
        Some("fixed") => match (updated, data_at) {
            (Some(u), Some(d)) if d > u => "failed",
            _ => "pending",
        },
        _ => "open",
    }
}

fn parse_ts(s: Option<&str>) -> Option<Ts> {
    s.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc))
}

const ASSIST_SELECT: &str =
    "SELECT f.id, f.fingerprint, f.system_id, y.hostname, f.rule, f.severity, f.title, f.detail,
            f.path, f.sid, f.affected, fs.status, fs.note, fs.updated_at, s.received_at AS data_at
     FROM findings f
     LEFT JOIN systems y ON y.id = f.system_id
     LEFT JOIN scans s ON s.id = y.last_scan_id
     LEFT JOIN finding_states fs ON fs.fingerprint = f.fingerprint";

/// Ergänzt Regeltitel und Bearbeitungsstand. AD-Befunde werden am letzten AD-Abgleich gemessen.
fn assist_item(v: &mut Value, ad_at: Option<Ts>) {
    let data_at = if v["system_id"].is_null() {
        ad_at
    } else {
        parse_ts(v["data_at"].as_str())
    };
    let status = assist_status(
        v["status"].as_str(),
        parse_ts(v["updated_at"].as_str()),
        data_at,
    );
    let r = analysis::rule(v["rule"].as_str().unwrap_or(""));
    v["rule_title"] = json!(r.map(|x| x.title));
    v["assist_status"] = json!(status);
    v["data_at"] = json!(data_at);
}

async fn assist_overview(State(st): State<AppState>, Query(q): Query<AssistQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let scope = q.scope.clone().unwrap_or_default();
    let ad_at = parse_ts(db::get_meta(c, "ad_synced_at").await?.as_deref());
    let mut items = query_json(
        c,
        &format!(
            "{ASSIST_SELECT}
             WHERE f.fingerprint IS NOT NULL AND ($1::bigint IS NULL OR f.system_id = $1)
               AND ($2 = '' OR ($2 = 'ad' AND f.system_id IS NULL) OR ($2 = 'system' AND f.system_id IS NOT NULL))
             ORDER BY {}, f.affected DESC, f.id LIMIT 5000",
            SEV_ORDER.replace("severity", "f.severity")
        ),
        &[&q.system_id, &scope],
    )
    .await?;
    let mut summary: HashMap<&str, i64> = ["open", "failed", "pending", "accepted"]
        .into_iter()
        .map(|k| (k, 0))
        .collect();
    for v in items.iter_mut() {
        assist_item(v, ad_at);
        if let Some(n) = summary.get_mut(v["assist_status"].as_str().unwrap_or("open")) {
            *n += 1;
        }
    }
    let resolved = query_json(
        c,
        "SELECT fs.fingerprint, fs.rule, fs.title, fs.note, fs.system_id, y.hostname, fs.updated_at, fs.resolved_at
         FROM finding_states fs LEFT JOIN systems y ON y.id = fs.system_id
         WHERE fs.status = 'resolved' AND ($1::bigint IS NULL OR fs.system_id = $1)
         ORDER BY fs.resolved_at DESC LIMIT 100",
        &[&q.system_id],
    )
    .await?;
    let resolved_total = count(
        c,
        "SELECT COUNT(*) FROM finding_states WHERE status = 'resolved' AND ($1::bigint IS NULL OR system_id = $1)",
        &[&q.system_id],
    )
    .await?;
    let mut summary = json!(summary);
    summary["resolved"] = json!(resolved_total);
    Ok(Json(json!({
        "summary": summary,
        "items": items,
        "resolved": resolved,
        "ldap_configured": st.cfg.ldap.is_configured(),
        "analysis_at": db::get_meta(c, "analysis_at").await?,
    })))
}

async fn load_assist_item(c: &impl GenericClient, fingerprint: &str) -> Result<Value, ApiError> {
    let ad_at = parse_ts(db::get_meta(c, "ad_synced_at").await?.as_deref());
    let mut v = query_one_json(
        c,
        &format!("{ASSIST_SELECT} WHERE f.fingerprint = $1 LIMIT 1"),
        &[&fingerprint],
    )
    .await?
    .ok_or_else(|| ApiError::not_found("Befund (evtl. bereits behoben)"))?;
    assist_item(&mut v, ad_at);
    Ok(v)
}

async fn assist_detail(State(st): State<AppState>, Path(fingerprint): Path<String>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let v = load_assist_item(c, &fingerprint).await?;
    let s = |k: &str| v[k].as_str().map(str::to_string);
    let f = assist::FindingRef {
        system_id: v["system_id"].as_i64(),
        hostname: s("hostname"),
        rule: s("rule").unwrap_or_default(),
        title: s("title").unwrap_or_default(),
        path: s("path"),
        sid: s("sid"),
    };
    let guide = assist::guide(c, &f, &st.cfg.analysis).await?;
    Ok(Json(json!({
        "finding": v,
        "rule": analysis::rule(&f.rule),
        "guide": guide,
    })))
}

#[derive(Deserialize)]
struct AssistUpdate {
    /// `fixed`, `accepted` oder `open`
    status: String,
    note: Option<String>,
}

async fn assist_update(
    State(st): State<AppState>,
    Path(fingerprint): Path<String>,
    Json(body): Json<AssistUpdate>,
) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let note = body
        .note
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    match body.status.as_str() {
        "open" => {
            c.execute(
                "DELETE FROM finding_states WHERE fingerprint = $1",
                &[&fingerprint],
            )
            .await?;
        }
        "fixed" | "accepted" => {
            if body.status == "accepted" && note.is_none() {
                return Err(ApiError::bad_request(
                    "Für eine Ausnahme ist eine Begründung erforderlich",
                ));
            }
            let v = load_assist_item(c, &fingerprint).await?;
            c.execute(
                "INSERT INTO finding_states (fingerprint, rule, system_id, title, status, note, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, now())
                 ON CONFLICT (fingerprint) DO UPDATE SET status = excluded.status, note = excluded.note,
                     title = excluded.title, updated_at = excluded.updated_at, resolved_at = NULL",
                &[
                    &fingerprint,
                    &v["rule"].as_str(),
                    &v["system_id"].as_i64(),
                    &v["title"].as_str(),
                    &body.status,
                    &note,
                ],
            )
            .await?;
            info!(
                "Audit-Assist: „{}“ als {} markiert",
                v["title"].as_str().unwrap_or(""),
                body.status
            );
        }
        other => {
            return Err(ApiError::bad_request(format!(
                "Unbekannter Status '{other}'"
            )))
        }
    }
    let v = load_assist_item(c, &fingerprint)
        .await
        .unwrap_or_else(|_| json!({ "assist_status": "open" }));
    Ok(Json(v))
}

#[cfg(test)]
mod assist_tests {
    use super::*;

    #[test]
    fn status_verification() {
        let t0 = chrono::Utc::now();
        let t1 = t0 + chrono::Duration::minutes(5);
        assert_eq!(assist_status(None, None, Some(t0)), "open");
        assert_eq!(
            assist_status(Some("accepted"), Some(t0), Some(t1)),
            "accepted"
        );
        assert_eq!(assist_status(Some("fixed"), Some(t1), Some(t0)), "pending");
        assert_eq!(assist_status(Some("fixed"), Some(t0), Some(t1)), "failed");
        assert_eq!(assist_status(Some("fixed"), Some(t0), None), "pending");
    }
}

// ---------------------------------------------------------------------------
// Prinzipale (Benutzer/Gruppen) und Zusammenhänge

#[derive(Deserialize)]
struct PrincipalQuery {
    q: Option<String>,
    kind: Option<String>,
    status: Option<String>,
    limit: Option<usize>,
}

async fn principals(State(st): State<AppState>, Query(q): Query<PrincipalQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let mut usage: HashMap<String, (i64, i64, i64)> = HashMap::new();
    for r in c
        .query(
            "SELECT sid, COUNT(*), COUNT(DISTINCT system_id) FROM aces WHERE NOT inherited GROUP BY sid",
            &[],
        )
        .await?
    {
        usage.insert(r.get(0), (r.get(1), r.get(2), 0));
    }
    for r in c
        .query("SELECT sid, COUNT(*) FROM share_aces GROUP BY sid", &[])
        .await?
    {
        usage.entry(r.get(0)).or_default().2 = r.get(1);
    }
    let mut sids: HashSet<String> = usage.keys().cloned().collect();
    sids.extend(dir.users.keys().cloned());
    sids.extend(dir.groups.keys().cloned());
    let needle =
        q.q.as_deref()
            .map(str::to_lowercase)
            .filter(|s| !s.is_empty());
    let mut out: Vec<Value> = sids
        .into_iter()
        .map(|sid| (dir.view(&sid), usage.get(&sid).copied().unwrap_or_default()))
        .filter(|(v, _)| {
            needle.as_ref().is_none_or(|n| {
                v.name.to_lowercase().contains(n)
                    || v.sid.to_lowercase().contains(n)
                    || v.description
                        .as_deref()
                        .is_some_and(|d| d.to_lowercase().contains(n))
            })
        })
        .filter(|(v, _)| {
            q.kind
                .as_deref()
                .is_none_or(|k| k.is_empty() || v.kind == k)
        })
        .filter(|(v, _)| {
            q.status
                .as_deref()
                .is_none_or(|s| s.is_empty() || v.status == s)
        })
        .map(|(v, (aces, systems, share_aces))| {
            let mut j = json!(v);
            j["explicit_aces"] = json!(aces);
            j["systems"] = json!(systems);
            j["share_aces"] = json!(share_aces);
            j
        })
        .collect();
    out.sort_by(|a, b| {
        b["explicit_aces"]
            .as_i64()
            .cmp(&a["explicit_aces"].as_i64())
            .then(a["name"].as_str().cmp(&b["name"].as_str()))
    });
    let total = out.len();
    out.truncate(q.limit.unwrap_or(500).min(5000));
    Ok(Json(json!({ "total": total, "items": out })))
}

/// Ordner und Freigaben, auf denen `sid` explizit berechtigt ist.
async fn access_for(
    c: &impl GenericClient,
    dir: &Directory,
    sid: &str,
    via: Option<&str>,
) -> anyhow::Result<Vec<Value>> {
    let via_view = via.map(|v| dir.view(v));
    let mut out: Vec<Value> = query_json(
        c,
        "SELECT 'folder' AS kind, y.id AS system_id, y.hostname, f.local_id, f.path, NULL::text AS share,
                a.ace_type, a.rights
         FROM aces a JOIN folders f ON f.system_id = a.system_id AND f.local_id = a.folder_local_id
         JOIN systems y ON y.id = a.system_id
         WHERE a.sid = $1 AND NOT a.inherited
         UNION ALL
         SELECT 'share', y.id, y.hostname, s.folder_local_id, s.path, s.name, a.ace_type, a.rights
         FROM share_aces a JOIN shares s ON s.id = a.share_id JOIN systems y ON y.id = s.system_id
         WHERE a.sid = $1
         ORDER BY 3, 5 LIMIT 2000",
        &[&sid],
    )
    .await?;
    for v in out.iter_mut() {
        v["rights_label"] = json!(rights_label(v["rights"].as_str().unwrap_or("")));
        v["via"] = json!(via_view);
    }
    Ok(out)
}

async fn principal_detail(State(st): State<AppState>, Path(sid): Path<String>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let view = dir.view(&sid);
    let direct = access_for(c, &dir, &sid, None).await?;
    let groups = dir.transitive_groups(&sid);
    let mut indirect = Vec::new();
    for (g, _) in &groups {
        indirect.extend(access_for(c, &dir, g, Some(g)).await?);
    }
    // Breite Gruppen gelten implizit für jeden Benutzer
    if view.kind == "user" {
        for b in [
            wellknown::EVERYONE,
            wellknown::AUTHENTICATED_USERS,
            wellknown::BUILTIN_USERS,
        ] {
            indirect.extend(access_for(c, &dir, b, Some(b)).await?);
        }
    }
    let member_of: Vec<Value> = groups
        .iter()
        .map(|(g, path)| {
            json!({
                "group": dir.view(g),
                "direct": path.len() == 1,
                "path": path.iter().map(|p| dir.view(p).name).collect::<Vec<_>>(),
            })
        })
        .collect();
    let members: Vec<Value> = dir
        .members
        .get(&sid)
        .into_iter()
        .flatten()
        .map(|m| json!(dir.view(m)))
        .collect();
    let ad = dir
        .users
        .get(&sid)
        .map(|u| {
            json!({
                "sam": u.sam, "upn": u.upn, "display_name": u.display_name, "enabled": u.enabled,
                "last_logon": u.last_logon, "created": u.created, "is_computer": u.is_computer,
            })
        })
        .or_else(|| {
            dir.groups.get(&sid).map(|g| {
                json!({
                    "sam": g.sam, "description": g.description, "scope": g.scope, "is_security": g.is_security,
                    "transitive_users": dir.transitive_user_members(&sid).len(),
                })
            })
        });
    let findings = query_json(
        c,
        "SELECT f.id, f.rule, f.severity, f.title, f.path, y.hostname FROM findings f
         LEFT JOIN systems y ON y.id = f.system_id WHERE f.sid = $1",
        &[&sid],
    )
    .await?;
    Ok(Json(json!({
        "principal": view,
        "ad": ad,
        "direct_access": direct,
        "indirect_access": indirect,
        "member_of": member_of,
        "members": members,
        "findings": findings,
    })))
}

// ---------------------------------------------------------------------------
// Active Directory

async fn ad_summary(State(st): State<AppState>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let mut info = ad_info(c).await?;
    let users: Vec<_> = dir.users.values().filter(|u| !u.is_computer).collect();
    info["disabled_users"] = json!(users.iter().filter(|u| !u.enabled).count());
    info["inactive_users"] = json!(users.iter().filter(|u| dir.is_inactive(u)).count());
    info["empty_groups"] = json!(dir
        .groups
        .keys()
        .filter(|g| !dir.members.contains_key(*g))
        .count());
    info["ldap_configured"] = json!(st.cfg.ldap.is_configured());
    info["score"] = json!(score_for(c, "system_id IS NULL", &[]).await?);
    info["findings"] = severity_counts(c, "system_id IS NULL", &[]).await?;
    Ok(Json(info))
}

#[derive(Deserialize)]
struct AdListQuery {
    q: Option<String>,
    status: Option<String>,
}

async fn explicit_usage(c: &impl GenericClient) -> anyhow::Result<HashMap<String, i64>> {
    Ok(c.query(
        "SELECT sid, COUNT(*) FROM (SELECT sid FROM aces WHERE NOT inherited UNION ALL SELECT sid FROM share_aces) x GROUP BY sid",
        &[],
    )
    .await?
    .iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect())
}

async fn ad_users(State(st): State<AppState>, Query(q): Query<AdListQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let used = explicit_usage(c).await?;
    let needle =
        q.q.as_deref()
            .map(str::to_lowercase)
            .filter(|s| !s.is_empty());
    let mut out: Vec<Value> = dir
        .users
        .iter()
        .filter(|(_, u)| !u.is_computer)
        .map(|(sid, u)| {
            let v = dir.view(sid);
            json!({
                "sid": sid, "name": v.name, "sam": u.sam, "display_name": u.display_name, "upn": u.upn,
                "enabled": u.enabled, "status": v.status, "last_logon": u.last_logon, "created": u.created,
                "groups": dir.member_of.get(sid).map(|g| g.len()).unwrap_or(0),
                "explicit_aces": used.get(sid).copied().unwrap_or(0),
            })
        })
        .filter(|j| {
            needle.as_ref().is_none_or(|n| {
                j["name"].as_str().unwrap_or("").to_lowercase().contains(n)
                    || j["display_name"].as_str().unwrap_or("").to_lowercase().contains(n)
            })
        })
        .filter(|j| q.status.as_deref().is_none_or(|s| s.is_empty() || j["status"] == s))
        .collect();
    out.sort_by(|a, b| a["sam"].as_str().cmp(&b["sam"].as_str()));
    Ok(Json(json!(out)))
}

async fn ad_groups(State(st): State<AppState>, Query(q): Query<AdListQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let used = explicit_usage(c).await?;
    let flagged: HashMap<String, String> = c
        .query(
            "SELECT sid, rule FROM findings WHERE system_id IS NULL AND sid IS NOT NULL AND rule LIKE 'AD\\_%GROUP'",
            &[],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let needle =
        q.q.as_deref()
            .map(str::to_lowercase)
            .filter(|s| !s.is_empty());
    let mut out: Vec<Value> = dir
        .groups
        .iter()
        .map(|(sid, g)| {
            let v = dir.view(sid);
            let status = match flagged.get(sid).map(String::as_str) {
                Some("AD_EMPTY_GROUP") => "empty",
                Some("AD_ORPHANED_GROUP") => "orphaned",
                Some("AD_UNUSED_GROUP") => "unused",
                _ => "ok",
            };
            json!({
                "sid": sid, "name": v.name, "sam": g.sam, "description": g.description, "scope": g.scope,
                "is_security": g.is_security,
                "members": dir.members.get(sid).map(|m| m.len()).unwrap_or(0),
                "transitive_users": dir.transitive_user_members(sid).len(),
                "explicit_aces": used.get(sid).copied().unwrap_or(0),
                "status": status,
            })
        })
        .filter(|j| needle.as_ref().is_none_or(|n| j["name"].as_str().unwrap_or("").to_lowercase().contains(n)))
        .filter(|j| q.status.as_deref().is_none_or(|s| s.is_empty() || j["status"] == s))
        .collect();
    out.sort_by(|a, b| a["sam"].as_str().cmp(&b["sam"].as_str()));
    Ok(Json(json!(out)))
}

pub async fn run_ldap_sync(st: &AppState) -> Result<Value, ApiError> {
    if !st.cfg.ldap.is_configured() {
        return Err(ApiError::bad_request(
            "LDAP ist nicht konfiguriert ([ldap] url/base_dn in pc-server.toml bzw. PC_LDAP_*)",
        ));
    }
    let _guard = st.ad_lock.lock().await;
    let ldap = st.cfg.ldap.clone();
    let snap = tokio::task::spawn_blocking(move || ad::fetch_snapshot(&ldap))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    store_and_analyze(st, snap, "ldap").await
}

pub async fn store_and_analyze(
    st: &AppState,
    snap: AdSnapshot,
    source: &'static str,
) -> Result<Value, ApiError> {
    let mut client = st.db.get().await?;
    let tx = client.transaction().await?;
    let (u, g) = ad::store_snapshot(&tx, &snap, source).await?;
    let a = analysis::run(&tx, &st.cfg.analysis).await?;
    tx.commit().await?;
    let v = json!({ "users": u, "groups": g, "findings": a.findings, "source": source });
    info!("AD-Daten übernommen: {v}");
    Ok(v)
}

async fn ad_sync(State(st): State<AppState>) -> ApiResult {
    Ok(Json(run_ldap_sync(&st).await?))
}

async fn ad_import(State(st): State<AppState>, body: Bytes) -> ApiResult {
    // PowerShell schreibt gern ein UTF-8-BOM
    let body = body.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&body);
    let snap: AdSnapshot = serde_json::from_slice(body)
        .map_err(|e| ApiError::bad_request(format!("AD-Export ungültig: {e}")))?;
    Ok(Json(store_and_analyze(&st, snap, "import").await?))
}

// ---------------------------------------------------------------------------
// Graph für die Visualisierung

#[derive(Deserialize)]
struct GraphQuery {
    mode: Option<String>,
    system_id: Option<i64>,
    sid: Option<String>,
    limit: Option<usize>,
}

struct GraphBuilder {
    nodes: Vec<Value>,
    edges: Vec<Value>,
    ids: HashSet<String>,
}

impl GraphBuilder {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            ids: HashSet::new(),
        }
    }
    fn node(&mut self, id: String, label: &str, kind: &str, extra: Value) {
        if self.ids.insert(id.clone()) {
            let mut n = json!({ "id": id, "label": label, "type": kind });
            if let Value::Object(m) = extra {
                for (k, v) in m {
                    n[k] = v;
                }
            }
            self.nodes.push(n);
        }
    }
    fn edge(&mut self, source: &str, target: &str, kind: &str, label: Option<&str>) {
        let id = format!("{source}->{target}:{kind}");
        if self.ids.insert(id.clone()) {
            self.edges.push(json!({ "id": id, "source": source, "target": target, "type": kind, "label": label }));
        }
    }
    fn principal(&mut self, dir: &Directory, sid: &str) -> String {
        let v = dir.view(sid);
        let id = format!("p:{sid}");
        self.node(
            id.clone(),
            &v.name,
            &v.kind,
            json!({ "status": v.status, "sid": sid }),
        );
        id
    }
    fn finish(self) -> Value {
        json!({ "nodes": self.nodes, "edges": self.edges })
    }
}

/// Administrative Standardprinzipale blähen den Graphen auf, ohne Erkenntnis zu liefern.
fn skip_in_graph(sid: &str) -> bool {
    wellknown::is_administrative(sid) || sid == wellknown::CREATOR_OWNER
}

async fn graph(State(st): State<AppState>, Query(q): Query<GraphQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    let dir = Directory::load(c, st.cfg.analysis.inactive_days).await?;
    let mut g = GraphBuilder::new();
    let limit = q.limit.unwrap_or(60).clamp(5, 500);
    match q.mode.as_deref().unwrap_or("landscape") {
        "system" => {
            let id = q
                .system_id
                .ok_or_else(|| ApiError::bad_request("system_id fehlt"))?;
            let host: String = c
                .query_opt("SELECT hostname FROM systems WHERE id = $1", &[&id])
                .await?
                .ok_or_else(|| ApiError::not_found("System"))?
                .get(0);
            let sys = format!("s:{id}");
            g.node(sys.clone(), &host, "system", json!({ "system_id": id }));
            let rows = c
                .query(
                    "SELECT local_id, parent_local_id, name, path, protected, is_root, error IS NOT NULL FROM folders
                     WHERE system_id = $1 AND (is_root OR explicit OR protected)
                     ORDER BY depth, path LIMIT $2",
                    &[&id, &((limit * 3) as i64)],
                )
                .await?;
            let included: HashSet<i64> = rows.iter().map(|r| r.get(0)).collect();
            let parents: HashMap<i64, Option<i64>> = c
                .query(
                    "SELECT local_id, parent_local_id FROM folders WHERE system_id = $1",
                    &[&id],
                )
                .await?
                .iter()
                .map(|r| (r.get(0), r.get(1)))
                .collect();
            let mut aces: HashMap<i64, Vec<(String, String, String)>> = HashMap::new();
            for r in c
                .query(
                    "SELECT folder_local_id, sid, rights, ace_type FROM aces WHERE system_id = $1 AND NOT inherited",
                    &[&id],
                )
                .await?
            {
                aces.entry(r.get(0)).or_default().push((r.get(1), r.get(2), r.get(3)));
            }
            for r in &rows {
                let (lid, parent, name, path, protected, is_root, error): (
                    i64,
                    Option<i64>,
                    String,
                    String,
                    bool,
                    bool,
                    bool,
                ) = (
                    r.get(0),
                    r.get(1),
                    r.get(2),
                    r.get(3),
                    r.get(4),
                    r.get(5),
                    r.get(6),
                );
                let nid = format!("f:{id}:{lid}");
                g.node(
                    nid.clone(),
                    &name,
                    "folder",
                    json!({ "system_id": id, "local_id": lid, "path": path, "protected": protected, "error": error }),
                );
                // Nächsten enthaltenen Vorfahren suchen (Berechtigungsstrang)
                let mut anc = parent;
                while let Some(a) = anc {
                    if included.contains(&a) {
                        break;
                    }
                    anc = parents.get(&a).copied().flatten();
                }
                match (anc, is_root) {
                    (Some(a), false) => g.edge(&format!("f:{id}:{a}"), &nid, "contains", None),
                    _ => g.edge(&sys, &nid, "contains", None),
                }
                for (sid, rights, t) in aces.get(&lid).into_iter().flatten() {
                    if skip_in_graph(sid) {
                        continue;
                    }
                    let p = g.principal(&dir, sid);
                    let label = format!(
                        "{}{}",
                        if t == "deny" { "✕ " } else { "" },
                        rights_label(rights)
                    );
                    g.edge(
                        &p,
                        &nid,
                        if t == "deny" { "deny" } else { "grants" },
                        Some(&label),
                    );
                }
            }
            for r in c
                .query(
                    "SELECT name, folder_local_id FROM shares WHERE system_id = $1 AND NOT is_special AND (share_type & 255) = 0",
                    &[&id],
                )
                .await?
            {
                let (name, fl): (String, Option<i64>) = (r.get(0), r.get(1));
                let sh = format!("sh:{id}:{name}");
                g.node(sh.clone(), &format!("\\\\{host}\\{name}"), "share", json!({ "system_id": id }));
                g.edge(&sys, &sh, "shares", None);
                if let Some(l) = fl.filter(|l| included.contains(l)) {
                    g.edge(&sh, &format!("f:{id}:{l}"), "maps", None);
                }
            }
        }
        "principal" => {
            let sid = q
                .sid
                .clone()
                .ok_or_else(|| ApiError::bad_request("sid fehlt"))?;
            let root = g.principal(&dir, &sid);
            let mut targets: Vec<(String, String)> = vec![(sid.clone(), root.clone())];
            for (grp, path) in dir.transitive_groups(&sid) {
                let gid = g.principal(&dir, &grp);
                let parent = if path.len() >= 2 {
                    g.principal(&dir, &path[path.len() - 2])
                } else {
                    root.clone()
                };
                g.edge(&parent, &gid, "member_of", None);
                targets.push((grp, gid));
            }
            for m in dir.members.get(&sid).into_iter().flatten().take(limit) {
                let mid = g.principal(&dir, m);
                g.edge(&mid, &root, "member_of", None);
            }
            for (tsid, tid) in targets {
                for a in access_for(c, &dir, &tsid, None)
                    .await?
                    .into_iter()
                    .take(limit)
                {
                    let sys_id = a["system_id"].as_i64().unwrap_or(0);
                    let sys = format!("s:{sys_id}");
                    g.node(
                        sys.clone(),
                        a["hostname"].as_str().unwrap_or(""),
                        "system",
                        json!({ "system_id": sys_id }),
                    );
                    let (nid, label, kind) = if a["kind"] == "share" {
                        let share = a["share"].as_str().unwrap_or("");
                        (
                            format!("sh:{sys_id}:{share}"),
                            format!("\\\\{share}"),
                            "share",
                        )
                    } else {
                        (
                            format!("f:{sys_id}:{}", a["local_id"]),
                            a["path"].as_str().unwrap_or("").to_string(),
                            "folder",
                        )
                    };
                    g.node(nid.clone(), &label, kind, json!({ "system_id": sys_id, "local_id": a["local_id"], "path": a["path"] }));
                    g.edge(&sys, &nid, "contains", None);
                    let t = if a["ace_type"] == "deny" {
                        "deny"
                    } else {
                        "grants"
                    };
                    g.edge(&tid, &nid, t, a["rights_label"].as_str());
                }
            }
        }
        _ => {
            // Landschaft: Domäne → Systeme → Freigaben, wichtigste Prinzipale ↔ Systeme
            let ad = ad_info(c).await?;
            let ad_domain = ad["domain"].as_str().map(str::to_string);
            for r in c
                .query(
                    "SELECT id, hostname, domain, is_dc FROM systems ORDER BY lower(hostname)",
                    &[],
                )
                .await?
            {
                let (id, host, domain, is_dc): (i64, String, Option<String>, bool) =
                    (r.get(0), r.get(1), r.get(2), r.get(3));
                let sid = format!("s:{id}");
                let sc = score_for(c, "system_id = $1", &[&id]).await?;
                g.node(sid.clone(), &host, "system", json!({ "system_id": id, "is_dc": is_dc, "grade": sc.grade, "score": sc.score }));
                let dname = domain.unwrap_or_else(|| "Arbeitsgruppe".into());
                let dn = format!("d:{}", dname.to_lowercase());
                g.node(dn.clone(), &dname, "domain", json!({}));
                g.edge(&dn, &sid, "contains", None);
            }
            if let Some(d) = &ad_domain {
                g.node(format!("d:{}", d.to_lowercase()), d, "domain", json!({}));
            }
            for r in c
                .query("SELECT system_id, name FROM shares WHERE NOT is_special AND (share_type & 255) = 0", &[])
                .await?
            {
                let (sys, name): (i64, String) = (r.get(0), r.get(1));
                let sh = format!("sh:{sys}:{name}");
                g.node(sh.clone(), &name, "share", json!({ "system_id": sys }));
                g.edge(&format!("s:{sys}"), &sh, "shares", None);
            }
            let usage: Vec<(String, i64, i64)> = c
                .query(
                    "SELECT sid, system_id, COUNT(*) FROM aces WHERE NOT inherited GROUP BY sid, system_id ORDER BY 3 DESC",
                    &[],
                )
                .await?
                .iter()
                .map(|r| (r.get(0), r.get(1), r.get(2)))
                .collect();
            let mut totals: HashMap<&str, i64> = HashMap::new();
            for (sid, _, n) in &usage {
                if !skip_in_graph(sid) {
                    *totals.entry(sid).or_default() += n;
                }
            }
            let mut ranked: Vec<(&str, i64)> = totals.into_iter().collect();
            // Verwaiste Prinzipale immer zeigen, sonst nach Häufigkeit
            ranked.sort_by_key(|(s, n)| (!dir.is_orphaned(s), -n));
            let top: HashSet<&str> = ranked.iter().take(limit).map(|(s, _)| *s).collect();
            for (sid, sys, n) in &usage {
                if top.contains(sid.as_str()) {
                    let p = g.principal(&dir, sid);
                    g.edge(
                        &p,
                        &format!("s:{sys}"),
                        "grants",
                        Some(&format!("{n} Ordner")),
                    );
                }
            }
        }
    }
    Ok(Json(g.finish()))
}
