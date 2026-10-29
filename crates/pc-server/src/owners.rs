//! Dateneigentümer: fachlich Verantwortliche je Ordner. Ein Eintrag gilt für den
//! Ordner und alle Unterordner, bis ein tieferer Eintrag ihn ablöst.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_postgres::GenericClient;

use crate::api::{ApiError, ApiResult, AppState};
use crate::db::query_json;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/owners", get(list).put(upsert).delete(remove))
        .with_state(state)
}

#[derive(Debug, Clone)]
pub struct OwnerRow {
    pub system_id: i64,
    pub hostname: String,
    pub path: String,
    pub owner: String,
    pub email: Option<String>,
}

pub async fn load_all(c: &impl GenericClient) -> anyhow::Result<Vec<OwnerRow>> {
    Ok(c.query(
        "SELECT o.system_id, y.hostname, o.path, o.owner, o.email FROM data_owners o
             JOIN systems y ON y.id = o.system_id",
        &[],
    )
    .await?
    .iter()
    .map(|r| OwnerRow {
        system_id: r.get(0),
        hostname: r.get(1),
        path: r.get(2),
        owner: r.get(3),
        email: r.get(4),
    })
    .collect())
}

/// `path` liegt in `base` oder ist `base` (ohne Beachtung der Groß-/Kleinschreibung).
pub fn path_within(path: &str, base: &str) -> bool {
    let p = path.trim_end_matches('\\').to_lowercase();
    let b = base.trim_end_matches('\\').to_lowercase();
    p == b || p.starts_with(&format!("{b}\\"))
}

/// Nächster Eintrag auf dem Weg zur Wurzel (tiefster passender Pfad).
pub fn effective_row<'a>(rows: &'a [OwnerRow], system_id: i64, path: &str) -> Option<&'a OwnerRow> {
    rows.iter()
        .filter(|o| o.system_id == system_id && path_within(path, &o.path))
        .max_by_key(|o| o.path.len())
}

/// Wie [`effective_row`], über den Hostnamen und als Anzeigetext „Name <Mail>“.
pub fn effective(rows: &[OwnerRow], hostname: &str, path: &str) -> Option<String> {
    rows.iter()
        .filter(|o| o.hostname.eq_ignore_ascii_case(hostname) && path_within(path, &o.path))
        .max_by_key(|o| o.path.len())
        .map(|o| match &o.email {
            Some(e) => format!("{} <{e}>", o.owner),
            None => o.owner.clone(),
        })
}

#[derive(Deserialize)]
struct ListQuery {
    system_id: Option<i64>,
    /// Liefert nur den für diesen Pfad wirksamen Eintrag
    path: Option<String>,
}

async fn list(State(st): State<AppState>, Query(q): Query<ListQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let c = &**c;
    if let (Some(sys), Some(path)) = (q.system_id, q.path.as_deref()) {
        let rows = load_all(c).await?;
        let found = effective_row(&rows, sys, path).map(|o| {
            json!({
                "system_id": o.system_id,
                "path": o.path,
                "owner": o.owner,
                "email": o.email,
                "inherited": !o.path.trim_end_matches('\\').eq_ignore_ascii_case(path.trim_end_matches('\\')),
            })
        });
        return Ok(Json(json!(found)));
    }
    let rows = query_json(
        c,
        "SELECT o.system_id, y.hostname, o.path, o.owner, o.email, o.note, o.updated_at,
                (SELECT COUNT(*) FROM findings f WHERE f.system_id = o.system_id
                   AND (lower(f.path) = lower(o.path) OR starts_with(lower(f.path), lower(rtrim(o.path, '\\')) || '\\'))) AS findings
         FROM data_owners o JOIN systems y ON y.id = o.system_id
         WHERE $1::bigint IS NULL OR o.system_id = $1
         ORDER BY lower(y.hostname), lower(o.path)",
        &[&q.system_id],
    )
    .await?;
    Ok(Json(json!(rows)))
}

#[derive(Deserialize)]
struct OwnerInput {
    system_id: i64,
    path: String,
    owner: String,
    email: Option<String>,
    note: Option<String>,
}

async fn upsert(State(st): State<AppState>, Json(b): Json<OwnerInput>) -> ApiResult {
    let owner = b.owner.trim();
    let path = b.path.trim().replace('/', "\\");
    if owner.is_empty() || path.is_empty() {
        return Err(ApiError::bad_request(
            "Pfad und Dateneigentümer sind erforderlich",
        ));
    }
    let clean = |s: Option<String>| s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let c = st.db.get().await?;
    c.execute(
        "INSERT INTO data_owners (system_id, path, owner, email, note, updated_at)
         VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (system_id, lower(path)) DO UPDATE SET path = excluded.path, owner = excluded.owner,
             email = excluded.email, note = excluded.note, updated_at = excluded.updated_at",
        &[&b.system_id, &path, &owner, &clean(b.email), &clean(b.note)],
    )
    .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct RemoveQuery {
    system_id: i64,
    path: String,
}

async fn remove(State(st): State<AppState>, Query(q): Query<RemoveQuery>) -> ApiResult {
    let c = st.db.get().await?;
    let n = c
        .execute(
            "DELETE FROM data_owners WHERE system_id = $1 AND lower(path) = lower($2)",
            &[&q.system_id, &q.path],
        )
        .await?;
    Ok(Json(json!({ "deleted": n })))
}

/// Eintrag als JSON für andere Module.
pub fn to_json(o: &OwnerRow) -> Value {
    json!({ "path": o.path, "owner": o.owner, "email": o.email })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_owner() {
        let rows = vec![
            OwnerRow {
                system_id: 1,
                hostname: "FS01".into(),
                path: "D:\\Daten".into(),
                owner: "IT".into(),
                email: None,
            },
            OwnerRow {
                system_id: 1,
                hostname: "FS01".into(),
                path: "D:\\Daten\\Vertrieb".into(),
                owner: "Vertrieb".into(),
                email: Some("v@x.de".into()),
            },
        ];
        assert_eq!(
            effective(&rows, "fs01", "d:\\daten\\vertrieb\\angebote").as_deref(),
            Some("Vertrieb <v@x.de>")
        );
        assert_eq!(
            effective(&rows, "FS01", "D:\\Daten\\Technik").as_deref(),
            Some("IT")
        );
        assert_eq!(effective(&rows, "FS01", "D:\\DatenAlt"), None);
        assert_eq!(effective_row(&rows, 2, "D:\\Daten").map(|o| &o.owner), None);
    }
}
