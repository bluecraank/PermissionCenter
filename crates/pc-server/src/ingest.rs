//! Übernahme eines Client-Reports in die Server-Datenbank.

use std::collections::HashSet;

use anyhow::{bail, Result};
use chrono::Utc;
use futures_util::pin_mut;
use tokio_postgres::binary_copy::BinaryCopyInWriter;
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::Transaction;

use pc_common::{ScanReport, REPORT_SCHEMA_VERSION};

pub struct IngestResult {
    pub system_id: i64,
    pub duplicate: bool,
    /// Erkannte Änderungen gegenüber dem vorherigen Scan.
    pub changes: usize,
}

fn folder_name(path: &str) -> String {
    let t = path.trim_end_matches('\\');
    match t.rfind('\\') {
        Some(i) if i + 1 < t.len() => t[i + 1..].to_string(),
        _ => path.to_string(),
    }
}

/// Schreibt Zeilen per `COPY … FROM STDIN BINARY`.
async fn copy_rows(
    tx: &Transaction<'_>,
    sql: &str,
    types: &[Type],
    rows: Vec<Vec<Box<dyn ToSql + Sync + Send>>>,
) -> Result<()> {
    let sink = tx.copy_in(sql).await?;
    let writer = BinaryCopyInWriter::new(sink, types);
    pin_mut!(writer);
    for row in &rows {
        let refs: Vec<&(dyn ToSql + Sync)> = row
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();
        writer.as_mut().write(&refs).await?;
    }
    writer.finish().await?;
    Ok(())
}

pub async fn ingest(tx: &Transaction<'_>, r: &ScanReport) -> Result<IngestResult> {
    if r.schema_version > REPORT_SCHEMA_VERSION {
        bail!(
            "Report-Schema {} wird nicht unterstützt (Server kennt {})",
            r.schema_version,
            REPORT_SCHEMA_VERSION
        );
    }
    let now = Utc::now();

    if let Some(row) = tx
        .query_opt("SELECT system_id FROM scans WHERE uuid = $1", &[&r.scan_id])
        .await?
    {
        return Ok(IngestResult {
            system_id: row.get(0),
            duplicate: true,
            changes: 0,
        });
    }

    let os_build = r.host.os_build.map(i64::from);
    let h = &r.host;
    let params: [&(dyn ToSql + Sync); 8] = [
        &h.hostname,
        &h.domain,
        &h.os_name,
        &h.os_version,
        &os_build,
        &h.is_domain_controller,
        &r.client_version,
        &now,
    ];
    // Erst aktualisieren, nur bei neuem System einfügen (vermeidet Lücken in der ID-Sequenz)
    let existing = tx
        .query_opt(
            "UPDATE systems SET hostname = $1, domain = $2, os_name = $3, os_version = $4, os_build = $5, is_dc = $6,
                client_version = $7, last_seen = $8
             WHERE lower(hostname) = lower($1) RETURNING id",
            &params,
        )
        .await?;
    let system_id: i64 = match existing {
        Some(row) => row.get(0),
        None => tx
            .query_one(
                "INSERT INTO systems (hostname, domain, os_name, os_version, os_build, is_dc, client_version, first_seen, last_seen)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8) RETURNING id",
                &params,
            )
            .await?
            .get(0),
    };

    // Uploads desselben Systems serialisieren
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&system_id])
        .await?;

    // Älterer Scan als der zuletzt bekannte (z. B. nachgereichte Outbox)? Dann nur Historie.
    let last_finished: Option<chrono::DateTime<Utc>> = tx
        .query_opt(
            "SELECT s.finished_at FROM systems y JOIN scans s ON s.id = y.last_scan_id WHERE y.id = $1",
            &[&system_id],
        )
        .await?
        .map(|row| row.get(0));
    let is_newest = last_finished.is_none_or(|f| f < r.finished_at);

    let s = &r.stats;
    let scan_id: i64 = tx
        .query_one(
            "INSERT INTO scans (uuid, system_id, started_at, finished_at, received_at, report_mode, folders_scanned,
                folders_reported, folders_excluded, explicit_folders, protected_folders, errors, orphaned_aces,
                duration_ms, roots, error_list)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING id",
            &[
                &r.scan_id,
                &system_id,
                &r.started_at,
                &r.finished_at,
                &now,
                &r.report_mode.as_str(),
                &(s.folders_scanned as i64),
                &(s.folders_reported as i64),
                &(s.folders_excluded as i64),
                &(s.folders_with_explicit_aces as i64),
                &(s.folders_inheritance_protected as i64),
                &(s.errors as i64),
                &(s.orphaned_aces as i64),
                &(s.duration_ms as i64),
                &serde_json::to_value(&r.roots)?,
                &serde_json::to_value(r.errors.iter().take(1000).collect::<Vec<_>>())?,
            ],
        )
        .await?
        .get(0);

    let mut changes = 0;
    if is_newest {
        // Vorheriger Stand für den Änderungsverlauf (vor dem Ersetzen)
        let before = match last_finished {
            Some(_) => Some(crate::changes::snapshot(tx, system_id).await?),
            None => None,
        };
        tx.execute(
            "UPDATE systems SET last_scan_id = $2 WHERE id = $1",
            &[&system_id, &scan_id],
        )
        .await?;
        tx.execute("DELETE FROM aces WHERE system_id = $1", &[&system_id])
            .await?;
        tx.execute("DELETE FROM folders WHERE system_id = $1", &[&system_id])
            .await?;
        tx.execute("DELETE FROM shares WHERE system_id = $1", &[&system_id])
            .await?;

        let root_ids: HashSet<u64> = r.roots.iter().filter_map(|x| x.folder_id).collect();
        let mut folder_rows: Vec<Vec<Box<dyn ToSql + Sync + Send>>> =
            Vec::with_capacity(r.folders.len());
        let mut ace_rows: Vec<Vec<Box<dyn ToSql + Sync + Send>>> = Vec::new();
        for f in &r.folders {
            let is_root = root_ids.contains(&f.id);
            folder_rows.push(vec![
                Box::new(system_id),
                Box::new(f.id as i64),
                Box::new(if is_root {
                    None
                } else {
                    f.parent_id.map(|v| v as i64)
                }),
                Box::new(f.path.clone()),
                Box::new(if is_root {
                    f.path.clone()
                } else {
                    folder_name(&f.path)
                }),
                Box::new(f.depth as i32),
                Box::new(f.owner_sid.clone()),
                Box::new(f.inheritance_protected),
                Box::new(f.has_explicit_aces),
                Box::new(f.acl_source_id.map(|v| v as i64)),
                Box::new(f.subfolder_total as i64),
                Box::new(f.file_count as i64),
                Box::new(f.file_bytes as i64),
                Box::new(is_root),
                Box::new(f.error.clone()),
            ]);
            for a in &f.aces {
                ace_rows.push(vec![
                    Box::new(system_id),
                    Box::new(f.id as i64),
                    Box::new(a.sid.clone()),
                    Box::new(a.ace_type.as_str().to_string()),
                    Box::new(a.mask as i64),
                    Box::new(a.rights.as_str().to_string()),
                    Box::new(a.inherited),
                    Box::new(a.flags as i32),
                ]);
            }
        }
        copy_rows(
            tx,
            "COPY folders (system_id, local_id, parent_local_id, path, name, depth, owner_sid, protected, explicit,
                acl_source_local_id, subfolder_total, file_count, file_bytes, is_root, error) FROM STDIN BINARY",
            &[
                Type::INT8, Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::INT4, Type::TEXT, Type::BOOL,
                Type::BOOL, Type::INT8, Type::INT8, Type::INT8, Type::INT8, Type::BOOL, Type::TEXT,
            ],
            folder_rows,
        )
        .await?;
        copy_rows(
            tx,
            "COPY aces (system_id, folder_local_id, sid, ace_type, mask, rights, inherited, flags) FROM STDIN BINARY",
            &[Type::INT8, Type::INT8, Type::TEXT, Type::TEXT, Type::INT8, Type::TEXT, Type::BOOL, Type::INT4],
            ace_rows,
        )
        .await?;

        for sh in &r.shares {
            let share_id: i64 = tx
                .query_one(
                    "INSERT INTO shares (system_id, name, path, remark, share_type, is_special, has_sd, folder_local_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
                    &[
                        &system_id,
                        &sh.name,
                        &sh.path,
                        &sh.remark,
                        &(sh.share_type as i64),
                        &sh.is_special,
                        &sh.permissions.is_some(),
                        &sh.folder_id.map(|v| v as i64),
                    ],
                )
                .await?
                .get(0);
            for a in sh.permissions.iter().flatten() {
                tx.execute(
                    "INSERT INTO share_aces (share_id, sid, ace_type, mask, rights) VALUES ($1, $2, $3, $4, $5)",
                    &[&share_id, &a.sid, &a.ace_type.as_str(), &(a.mask as i64), &a.rights.as_str()],
                )
                .await?;
            }
        }

        if let Some(before) = before {
            let after = crate::changes::snapshot(tx, system_id).await?;
            let list = crate::changes::diff(&before, &after, &h.hostname);
            crate::changes::store(tx, system_id, scan_id, now, &list).await?;
            changes = list.len();
        }
    }

    // Auflösung des Clients übernehmen; bekannte Namen nicht durch „unbekannt“ überschreiben.
    let stmt = tx
        .prepare(
            "INSERT INTO principals (sid, name, domain, kind, last_seen) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (sid) DO UPDATE SET
                name = COALESCE(excluded.name, principals.name),
                domain = COALESCE(excluded.domain, principals.domain),
                kind = CASE WHEN excluded.kind = 'unknown' THEN principals.kind ELSE excluded.kind END,
                last_seen = excluded.last_seen",
        )
        .await?;
    for p in &r.principals {
        tx.execute(&stmt, &[&p.sid, &p.name, &p.domain, &p.kind.as_str(), &now])
            .await?;
    }

    Ok(IngestResult {
        system_id,
        duplicate: false,
        changes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(folder_name("C:\\Daten\\Vertrieb"), "Vertrieb");
        assert_eq!(folder_name("C:\\"), "C:\\");
        assert_eq!(folder_name("\\\\srv\\share\\x\\"), "x");
    }
}
