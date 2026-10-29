//! Lokale SQLite-Datenbank: Scan-Historie, normalisierte Ergebnisse und
//! Upload-Warteschlange (Outbox) für den Offline-Betrieb.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use rusqlite::{params, Connection, OptionalExtension};

use pc_common::ScanReport;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_uuid       TEXT NOT NULL UNIQUE,
    started_at      TEXT NOT NULL,
    finished_at     TEXT NOT NULL,
    report_mode     TEXT NOT NULL,
    folders_scanned INTEGER NOT NULL,
    folders_reported INTEGER NOT NULL,
    errors          INTEGER NOT NULL,
    orphaned_aces   INTEGER NOT NULL,
    payload         BLOB NOT NULL,
    uploaded_at     TEXT,
    upload_attempts INTEGER NOT NULL DEFAULT 0,
    upload_error    TEXT
);
CREATE TABLE IF NOT EXISTS folders (
    scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id              INTEGER NOT NULL,
    parent_id       INTEGER,
    path            TEXT NOT NULL,
    depth           INTEGER NOT NULL,
    owner_sid       TEXT,
    protected       INTEGER NOT NULL,
    explicit        INTEGER NOT NULL,
    acl_source_id   INTEGER,
    subfolder_total INTEGER NOT NULL,
    file_count      INTEGER NOT NULL,
    error           TEXT,
    PRIMARY KEY (scan_id, id)
);
CREATE TABLE IF NOT EXISTS aces (
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    folder_id INTEGER NOT NULL,
    sid       TEXT NOT NULL,
    ace_type  TEXT NOT NULL,
    mask      INTEGER NOT NULL,
    rights    TEXT NOT NULL,
    inherited INTEGER NOT NULL,
    flags     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aces_sid ON aces(sid);
CREATE TABLE IF NOT EXISTS shares (
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    path       TEXT NOT NULL,
    remark     TEXT,
    share_type INTEGER NOT NULL,
    is_special INTEGER NOT NULL,
    folder_id  INTEGER,
    permissions_json TEXT
);
CREATE TABLE IF NOT EXISTS principals (
    sid       TEXT PRIMARY KEY,
    name      TEXT,
    domain    TEXT,
    kind      TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
"#;

pub struct LocalDb {
    conn: Connection,
}

#[derive(Debug)]
pub struct ScanSummary {
    pub id: i64,
    pub scan_uuid: String,
    pub finished_at: String,
    pub report_mode: String,
    pub folders_scanned: i64,
    pub folders_reported: i64,
    pub errors: i64,
    pub orphaned_aces: i64,
    pub uploaded_at: Option<String>,
    pub upload_attempts: i64,
    pub upload_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OrphanRow {
    pub sid: String,
    pub folders: i64,
    pub example_path: String,
}

pub fn compress(report: &ScanReport) -> Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    serde_json::to_writer(&mut enc, report)?;
    enc.flush()?;
    Ok(enc.finish()?)
}

pub fn decompress(bytes: &[u8]) -> Result<ScanReport> {
    let mut s = String::new();
    GzDecoder::new(bytes).read_to_string(&mut s)?;
    Ok(serde_json::from_str(&s)?)
}

impl LocalDb {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Verzeichnis {} nicht anlegbar", dir.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("Lokale DB {} nicht öffenbar", path.display()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Speichert einen Report normalisiert und als komprimierte Nutzlast.
    pub fn store(&mut self, r: &ScanReport) -> Result<i64> {
        let payload = compress(r)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO scans (scan_uuid, started_at, finished_at, report_mode, folders_scanned,
                folders_reported, errors, orphaned_aces, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                r.scan_id.to_string(),
                r.started_at.to_rfc3339(),
                r.finished_at.to_rfc3339(),
                r.report_mode.as_str(),
                r.stats.folders_scanned as i64,
                r.stats.folders_reported as i64,
                r.stats.errors as i64,
                r.stats.orphaned_aces as i64,
                payload,
            ],
        )?;
        let scan_id = tx.last_insert_rowid();
        {
            let mut fst = tx.prepare(
                "INSERT INTO folders VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            let mut ast = tx.prepare("INSERT INTO aces VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?;
            for f in &r.folders {
                fst.execute(params![
                    scan_id,
                    f.id as i64,
                    f.parent_id.map(|v| v as i64),
                    f.path,
                    f.depth,
                    f.owner_sid,
                    f.inheritance_protected,
                    f.has_explicit_aces,
                    f.acl_source_id.map(|v| v as i64),
                    f.subfolder_total as i64,
                    f.file_count as i64,
                    f.error,
                ])?;
                for a in &f.aces {
                    ast.execute(params![
                        scan_id,
                        f.id as i64,
                        a.sid,
                        a.ace_type.as_str(),
                        a.mask as i64,
                        a.rights.as_str(),
                        a.inherited,
                        a.flags,
                    ])?;
                }
            }
            let mut sst =
                tx.prepare("INSERT INTO shares VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?;
            for s in &r.shares {
                sst.execute(params![
                    scan_id,
                    s.name,
                    s.path,
                    s.remark,
                    s.share_type,
                    s.is_special,
                    s.folder_id.map(|v| v as i64),
                    s.permissions
                        .as_ref()
                        .map(|p| serde_json::to_string(p).unwrap_or_default()),
                ])?;
            }
            let now = Utc::now().to_rfc3339();
            let mut pst = tx.prepare(
                "INSERT INTO principals (sid, name, domain, kind, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sid) DO UPDATE SET name=excluded.name, domain=excluded.domain,
                    kind=excluded.kind, last_seen=excluded.last_seen",
            )?;
            for p in &r.principals {
                pst.execute(params![p.sid, p.name, p.domain, p.kind.as_str(), now])?;
            }
        }
        tx.commit()?;
        Ok(scan_id)
    }

    /// Löscht alte Scans, behält die neuesten `keep`.
    pub fn prune(&self, keep: u32) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?1)",
            params![keep.max(1)],
        )?;
        // Normalisierte Daten ohne Scan entfernen (falls Foreign Keys nicht griffen)
        self.conn.execute_batch(
            "DELETE FROM folders WHERE scan_id NOT IN (SELECT id FROM scans);
             DELETE FROM aces WHERE scan_id NOT IN (SELECT id FROM scans);
             DELETE FROM shares WHERE scan_id NOT IN (SELECT id FROM scans);",
        )?;
        Ok(n)
    }

    pub fn list(&self) -> Result<Vec<ScanSummary>> {
        let mut st = self.conn.prepare(
            "SELECT id, scan_uuid, finished_at, report_mode, folders_scanned, folders_reported, errors,
                    orphaned_aces, uploaded_at, upload_attempts, upload_error
             FROM scans ORDER BY id DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok(ScanSummary {
                id: r.get(0)?,
                scan_uuid: r.get(1)?,
                finished_at: r.get(2)?,
                report_mode: r.get(3)?,
                folders_scanned: r.get(4)?,
                folders_reported: r.get(5)?,
                errors: r.get(6)?,
                orphaned_aces: r.get(7)?,
                uploaded_at: r.get(8)?,
                upload_attempts: r.get(9)?,
                upload_error: r.get(10)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Noch nicht übertragene Scans (älteste zuerst).
    pub fn pending(&self) -> Result<Vec<(i64, Vec<u8>)>> {
        let mut st = self
            .conn
            .prepare("SELECT id, payload FROM scans WHERE uploaded_at IS NULL ORDER BY id ASC")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn payload(&self, selector: &str) -> Result<Option<Vec<u8>>> {
        let sql = if selector == "latest" {
            "SELECT payload FROM scans ORDER BY id DESC LIMIT 1"
        } else {
            "SELECT payload FROM scans WHERE scan_uuid = ?1 OR CAST(id AS TEXT) = ?1"
        };
        let mut st = self.conn.prepare(sql)?;
        let res = if selector == "latest" {
            st.query_row([], |r| r.get(0)).optional()?
        } else {
            st.query_row([selector], |r| r.get(0)).optional()?
        };
        Ok(res)
    }

    pub fn mark_uploaded(&self, id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE scans SET uploaded_at = ?2, upload_attempts = upload_attempts + 1, upload_error = NULL WHERE id = ?1",
            params![id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn mark_failed(&self, id: i64, err: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE scans SET upload_attempts = upload_attempts + 1, upload_error = ?2 WHERE id = ?1",
            params![id, err],
        )?;
        Ok(())
    }

    /// Verwaiste SIDs mit expliziten ACEs im neuesten Scan.
    pub fn orphans(&self) -> Result<Vec<OrphanRow>> {
        let mut st = self.conn.prepare(
            "SELECT a.sid, COUNT(DISTINCT a.folder_id), MIN(f.path)
             FROM aces a
             JOIN principals p ON p.sid = a.sid
             JOIN folders f ON f.scan_id = a.scan_id AND f.id = a.folder_id
             WHERE a.scan_id = (SELECT MAX(id) FROM scans)
               AND a.inherited = 0 AND p.kind IN ('unresolved', 'deleted')
             GROUP BY a.sid ORDER BY 2 DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok(OrphanRow {
                sid: r.get(0)?,
                folders: r.get(1)?,
                example_path: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}
