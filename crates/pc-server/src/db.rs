//! PostgreSQL-Datenbank des Servers.
//!
//! Pro System wird nur der Detailstand des neuesten Scans gehalten (Ordner,
//! ACEs, Freigaben); die Scan-Historie bleibt als Kennzahlen erhalten.
//! Massendaten werden per `COPY … BINARY` geschrieben.

use std::time::Duration;

use anyhow::{Context, Result};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod};
use serde_json::{json, Map, Value};
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::{GenericClient, NoTls, Row};
use tracing::{info, warn};

pub const SCHEMA_VERSION: i64 = 3;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS systems (
    id             BIGSERIAL PRIMARY KEY,
    hostname       TEXT NOT NULL,
    domain         TEXT,
    os_name        TEXT,
    os_version     TEXT,
    os_build       BIGINT,
    is_dc          BOOLEAN NOT NULL DEFAULT FALSE,
    client_version TEXT,
    first_seen     TIMESTAMPTZ NOT NULL,
    last_seen      TIMESTAMPTZ NOT NULL,
    last_scan_id   BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_systems_hostname ON systems (lower(hostname));

CREATE TABLE IF NOT EXISTS scans (
    id                BIGSERIAL PRIMARY KEY,
    uuid              UUID NOT NULL UNIQUE,
    system_id         BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    started_at        TIMESTAMPTZ NOT NULL,
    finished_at       TIMESTAMPTZ NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL,
    report_mode       TEXT NOT NULL,
    folders_scanned   BIGINT NOT NULL,
    folders_reported  BIGINT NOT NULL,
    folders_excluded  BIGINT NOT NULL,
    explicit_folders  BIGINT NOT NULL,
    protected_folders BIGINT NOT NULL,
    errors            BIGINT NOT NULL,
    orphaned_aces     BIGINT NOT NULL,
    duration_ms       BIGINT NOT NULL,
    roots             JSONB NOT NULL,
    error_list        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_system ON scans(system_id);

CREATE TABLE IF NOT EXISTS folders (
    system_id           BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    local_id            BIGINT NOT NULL,
    parent_local_id     BIGINT,
    path                TEXT NOT NULL,
    name                TEXT NOT NULL,
    depth               INTEGER NOT NULL,
    owner_sid           TEXT,
    protected           BOOLEAN NOT NULL,
    explicit            BOOLEAN NOT NULL,
    acl_source_local_id BIGINT,
    subfolder_total     BIGINT NOT NULL,
    file_count          BIGINT NOT NULL,
    file_bytes          BIGINT NOT NULL,
    is_root             BOOLEAN NOT NULL,
    error               TEXT,
    PRIMARY KEY (system_id, local_id)
);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(system_id, parent_local_id);
CREATE INDEX IF NOT EXISTS idx_folders_path ON folders(system_id, path);

CREATE TABLE IF NOT EXISTS aces (
    system_id       BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    folder_local_id BIGINT NOT NULL,
    sid             TEXT NOT NULL,
    ace_type        TEXT NOT NULL,
    mask            BIGINT NOT NULL,
    rights          TEXT NOT NULL,
    inherited       BOOLEAN NOT NULL,
    flags           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aces_folder ON aces(system_id, folder_local_id);
CREATE INDEX IF NOT EXISTS idx_aces_sid ON aces(sid) WHERE NOT inherited;

CREATE TABLE IF NOT EXISTS shares (
    id              BIGSERIAL PRIMARY KEY,
    system_id       BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    path            TEXT NOT NULL,
    remark          TEXT,
    share_type      BIGINT NOT NULL,
    is_special      BOOLEAN NOT NULL,
    has_sd          BOOLEAN NOT NULL,
    folder_local_id BIGINT
);
CREATE TABLE IF NOT EXISTS share_aces (
    share_id BIGINT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    sid      TEXT NOT NULL,
    ace_type TEXT NOT NULL,
    mask     BIGINT NOT NULL,
    rights   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_share_aces_sid ON share_aces(sid);

CREATE TABLE IF NOT EXISTS principals (
    sid       TEXT PRIMARY KEY,
    name      TEXT,
    domain    TEXT,
    kind      TEXT NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS ad_users (
    sid          TEXT PRIMARY KEY,
    sam          TEXT NOT NULL,
    upn          TEXT,
    display_name TEXT,
    dn           TEXT,
    enabled      BOOLEAN NOT NULL,
    last_logon   TIMESTAMPTZ,
    pwd_last_set TIMESTAMPTZ,
    created      TIMESTAMPTZ,
    is_computer  BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS ad_groups (
    sid         TEXT PRIMARY KEY,
    sam         TEXT NOT NULL,
    dn          TEXT,
    description TEXT,
    scope       TEXT,
    is_security BOOLEAN NOT NULL,
    created     TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS ad_members (
    group_sid  TEXT NOT NULL,
    member_sid TEXT NOT NULL,
    PRIMARY KEY (group_sid, member_sid)
);
CREATE INDEX IF NOT EXISTS idx_ad_members_member ON ad_members(member_sid);

CREATE TABLE IF NOT EXISTS findings (
    id         BIGSERIAL PRIMARY KEY,
    system_id  BIGINT REFERENCES systems(id) ON DELETE CASCADE,
    rule       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    detail     TEXT,
    path       TEXT,
    sid        TEXT,
    affected   BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_system ON findings(system_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule);
CREATE INDEX IF NOT EXISTS idx_findings_sid ON findings(sid);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint TEXT;
ALTER TABLE ad_users ADD COLUMN IF NOT EXISTS pwd_never_expires BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ad_users ADD COLUMN IF NOT EXISTS spns TEXT[];
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);

-- Audit-Assist: Bearbeitungsstand je Befund (überdauert die Neuberechnung der Befunde)
CREATE TABLE IF NOT EXISTS finding_states (
    fingerprint TEXT PRIMARY KEY,
    rule        TEXT NOT NULL,
    system_id   BIGINT REFERENCES systems(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL,
    note        TEXT,
    updated_at  TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ
);

-- Änderungsverlauf zwischen zwei Scans eines Systems
CREATE TABLE IF NOT EXISTS changes (
    id          BIGSERIAL PRIMARY KEY,
    system_id   BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    scan_id     BIGINT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL,
    object_kind TEXT NOT NULL,
    path        TEXT NOT NULL,
    change      TEXT NOT NULL,
    sid         TEXT,
    old_value   TEXT,
    new_value   TEXT
);
CREATE INDEX IF NOT EXISTS idx_changes_system ON changes(system_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_changes_sid ON changes(sid);

-- Tageswerte der Bewertung (Trend); system_id 0 = gesamt bzw. AD
CREATE TABLE IF NOT EXISTS score_history (
    day       DATE NOT NULL,
    scope     TEXT NOT NULL,
    system_id BIGINT NOT NULL DEFAULT 0,
    score     INTEGER NOT NULL,
    grade     TEXT NOT NULL,
    critical  INTEGER NOT NULL,
    high      INTEGER NOT NULL,
    medium    INTEGER NOT NULL,
    low       INTEGER NOT NULL,
    info      INTEGER NOT NULL,
    PRIMARY KEY (day, scope, system_id)
);

-- Fachlich verantwortliche Person je Ordner (gilt auch für Unterordner)
CREATE TABLE IF NOT EXISTS data_owners (
    system_id  BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    path       TEXT NOT NULL,
    owner      TEXT NOT NULL,
    email      TEXT,
    note       TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_data_owners ON data_owners (system_id, lower(path));

-- Mitglieder der lokalen Administratorengruppe je System (neuester Scan)
CREATE TABLE IF NOT EXISTS local_admins (
    system_id BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    sid       TEXT NOT NULL,
    name      TEXT,
    kind      TEXT NOT NULL,
    PRIMARY KEY (system_id, sid)
);

-- Dateien mit eigenen Berechtigungen (optionale Dateiebene, neuester Scan)
CREATE TABLE IF NOT EXISTS files (
    system_id       BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    file_id         BIGINT NOT NULL,
    folder_local_id BIGINT NOT NULL,
    path            TEXT NOT NULL,
    owner_sid       TEXT,
    protected       BOOLEAN NOT NULL,
    PRIMARY KEY (system_id, file_id)
);
CREATE INDEX IF NOT EXISTS idx_files_folder ON files(system_id, folder_local_id);
CREATE TABLE IF NOT EXISTS file_aces (
    system_id BIGINT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    file_id   BIGINT NOT NULL,
    sid       TEXT NOT NULL,
    ace_type  TEXT NOT NULL,
    mask      BIGINT NOT NULL,
    rights    TEXT NOT NULL,
    inherited BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_aces ON file_aces(system_id, file_id);

-- „Jetzt scannen“: vom Client-Dienst abgeholte Aufträge
CREATE TABLE IF NOT EXISTS scan_requests (
    system_id    BIGINT PRIMARY KEY REFERENCES systems(id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL,
    picked_at    TIMESTAMPTZ
);
"#;

/// Sperre, die parallele Analyse-Läufe serialisiert.
pub const ANALYSIS_LOCK: i64 = 0x5043_414E; // "PCAN"

pub type Db = Pool;

/// Verbindet sich mit PostgreSQL (mit Wiederholungen beim Containerstart) und legt das Schema an.
pub async fn connect(url: &str, max_size: usize) -> Result<Db> {
    let pg: tokio_postgres::Config = url.parse().context("database_url ungültig")?;
    let mgr = Manager::from_config(
        pg,
        NoTls,
        ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        },
    );
    let pool = Pool::builder(mgr).max_size(max_size).build()?;
    let mut attempt = 0;
    let client = loop {
        match pool.get().await {
            Ok(c) => break c,
            Err(e) if attempt < 30 => {
                attempt += 1;
                warn!("Datenbank nicht erreichbar ({e}) – neuer Versuch in 2 s ({attempt}/30)");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(anyhow::anyhow!("Datenbank nicht erreichbar: {e}")),
        }
    };
    migrate(&client).await?;
    Ok(pool)
}

async fn migrate(c: &Object) -> Result<()> {
    c.batch_execute(SCHEMA)
        .await
        .context("Schema konnte nicht angelegt werden")?;
    let current: Option<i64> = get_meta(&***c, "schema_version")
        .await?
        .and_then(|v| v.parse().ok());
    if current != Some(SCHEMA_VERSION) {
        set_meta(&***c, "schema_version", Some(&SCHEMA_VERSION.to_string())).await?;
        info!("Datenbankschema Version {SCHEMA_VERSION} aktiv");
    }
    Ok(())
}

pub async fn get_meta(c: &impl GenericClient, key: &str) -> Result<Option<String>> {
    Ok(
        c.query_opt("SELECT value FROM meta WHERE key = $1", &[&key])
            .await?
            .and_then(|r| r.get(0)),
    )
}

pub async fn set_meta(c: &impl GenericClient, key: &str, value: Option<&str>) -> Result<()> {
    c.execute(
        "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        &[&key, &value],
    )
    .await?;
    Ok(())
}

/// Wandelt eine Zeile anhand der Spaltentypen in ein JSON-Objekt um.
pub fn row_json(row: &Row) -> Value {
    let mut m = Map::new();
    for (i, col) in row.columns().iter().enumerate() {
        let t = col.type_();
        let v = if *t == Type::INT8 {
            json!(row.get::<_, Option<i64>>(i))
        } else if *t == Type::INT4 {
            json!(row.get::<_, Option<i32>>(i))
        } else if *t == Type::INT2 {
            json!(row.get::<_, Option<i16>>(i))
        } else if *t == Type::BOOL {
            json!(row.get::<_, Option<bool>>(i))
        } else if *t == Type::FLOAT8 {
            json!(row.get::<_, Option<f64>>(i))
        } else if *t == Type::TIMESTAMPTZ {
            json!(row.get::<_, Option<chrono::DateTime<chrono::Utc>>>(i))
        } else if *t == Type::JSONB || *t == Type::JSON {
            row.get::<_, Option<Value>>(i).unwrap_or(Value::Null)
        } else if *t == Type::UUID {
            json!(row.get::<_, Option<uuid::Uuid>>(i))
        } else if *t == Type::TEXT_ARRAY {
            json!(row.get::<_, Option<Vec<String>>>(i))
        } else {
            json!(row.try_get::<_, Option<String>>(i).ok().flatten())
        };
        m.insert(col.name().to_string(), v);
    }
    Value::Object(m)
}

pub async fn query_json(
    c: &impl GenericClient,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Vec<Value>> {
    Ok(c.query(sql, params).await?.iter().map(row_json).collect())
}

pub async fn query_one_json(
    c: &impl GenericClient,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<Option<Value>> {
    Ok(c.query_opt(sql, params).await?.as_ref().map(row_json))
}

pub async fn count(
    c: &impl GenericClient,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
) -> Result<i64> {
    Ok(c.query_one(sql, params)
        .await?
        .get::<_, Option<i64>>(0)
        .unwrap_or(0))
}
