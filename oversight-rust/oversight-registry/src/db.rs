use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::path::Path;
use std::str::FromStr;

use crate::error::{RegistryError, Result};
use crate::models::*;

const MIGRATED_TABLES: &[&str] = &["manifests", "beacons", "watermarks", "events", "corpus"];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MigrationReport {
    pub source: String,
    pub dry_run: bool,
    pub manifests: i64,
    pub beacons: i64,
    pub watermarks: i64,
    pub events: i64,
    pub corpus: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RegistryCounts {
    pub manifests: i64,
    pub beacons: i64,
    pub watermarks: i64,
    pub events: i64,
    pub corpus: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RegistryIntegrityReport {
    pub ok: bool,
    pub counts: RegistryCounts,
    pub orphan_beacons: i64,
    pub orphan_watermarks: i64,
    pub orphan_events: i64,
    pub orphan_corpus: i64,
    pub beacon_identity_mismatches: i64,
    pub watermark_identity_mismatches: i64,
    pub event_identity_mismatches: i64,
    pub malformed_event_extra_json: i64,
    pub malformed_corpus_metadata_json: i64,
    pub duplicate_event_tlog_indexes: i64,
    pub negative_event_tlog_indexes: i64,
    pub events_without_tlog_index: i64,
    pub event_tlog_indexes_out_of_range: i64,
    pub event_tlog_leaf_mismatches: i64,
    pub tlog_size: Option<usize>,
    pub malformed_manifest_json: i64,
    pub invalid_manifest_signatures: i64,
    pub mismatched_manifest_file_ids: i64,
}

pub async fn create_pool(db_path: &Path) -> Result<SqlitePool> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| RegistryError::Internal(format!("cannot create db directory: {e}")))?;
    }

    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let opts = SqliteConnectOptions::from_str(&db_url)
        .map_err(|e| RegistryError::Internal(format!("bad db url: {e}")))?
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;

    Ok(pool)
}

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS beacons (
            token_id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            issuer_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            registered_at INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS watermarks (
            mark_id TEXT NOT NULL,
            layer TEXT NOT NULL,
            file_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            issuer_id TEXT NOT NULL,
            registered_at INTEGER NOT NULL,
            PRIMARY KEY (mark_id, layer)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS manifests (
            file_id TEXT PRIMARY KEY,
            recipient_id TEXT NOT NULL,
            issuer_id TEXT NOT NULL,
            issuer_ed25519_pub TEXT NOT NULL,
            manifest_json TEXT NOT NULL,
            registered_at INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id TEXT NOT NULL,
            file_id TEXT,
            recipient_id TEXT,
            issuer_id TEXT,
            kind TEXT NOT NULL,
            source_ip TEXT,
            user_agent TEXT,
            extra TEXT,
            timestamp INTEGER NOT NULL,
            qualified_timestamp TEXT,
            tlog_index INTEGER
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS corpus (
            file_id TEXT NOT NULL,
            hash_kind TEXT NOT NULL,
            hash_value TEXT NOT NULL,
            metadata TEXT,
            registered_at INTEGER NOT NULL,
            PRIMARY KEY (file_id, hash_kind, hash_value)
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_token ON events(token_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_file ON events(file_id);")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_corpus_hash ON corpus(hash_kind, hash_value);")
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn migrate_from_sqlite(
    pool: &SqlitePool,
    source_path: &Path,
    dry_run: bool,
) -> Result<MigrationReport> {
    if !source_path.is_file() {
        return Err(RegistryError::BadRequest(format!(
            "migration source is not a file: {}",
            source_path.display()
        )));
    }

    let source = source_path
        .canonicalize()
        .map_err(|e| RegistryError::BadRequest(format!("cannot resolve migration source: {e}")))?;
    let source_uri = source.to_string_lossy().to_string();

    let mut conn = pool.acquire().await?;
    sqlx::query("ATTACH DATABASE ? AS source_registry")
        .bind(&source_uri)
        .execute(&mut *conn)
        .await?;

    let result = async {
        validate_source_schema(&mut conn).await?;
        let report = MigrationReport {
            source: source_uri,
            dry_run,
            manifests: source_count(&mut conn, "manifests").await?,
            beacons: source_count(&mut conn, "beacons").await?,
            watermarks: source_count(&mut conn, "watermarks").await?,
            events: source_count(&mut conn, "events").await?,
            corpus: source_count(&mut conn, "corpus").await?,
        };

        if dry_run {
            return Ok(report);
        }

        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let copy_result = copy_attached_source(&mut conn).await;
        match copy_result {
            Ok(()) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(report)
            }
            Err(err) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(err)
            }
        }
    }
    .await;

    let detach_result = sqlx::query("DETACH DATABASE source_registry")
        .execute(&mut *conn)
        .await;
    if let Err(err) = detach_result {
        return Err(RegistryError::Database(err));
    }
    result
}

pub async fn validate_registry_integrity(
    pool: &SqlitePool,
    tlog: Option<&oversight_tlog::TransparencyLog>,
) -> Result<RegistryIntegrityReport> {
    let tlog_size = tlog.map(|log| log.size());
    let counts = registry_counts(pool).await?;
    let orphan_beacons = count_query(
        pool,
        "SELECT COUNT(*) FROM beacons b LEFT JOIN manifests m ON b.file_id = m.file_id WHERE m.file_id IS NULL",
    )
    .await?;
    let orphan_watermarks = count_query(
        pool,
        "SELECT COUNT(*) FROM watermarks w LEFT JOIN manifests m ON w.file_id = m.file_id WHERE m.file_id IS NULL",
    )
    .await?;
    let orphan_events = count_query(
        pool,
        "SELECT COUNT(*) FROM events e LEFT JOIN manifests m ON e.file_id = m.file_id WHERE e.file_id IS NOT NULL AND m.file_id IS NULL",
    )
    .await?;
    let orphan_corpus = count_query(
        pool,
        "SELECT COUNT(*) FROM corpus c LEFT JOIN manifests m ON c.file_id = m.file_id WHERE m.file_id IS NULL",
    )
    .await?;
    let beacon_identity_mismatches = count_query(
        pool,
        "SELECT COUNT(*) FROM beacons b JOIN manifests m ON b.file_id = m.file_id WHERE b.recipient_id != m.recipient_id OR b.issuer_id != m.issuer_id",
    )
    .await?;
    let watermark_identity_mismatches = count_query(
        pool,
        "SELECT COUNT(*) FROM watermarks w JOIN manifests m ON w.file_id = m.file_id WHERE w.recipient_id != m.recipient_id OR w.issuer_id != m.issuer_id",
    )
    .await?;
    let event_identity_mismatches = count_query(
        pool,
        "SELECT COUNT(*) FROM events e JOIN manifests m ON e.file_id = m.file_id WHERE (e.recipient_id IS NOT NULL AND e.recipient_id != m.recipient_id) OR (e.issuer_id IS NOT NULL AND e.issuer_id != m.issuer_id)",
    )
    .await?;
    let duplicate_event_tlog_indexes = count_query(
        pool,
        "SELECT COALESCE(SUM(cnt - 1), 0) FROM (SELECT COUNT(*) AS cnt FROM events WHERE tlog_index IS NOT NULL GROUP BY tlog_index HAVING COUNT(*) > 1)",
    )
    .await?;
    let negative_event_tlog_indexes = count_query(
        pool,
        "SELECT COUNT(*) FROM events WHERE tlog_index IS NOT NULL AND tlog_index < 0",
    )
    .await?;
    let events_without_tlog_index =
        count_query(pool, "SELECT COUNT(*) FROM events WHERE tlog_index IS NULL").await?;
    let event_tlog_indexes_out_of_range = match tlog_size {
        Some(size) => {
            let (count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM events WHERE tlog_index IS NOT NULL AND tlog_index >= ?",
            )
            .bind(size as i64)
            .fetch_one(pool)
            .await?;
            count
        }
        None => 0,
    };

    let event_extra_rows: Vec<String> = sqlx::query_scalar(
        "SELECT extra FROM events WHERE extra IS NOT NULL AND TRIM(extra) != ''",
    )
    .fetch_all(pool)
    .await?;
    let malformed_event_extra_json = event_extra_rows
        .iter()
        .filter(|extra| serde_json::from_str::<serde_json::Value>(extra).is_err())
        .count() as i64;

    let corpus_metadata_rows: Vec<String> = sqlx::query_scalar(
        "SELECT metadata FROM corpus WHERE metadata IS NOT NULL AND TRIM(metadata) != ''",
    )
    .fetch_all(pool)
    .await?;
    let malformed_corpus_metadata_json = corpus_metadata_rows
        .iter()
        .filter(|metadata| serde_json::from_str::<serde_json::Value>(metadata).is_err())
        .count() as i64;

    let event_rows: Vec<EventRow> = sqlx::query_as(
        "SELECT id, token_id, file_id, recipient_id, issuer_id, kind, source_ip, user_agent, extra, timestamp, qualified_timestamp, tlog_index FROM events",
    )
    .fetch_all(pool)
    .await?;
    let mut event_tlog_leaf_mismatches = 0;
    if let Some(log) = tlog {
        for event in &event_rows {
            let Some(idx) = event.tlog_index else {
                continue;
            };
            if idx < 0 || idx as usize >= log.size() {
                continue;
            }
            let Some(record) = log
                .leaf_record(idx as usize)
                .map_err(|e| RegistryError::Internal(format!("tlog leaf read failed: {e}")))?
            else {
                event_tlog_leaf_mismatches += 1;
                continue;
            };
            let Ok(leaf) = serde_json::from_str::<serde_json::Value>(&record.leaf_data) else {
                event_tlog_leaf_mismatches += 1;
                continue;
            };
            if !event_matches_tlog_leaf(event, &leaf) {
                event_tlog_leaf_mismatches += 1;
            }
        }
    }

    let mut malformed_manifest_json = 0;
    let mut invalid_manifest_signatures = 0;
    let mut mismatched_manifest_file_ids = 0;
    let manifest_rows: Vec<(String, String)> =
        sqlx::query_as("SELECT file_id, manifest_json FROM manifests")
            .fetch_all(pool)
            .await?;

    for (file_id, manifest_json) in manifest_rows {
        match oversight_manifest::Manifest::from_json(manifest_json.as_bytes()) {
            Ok(manifest) => {
                if manifest.file_id != file_id {
                    mismatched_manifest_file_ids += 1;
                }
                if !manifest.verify().unwrap_or(false) {
                    invalid_manifest_signatures += 1;
                }
            }
            Err(_) => {
                malformed_manifest_json += 1;
            }
        }
    }

    let ok = orphan_beacons == 0
        && orphan_watermarks == 0
        && orphan_events == 0
        && orphan_corpus == 0
        && beacon_identity_mismatches == 0
        && watermark_identity_mismatches == 0
        && event_identity_mismatches == 0
        && malformed_event_extra_json == 0
        && malformed_corpus_metadata_json == 0
        && duplicate_event_tlog_indexes == 0
        && negative_event_tlog_indexes == 0
        && events_without_tlog_index == 0
        && event_tlog_indexes_out_of_range == 0
        && event_tlog_leaf_mismatches == 0
        && malformed_manifest_json == 0
        && invalid_manifest_signatures == 0
        && mismatched_manifest_file_ids == 0;

    Ok(RegistryIntegrityReport {
        ok,
        counts,
        orphan_beacons,
        orphan_watermarks,
        orphan_events,
        orphan_corpus,
        beacon_identity_mismatches,
        watermark_identity_mismatches,
        event_identity_mismatches,
        malformed_event_extra_json,
        malformed_corpus_metadata_json,
        duplicate_event_tlog_indexes,
        negative_event_tlog_indexes,
        events_without_tlog_index,
        event_tlog_indexes_out_of_range,
        event_tlog_leaf_mismatches,
        tlog_size,
        malformed_manifest_json,
        invalid_manifest_signatures,
        mismatched_manifest_file_ids,
    })
}

fn event_matches_tlog_leaf(event: &EventRow, leaf: &serde_json::Value) -> bool {
    let user_agent_matches =
        event.kind == "dns" || json_opt_str(leaf, "user_agent", event.user_agent.as_deref());
    leaf.get("event").and_then(|v| v.as_str()) == Some("beacon")
        && leaf.get("kind").and_then(|v| v.as_str()) == Some(event.kind.as_str())
        && leaf.get("token_id").and_then(|v| v.as_str()) == Some(event.token_id.as_str())
        && json_opt_str(leaf, "file_id", event.file_id.as_deref())
        && json_opt_str(leaf, "recipient_id", event.recipient_id.as_deref())
        && json_opt_str(leaf, "source_ip", event.source_ip.as_deref())
        && user_agent_matches
        && json_opt_str(leaf, "timestamp", event.qualified_timestamp.as_deref())
        && dns_extra_matches_tlog_leaf(event, leaf)
}

fn dns_extra_matches_tlog_leaf(event: &EventRow, leaf: &serde_json::Value) -> bool {
    if event.kind != "dns" {
        return true;
    }
    let extra = event
        .extra
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    json_opt_str(leaf, "qname", extra.get("qname").and_then(|v| v.as_str()))
        && json_opt_str(leaf, "qtype", extra.get("qtype").and_then(|v| v.as_str()))
}

fn json_opt_str(value: &serde_json::Value, key: &str, expected: Option<&str>) -> bool {
    match expected {
        Some(s) => value.get(key).and_then(|v| v.as_str()) == Some(s),
        None => match value.get(key) {
            Some(v) => v.is_null(),
            None => true,
        },
    }
}

async fn registry_counts(pool: &SqlitePool) -> Result<RegistryCounts> {
    Ok(RegistryCounts {
        manifests: count_query(pool, "SELECT COUNT(*) FROM manifests").await?,
        beacons: count_query(pool, "SELECT COUNT(*) FROM beacons").await?,
        watermarks: count_query(pool, "SELECT COUNT(*) FROM watermarks").await?,
        events: count_query(pool, "SELECT COUNT(*) FROM events").await?,
        corpus: count_query(pool, "SELECT COUNT(*) FROM corpus").await?,
    })
}

async fn count_query(pool: &SqlitePool, sql: &str) -> Result<i64> {
    let (count,): (i64,) = sqlx::query_as(sql).fetch_one(pool).await?;
    Ok(count)
}

async fn validate_source_schema(conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>) -> Result<()> {
    for table in MIGRATED_TABLES {
        let exists: Option<(String,)> = sqlx::query_as(
            "SELECT name FROM source_registry.sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(table)
        .fetch_optional(&mut **conn)
        .await?;
        if exists.is_none() {
            return Err(RegistryError::BadRequest(format!(
                "migration source missing required table: {table}"
            )));
        }
    }
    Ok(())
}

async fn source_count(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
    table: &str,
) -> Result<i64> {
    let sql = match table {
        "manifests" => "SELECT COUNT(*) FROM source_registry.manifests",
        "beacons" => "SELECT COUNT(*) FROM source_registry.beacons",
        "watermarks" => "SELECT COUNT(*) FROM source_registry.watermarks",
        "events" => "SELECT COUNT(*) FROM source_registry.events",
        "corpus" => "SELECT COUNT(*) FROM source_registry.corpus",
        _ => {
            return Err(RegistryError::Internal(
                "unsupported migration table".into(),
            ))
        }
    };
    let (count,): (i64,) = sqlx::query_as(sql).fetch_one(&mut **conn).await?;
    Ok(count)
}

async fn copy_attached_source(conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>) -> Result<()> {
    sqlx::query(
        r#"
        INSERT OR REPLACE INTO manifests
            (file_id, recipient_id, issuer_id, issuer_ed25519_pub, manifest_json, registered_at)
        SELECT file_id, recipient_id, issuer_id, issuer_ed25519_pub, manifest_json, registered_at
        FROM source_registry.manifests
        "#,
    )
    .execute(&mut **conn)
    .await?;

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO beacons
            (token_id, file_id, recipient_id, issuer_id, kind, registered_at)
        SELECT token_id, file_id, recipient_id, issuer_id, kind, registered_at
        FROM source_registry.beacons
        "#,
    )
    .execute(&mut **conn)
    .await?;

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO watermarks
            (mark_id, layer, file_id, recipient_id, issuer_id, registered_at)
        SELECT mark_id, layer, file_id, recipient_id, issuer_id, registered_at
        FROM source_registry.watermarks
        "#,
    )
    .execute(&mut **conn)
    .await?;

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO events
            (id, token_id, file_id, recipient_id, issuer_id, kind, source_ip,
             user_agent, extra, timestamp, qualified_timestamp, tlog_index)
        SELECT id, token_id, file_id, recipient_id, issuer_id, kind, source_ip,
               user_agent, extra, timestamp, qualified_timestamp, tlog_index
        FROM source_registry.events
        "#,
    )
    .execute(&mut **conn)
    .await?;

    sqlx::query(
        r#"
        INSERT OR REPLACE INTO corpus
            (file_id, hash_kind, hash_value, metadata, registered_at)
        SELECT file_id, hash_kind, hash_value, metadata, registered_at
        FROM source_registry.corpus
        "#,
    )
    .execute(&mut **conn)
    .await?;

    Ok(())
}

pub async fn get_manifest_issuer_pub(pool: &SqlitePool, file_id: &str) -> Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT issuer_ed25519_pub FROM manifests WHERE file_id = ?")
            .bind(file_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}

pub async fn upsert_manifest(
    pool: &SqlitePool,
    file_id: &str,
    recipient_id: &str,
    issuer_id: &str,
    issuer_pub: &str,
    manifest_json: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO manifests (file_id, recipient_id, issuer_id, issuer_ed25519_pub, manifest_json, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(file_id)
    .bind(recipient_id)
    .bind(issuer_id)
    .bind(issuer_pub)
    .bind(manifest_json)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_manifest(pool: &SqlitePool, file_id: &str) -> Result<Option<ManifestRow>> {
    let row = sqlx::query_as::<_, ManifestRow>(
        "SELECT file_id, recipient_id, issuer_id, issuer_ed25519_pub, manifest_json, registered_at FROM manifests WHERE file_id = ?",
    )
    .bind(file_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn upsert_beacon(
    pool: &SqlitePool,
    token_id: &str,
    file_id: &str,
    recipient_id: &str,
    issuer_id: &str,
    kind: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO beacons (token_id, file_id, recipient_id, issuer_id, kind, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(token_id)
    .bind(file_id)
    .bind(recipient_id)
    .bind(issuer_id)
    .bind(kind)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_beacon(pool: &SqlitePool, token_id: &str) -> Result<Option<BeaconRow>> {
    let row = sqlx::query_as::<_, BeaconRow>(
        "SELECT token_id, file_id, recipient_id, issuer_id, kind, registered_at FROM beacons WHERE token_id = ?",
    )
    .bind(token_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn get_beacons_by_file(pool: &SqlitePool, file_id: &str) -> Result<Vec<BeaconRow>> {
    let rows = sqlx::query_as::<_, BeaconRow>(
        "SELECT token_id, file_id, recipient_id, issuer_id, kind, registered_at FROM beacons WHERE file_id = ?",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn upsert_watermark(
    pool: &SqlitePool,
    mark_id: &str,
    layer: &str,
    file_id: &str,
    recipient_id: &str,
    issuer_id: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO watermarks (mark_id, layer, file_id, recipient_id, issuer_id, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(mark_id)
    .bind(layer)
    .bind(file_id)
    .bind(recipient_id)
    .bind(issuer_id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_watermark(
    pool: &SqlitePool,
    mark_id: &str,
    layer: Option<&str>,
) -> Result<Option<WatermarkRow>> {
    let row = match layer {
        Some(l) => {
            sqlx::query_as::<_, WatermarkRow>(
                "SELECT mark_id, layer, file_id, recipient_id, issuer_id, registered_at FROM watermarks WHERE mark_id = ? AND layer = ?",
            )
            .bind(mark_id)
            .bind(l)
            .fetch_optional(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, WatermarkRow>(
                "SELECT mark_id, layer, file_id, recipient_id, issuer_id, registered_at FROM watermarks WHERE mark_id = ?",
            )
            .bind(mark_id)
            .fetch_optional(pool)
            .await?
        }
    };
    Ok(row)
}

pub async fn get_watermarks_by_file(pool: &SqlitePool, file_id: &str) -> Result<Vec<WatermarkRow>> {
    let rows = sqlx::query_as::<_, WatermarkRow>(
        "SELECT mark_id, layer, file_id, recipient_id, issuer_id, registered_at FROM watermarks WHERE file_id = ?",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn insert_event(
    pool: &SqlitePool,
    token_id: &str,
    file_id: Option<&str>,
    recipient_id: Option<&str>,
    issuer_id: Option<&str>,
    kind: &str,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
    extra: Option<&str>,
    timestamp: i64,
    qualified_timestamp: Option<&str>,
    tlog_index: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO events (token_id, file_id, recipient_id, issuer_id, kind, source_ip, user_agent, extra, timestamp, qualified_timestamp, tlog_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(token_id)
    .bind(file_id)
    .bind(recipient_id)
    .bind(issuer_id)
    .bind(kind)
    .bind(source_ip)
    .bind(user_agent)
    .bind(extra)
    .bind(timestamp)
    .bind(qualified_timestamp)
    .bind(tlog_index)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_recent_events(
    pool: &SqlitePool,
    file_id: &str,
    limit: i64,
) -> Result<Vec<EventRow>> {
    let rows = sqlx::query_as::<_, EventRow>(
        "SELECT id, token_id, file_id, recipient_id, issuer_id, kind, source_ip, user_agent, extra, timestamp, qualified_timestamp, tlog_index FROM events WHERE file_id = ? ORDER BY timestamp DESC LIMIT ?",
    )
    .bind(file_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_events_by_file(pool: &SqlitePool, file_id: &str) -> Result<Vec<EventRow>> {
    let rows = sqlx::query_as::<_, EventRow>(
        "SELECT id, token_id, file_id, recipient_id, issuer_id, kind, source_ip, user_agent, extra, timestamp, qualified_timestamp, tlog_index FROM events WHERE file_id = ? ORDER BY timestamp ASC",
    )
    .bind(file_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn upsert_corpus(
    pool: &SqlitePool,
    file_id: &str,
    hash_kind: &str,
    hash_value: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO corpus (file_id, hash_kind, hash_value, metadata, registered_at) VALUES (?, ?, ?, NULL, ?)",
    )
    .bind(file_id)
    .bind(hash_kind)
    .bind(hash_value)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn lookup_by_perceptual_hash(
    pool: &SqlitePool,
    hash_value: &str,
) -> Result<Option<(String, Option<String>, Option<String>)>> {
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT c.file_id, b.recipient_id, b.issuer_id FROM corpus c LEFT JOIN beacons b ON c.file_id = b.file_id WHERE c.hash_kind = 'perceptual' AND c.hash_value = ? LIMIT 1",
    )
    .bind(hash_value)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn get_semantic_candidates(
    pool: &SqlitePool,
    limit: i64,
    since: Option<i64>,
) -> Result<Vec<SemanticCandidateRow>> {
    let rows = match since {
        Some(since) => {
            sqlx::query_as::<_, SemanticCandidateRow>(
                "SELECT mark_id, file_id, recipient_id, registered_at FROM watermarks WHERE layer = 'L3_semantic' AND registered_at >= ? ORDER BY registered_at DESC LIMIT ?",
            )
            .bind(since)
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as::<_, SemanticCandidateRow>(
                "SELECT mark_id, file_id, recipient_id, registered_at FROM watermarks WHERE layer = 'L3_semantic' ORDER BY registered_at DESC LIMIT ?",
            )
            .bind(limit)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oversight_crypto::ClassicIdentity;
    use oversight_manifest::{Manifest, Recipient};
    use std::path::PathBuf;

    fn temp_dir(label: &str) -> PathBuf {
        let unique = format!(
            "oversight-registry-migrate-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    async fn seed_source(pool: &SqlitePool) {
        let (issuer_pub, manifest_json) = signed_manifest_json("file-1");
        upsert_manifest(
            pool,
            "file-1",
            "recipient-1",
            "issuer-1",
            &issuer_pub,
            &manifest_json,
            10,
        )
        .await
        .unwrap();
        upsert_beacon(
            pool,
            "token-1",
            "file-1",
            "recipient-1",
            "issuer-1",
            "dns",
            10,
        )
        .await
        .unwrap();
        upsert_watermark(
            pool,
            "mark-1",
            "L1_zero_width",
            "file-1",
            "recipient-1",
            "issuer-1",
            10,
        )
        .await
        .unwrap();
        insert_event(
            pool,
            "token-1",
            Some("file-1"),
            Some("recipient-1"),
            Some("issuer-1"),
            "dns",
            Some("198.51.100.10"),
            Some("agent"),
            Some(r#"{"qtype":"A"}"#),
            11,
            Some("2026-05-17T00:00:00Z"),
            Some(7),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO corpus (file_id, hash_kind, hash_value, metadata, registered_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind("file-1")
        .bind("perceptual")
        .bind("phash-1")
        .bind(r#"{"source":"fixture"}"#)
        .bind(12_i64)
        .execute(pool)
        .await
        .unwrap();
    }

    fn signed_manifest_json(file_id: &str) -> (String, String) {
        let issuer = ClassicIdentity::generate();
        let recipient = ClassicIdentity::generate();
        let mut manifest = Manifest::new(
            "fixture.txt",
            "ab".repeat(32),
            4096,
            "issuer-1",
            hex::encode(issuer.ed25519_pub),
            Recipient {
                recipient_id: "recipient-1".into(),
                x25519_pub: hex::encode(recipient.x25519_pub),
                ed25519_pub: None,
                p256_pub: None,
            },
            "https://registry.test",
            "text/plain",
            None,
            None,
            "GLOBAL",
        );
        manifest.file_id = file_id.into();
        manifest.sign(issuer.ed25519_priv.as_ref()).unwrap();
        (
            hex::encode(issuer.ed25519_pub),
            String::from_utf8(manifest.to_json().unwrap()).unwrap(),
        )
    }

    #[tokio::test]
    async fn migrate_from_sqlite_copies_python_registry_tables() {
        let source_dir = temp_dir("source");
        let dest_dir = temp_dir("dest");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&dest_dir).unwrap();
        let source_path = source_dir.join("registry.sqlite");
        let dest_path = dest_dir.join("registry.sqlite");

        let source_pool = create_pool(&source_path).await.unwrap();
        run_migrations(&source_pool).await.unwrap();
        seed_source(&source_pool).await;
        source_pool.close().await;

        let dest_pool = create_pool(&dest_path).await.unwrap();
        run_migrations(&dest_pool).await.unwrap();
        let report = migrate_from_sqlite(&dest_pool, &source_path, false)
            .await
            .unwrap();

        assert_eq!(report.manifests, 1);
        assert_eq!(report.beacons, 1);
        assert_eq!(report.watermarks, 1);
        assert_eq!(report.events, 1);
        assert_eq!(report.corpus, 1);

        assert!(get_manifest(&dest_pool, "file-1").await.unwrap().is_some());
        assert!(get_beacon(&dest_pool, "token-1").await.unwrap().is_some());
        assert!(get_watermark(&dest_pool, "mark-1", None)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            lookup_by_perceptual_hash(&dest_pool, "phash-1")
                .await
                .unwrap()
                .unwrap()
                .0,
            "file-1"
        );
        let event_row: (i64, Option<String>) =
            sqlx::query_as("SELECT id, extra FROM events WHERE token_id = ?")
                .bind("token-1")
                .fetch_one(&dest_pool)
                .await
                .unwrap();
        assert_eq!(event_row.0, 1);
        assert_eq!(event_row.1.as_deref(), Some(r#"{"qtype":"A"}"#));
        let corpus_metadata: (Option<String>,) =
            sqlx::query_as("SELECT metadata FROM corpus WHERE hash_value = ?")
                .bind("phash-1")
                .fetch_one(&dest_pool)
                .await
                .unwrap();
        assert_eq!(
            corpus_metadata.0.as_deref(),
            Some(r#"{"source":"fixture"}"#)
        );

        dest_pool.close().await;
        let _ = std::fs::remove_dir_all(source_dir);
        let _ = std::fs::remove_dir_all(dest_dir);
    }

    #[tokio::test]
    async fn migrate_from_sqlite_dry_run_only_counts_rows() {
        let source_dir = temp_dir("dry-source");
        let dest_dir = temp_dir("dry-dest");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&dest_dir).unwrap();
        let source_path = source_dir.join("registry.sqlite");
        let dest_path = dest_dir.join("registry.sqlite");

        let source_pool = create_pool(&source_path).await.unwrap();
        run_migrations(&source_pool).await.unwrap();
        seed_source(&source_pool).await;
        source_pool.close().await;

        let dest_pool = create_pool(&dest_path).await.unwrap();
        run_migrations(&dest_pool).await.unwrap();
        let report = migrate_from_sqlite(&dest_pool, &source_path, true)
            .await
            .unwrap();
        assert!(report.dry_run);
        assert_eq!(report.events, 1);
        assert!(get_manifest(&dest_pool, "file-1").await.unwrap().is_none());

        dest_pool.close().await;
        let _ = std::fs::remove_dir_all(source_dir);
        let _ = std::fs::remove_dir_all(dest_dir);
    }

    #[tokio::test]
    async fn validate_registry_integrity_accepts_clean_rows() {
        let dir = temp_dir("validate-clean");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("registry.sqlite");
        let pool = create_pool(&db_path).await.unwrap();
        run_migrations(&pool).await.unwrap();
        seed_source(&pool).await;

        let report = validate_registry_integrity(&pool, None).await.unwrap();
        assert!(report.ok);
        assert_eq!(report.counts.manifests, 1);
        assert_eq!(report.counts.beacons, 1);
        assert_eq!(report.malformed_manifest_json, 0);
        assert_eq!(report.invalid_manifest_signatures, 0);
        assert_eq!(report.malformed_event_extra_json, 0);
        assert_eq!(report.malformed_corpus_metadata_json, 0);
        assert_eq!(report.duplicate_event_tlog_indexes, 0);
        assert_eq!(report.negative_event_tlog_indexes, 0);
        assert_eq!(report.events_without_tlog_index, 0);
        assert_eq!(report.event_tlog_indexes_out_of_range, 0);
        assert_eq!(report.event_tlog_leaf_mismatches, 0);
        assert_eq!(report.tlog_size, None);

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn event_leaf_matching_accepts_dns_without_user_agent() {
        let event = EventRow {
            id: 1,
            token_id: "token-1".into(),
            file_id: Some("file-1".into()),
            recipient_id: Some("recipient-1".into()),
            issuer_id: Some("issuer-1".into()),
            kind: "dns".into(),
            source_ip: Some("198.51.100.10".into()),
            user_agent: Some(String::new()),
            extra: Some(r#"{"qname":"b.example","qtype":"A"}"#.into()),
            timestamp: 1,
            qualified_timestamp: Some("2026-05-24T00:00:00Z".into()),
            tlog_index: Some(0),
        };
        let leaf = serde_json::json!({
            "event": "beacon",
            "kind": "dns",
            "token_id": "token-1",
            "file_id": "file-1",
            "recipient_id": "recipient-1",
            "source_ip": "198.51.100.10",
            "qname": "b.example",
            "qtype": "A",
            "timestamp": "2026-05-24T00:00:00Z",
        });
        assert!(event_matches_tlog_leaf(&event, &leaf));
    }

    #[tokio::test]
    async fn validate_registry_integrity_reports_bad_rows() {
        let dir = temp_dir("validate-bad");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("registry.sqlite");
        let pool = create_pool(&db_path).await.unwrap();
        run_migrations(&pool).await.unwrap();
        seed_source(&pool).await;
        let tlog = oversight_tlog::TransparencyLog::open(dir.join("tlog")).unwrap();
        tlog.append_event(&serde_json::json!({
            "event": "beacon",
            "kind": "dns",
            "token_id": "different-token",
        }))
        .unwrap();

        sqlx::query(
            "INSERT INTO manifests (file_id, recipient_id, issuer_id, issuer_ed25519_pub, manifest_json, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind("bad-file")
        .bind("recipient-1")
        .bind("issuer-1")
        .bind("00")
        .bind("{")
        .bind(20_i64)
        .execute(&pool)
        .await
        .unwrap();
        upsert_beacon(&pool, "orphan-token", "missing-file", "r", "i", "dns", 21)
            .await
            .unwrap();
        upsert_watermark(&pool, "orphan-mark", "L1", "missing-file", "r", "i", 21)
            .await
            .unwrap();
        insert_event(
            &pool,
            "orphan-token",
            Some("missing-file"),
            Some("r"),
            Some("i"),
            "dns",
            None,
            None,
            Some("{"),
            21,
            None,
            Some(-1),
        )
        .await
        .unwrap();
        insert_event(
            &pool,
            "token-1",
            Some("file-1"),
            Some("recipient-1"),
            Some("issuer-1"),
            "dns",
            None,
            None,
            Some(r#"{"ok":true}"#),
            22,
            None,
            Some(7),
        )
        .await
        .unwrap();
        insert_event(
            &pool,
            "token-no-tlog",
            Some("file-1"),
            Some("recipient-1"),
            Some("issuer-1"),
            "dns",
            None,
            None,
            Some(r#"{"ok":true}"#),
            23,
            None,
            None,
        )
        .await
        .unwrap();
        insert_event(
            &pool,
            "token-mismatch",
            Some("file-1"),
            Some("recipient-1"),
            Some("issuer-1"),
            "dns",
            Some("127.0.0.1"),
            Some("agent"),
            Some(r#"{"qtype":"A"}"#),
            24,
            Some("2026-05-24T00:00:00Z"),
            Some(0),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO corpus (file_id, hash_kind, hash_value, metadata, registered_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind("missing-file")
        .bind("perceptual")
        .bind("phash-missing")
        .bind("{")
        .bind(21_i64)
        .execute(&pool)
        .await
        .unwrap();

        let report = validate_registry_integrity(&pool, Some(&tlog))
            .await
            .unwrap();
        assert!(!report.ok);
        assert_eq!(report.orphan_beacons, 1);
        assert_eq!(report.orphan_watermarks, 1);
        assert_eq!(report.orphan_events, 1);
        assert_eq!(report.orphan_corpus, 1);
        assert_eq!(report.malformed_manifest_json, 1);
        assert_eq!(report.malformed_event_extra_json, 1);
        assert_eq!(report.malformed_corpus_metadata_json, 1);
        assert_eq!(report.duplicate_event_tlog_indexes, 1);
        assert_eq!(report.negative_event_tlog_indexes, 1);
        assert_eq!(report.events_without_tlog_index, 1);
        assert_eq!(report.event_tlog_indexes_out_of_range, 2);
        assert_eq!(report.event_tlog_leaf_mismatches, 1);
        assert_eq!(report.tlog_size, Some(1));

        pool.close().await;
        let _ = std::fs::remove_dir_all(dir);
    }
}
