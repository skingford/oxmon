use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing;

const METRICS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS metrics (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    labels TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_agent_metric_time
    ON metrics(agent_id, metric_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_time
    ON metrics(timestamp);
";

const ALERTS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS alert_events (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    value REAL NOT NULL,
    threshold REAL NOT NULL,
    timestamp INTEGER NOT NULL,
    predicted_breach INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alert_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alert_events(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alert_events(agent_id);
";

pub struct PartitionManager {
    data_dir: PathBuf,
    connections: Mutex<HashMap<String, Connection>>,
}

impl PartitionManager {
    pub fn new(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            connections: Mutex::new(HashMap::new()),
        })
    }

    fn partition_key(ts: DateTime<Utc>) -> String {
        ts.format("%Y-%m-%d").to_string()
    }

    fn partition_path(&self, key: &str) -> PathBuf {
        self.data_dir.join(format!("{key}.db"))
    }

    pub fn get_or_create(&self, ts: DateTime<Utc>) -> Result<String> {
        let key = Self::partition_key(ts);
        let mut conns = self.connections.lock().unwrap();
        if !conns.contains_key(&key) {
            let path = self.partition_path(&key);
            let conn = Connection::open(&path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
            conn.execute_batch(METRICS_SCHEMA)?;
            conn.execute_batch(ALERTS_SCHEMA)?;
            migrate_partition(&conn);
            tracing::info!(partition = %key, "Created new partition");
            conns.insert(key.clone(), conn);
        }
        Ok(key)
    }

    pub fn with_partition<F, R>(&self, key: &str, f: F) -> Result<R>
    where
        F: FnOnce(&Connection) -> Result<R>,
    {
        let conns = self.connections.lock().unwrap();
        let conn = conns
            .get(key)
            .ok_or_else(|| anyhow::anyhow!("Partition {key} not found"))?;
        f(conn)
    }

    pub fn partitions_in_range(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<String>> {
        let from_date = from.date_naive();
        let to_date = to.date_naive();
        let mut keys = Vec::new();
        let mut date = from_date;
        while date <= to_date {
            let key = date.format("%Y-%m-%d").to_string();
            let path = self.partition_path(&key);
            if path.exists() {
                // Ensure it's loaded
                let mut conns = self.connections.lock().unwrap();
                if !conns.contains_key(&key) {
                    let conn = Connection::open(&path)?;
                    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
                    migrate_partition(&conn);
                    conns.insert(key.clone(), conn);
                }
                keys.push(key);
            }
            date = date.succ_opt().unwrap_or(date);
        }
        Ok(keys)
    }

    pub fn cleanup_older_than(&self, retention_days: u32) -> Result<u32> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_date = cutoff.date_naive();
        let mut removed = 0u32;

        let entries = std::fs::read_dir(&self.data_dir)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(date_str) = name.strip_suffix(".db") {
                if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                    if date < cutoff_date {
                        // Remove from connection cache
                        {
                            let mut conns = self.connections.lock().unwrap();
                            conns.remove(date_str);
                        }
                        std::fs::remove_file(entry.path())?;
                        tracing::info!(partition = %date_str, "Removed expired partition");
                        removed += 1;
                    }
                }
            }
        }

        Ok(removed)
    }
}

/// Migrate old partition schemas by adding missing columns.
/// Uses ALTER TABLE ADD COLUMN which is a no-op if the column already exists (errors are ignored).
fn migrate_partition(conn: &Connection) {
    // metrics table: add id, created_at, updated_at
    let _ = conn.execute_batch("ALTER TABLE metrics ADD COLUMN id TEXT;");
    let _ = conn.execute_batch("ALTER TABLE metrics ADD COLUMN created_at INTEGER;");
    let _ = conn.execute_batch("ALTER TABLE metrics ADD COLUMN updated_at INTEGER;");
    // alert_events table: add created_at, updated_at
    let _ = conn.execute_batch("ALTER TABLE alert_events ADD COLUMN created_at INTEGER;");
    let _ = conn.execute_batch("ALTER TABLE alert_events ADD COLUMN updated_at INTEGER;");
}
