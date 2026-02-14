use crate::PartitionInfo;
use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
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
    rule_name TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    value REAL NOT NULL,
    threshold REAL NOT NULL,
    timestamp INTEGER NOT NULL,
    predicted_breach INTEGER,
    labels TEXT NOT NULL,
    first_triggered_at INTEGER,
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

    /// Lock the connections map, recovering from a poisoned Mutex if necessary.
    fn lock_connections(&self) -> MutexGuard<'_, HashMap<String, Connection>> {
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn partition_key(ts: DateTime<Utc>) -> String {
        ts.format("%Y-%m-%d").to_string()
    }

    fn partition_path(&self, key: &str) -> PathBuf {
        self.data_dir.join(format!("{key}.db"))
    }

    pub fn get_or_create(&self, ts: DateTime<Utc>) -> Result<String> {
        let key = Self::partition_key(ts);
        let mut conns = self.lock_connections();
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
        let conns = self.lock_connections();
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
                let mut conns = self.lock_connections();
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

        // Collect expired partition dates first
        let mut expired_dates: Vec<(String, PathBuf)> = Vec::new();
        let entries = std::fs::read_dir(&self.data_dir)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(date_str) = name.strip_suffix(".db") {
                if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                    if date < cutoff_date {
                        expired_dates.push((date_str.to_string(), entry.path()));
                    }
                }
            }
        }

        // Delete expired partitions (best-effort: log errors, don't abort)
        for (date_str, db_path) in &expired_dates {
            // Remove from connection cache (drops the Connection, triggering WAL checkpoint)
            {
                let mut conns = self.lock_connections();
                conns.remove(date_str.as_str());
            }

            // Remove .db file and associated WAL/SHM files
            if let Err(e) = std::fs::remove_file(db_path) {
                tracing::error!(partition = %date_str, error = %e, "Failed to remove partition file");
                continue;
            }
            // Clean up SQLite WAL mode auxiliary files
            let wal_path = self.data_dir.join(format!("{date_str}.db-wal"));
            let shm_path = self.data_dir.join(format!("{date_str}.db-shm"));
            if wal_path.exists() {
                if let Err(e) = std::fs::remove_file(&wal_path) {
                    tracing::warn!(path = %wal_path.display(), error = %e, "Failed to remove WAL file");
                }
            }
            if shm_path.exists() {
                if let Err(e) = std::fs::remove_file(&shm_path) {
                    tracing::warn!(path = %shm_path.display(), error = %e, "Failed to remove SHM file");
                }
            }

            tracing::info!(partition = %date_str, "Removed expired partition");
            removed += 1;
        }

        Ok(removed)
    }

    /// Returns information about all existing partitions on disk.
    pub fn list_partition_info(&self) -> Result<Vec<PartitionInfo>> {
        let mut infos = Vec::new();
        let entries = std::fs::read_dir(&self.data_dir)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(date_str) = name.strip_suffix(".db") {
                if NaiveDate::parse_from_str(date_str, "%Y-%m-%d").is_ok() {
                    let metadata = entry.metadata()?;
                    infos.push(PartitionInfo {
                        date: date_str.to_string(),
                        size_bytes: metadata.len(),
                        path: entry.path().to_string_lossy().to_string(),
                    });
                }
            }
        }
        infos.sort_by(|a, b| a.date.cmp(&b.date));
        Ok(infos)
    }

    /// Updates the status of an alert event across all partitions.
    /// Returns true if the event was found and updated.
    pub fn update_alert_status(&self, event_id: &str, status: &str) -> Result<bool> {
        let conns = self.lock_connections();
        let now = chrono::Utc::now().timestamp();
        for conn in conns.values() {
            let updated = conn.execute(
                "UPDATE alert_events SET status = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![status, now, event_id],
            )?;
            if updated > 0 {
                return Ok(true);
            }
        }
        // Also scan disk for partitions not yet loaded
        drop(conns);

        let entries = std::fs::read_dir(&self.data_dir)?;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(date_str) = name.strip_suffix(".db") {
                if NaiveDate::parse_from_str(date_str, "%Y-%m-%d").is_ok() {
                    let mut conns = self.lock_connections();
                    if !conns.contains_key(date_str) {
                        let conn = Connection::open(entry.path())?;
                        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
                        migrate_partition(&conn);
                        conns.insert(date_str.to_string(), conn);
                    }
                    let conn = conns.get(date_str).unwrap();
                    let updated = conn.execute(
                        "UPDATE alert_events SET status = ?1, updated_at = ?2 WHERE id = ?3",
                        rusqlite::params![status, now, event_id],
                    )?;
                    if updated > 0 {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

/// Migrate old partition schemas by adding missing columns.
/// Uses ALTER TABLE ADD COLUMN which is a no-op if the column already exists (errors are ignored).
fn migrate_partition(conn: &Connection) {
    // metrics table: add id, created_at, updated_at
    let _ = conn.execute_batch("ALTER TABLE metrics ADD COLUMN id TEXT;");
    let _ = conn.execute_batch("ALTER TABLE metrics ADD COLUMN created_at INTEGER;");
    let _ = conn.execute_batch("ALTER TABLE metrics ADD COLUMN updated_at INTEGER;");
    // alert_events table: add created_at, updated_at, status, rule_name, labels, first_triggered_at
    let _ = conn.execute_batch("ALTER TABLE alert_events ADD COLUMN created_at INTEGER;");
    let _ = conn.execute_batch("ALTER TABLE alert_events ADD COLUMN updated_at INTEGER;");
    let _ = conn.execute_batch("ALTER TABLE alert_events ADD COLUMN status TEXT DEFAULT 'open';");
    let _ = conn
        .execute_batch("ALTER TABLE alert_events ADD COLUMN rule_name TEXT NOT NULL DEFAULT '';");
    let _ = conn
        .execute_batch("ALTER TABLE alert_events ADD COLUMN labels TEXT NOT NULL DEFAULT '{}';");
    let _ = conn.execute_batch("ALTER TABLE alert_events ADD COLUMN first_triggered_at INTEGER;");
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tempfile::TempDir;

    #[test]
    fn test_cleanup_removes_expired_partitions_and_wal_files() {
        let tmp = TempDir::new().unwrap();
        let pm = PartitionManager::new(tmp.path()).unwrap();

        // Create a partition 10 days ago (should be cleaned with retention_days=7)
        let old_ts = Utc::now() - Duration::days(10);
        let old_key = pm.get_or_create(old_ts).unwrap();
        let old_db = tmp.path().join(format!("{old_key}.db"));

        // Create today's partition (should NOT be cleaned)
        let today_key = pm.get_or_create(Utc::now()).unwrap();
        let today_db = tmp.path().join(format!("{today_key}.db"));

        // Verify both partitions exist
        assert!(old_db.exists(), "old partition should exist");
        assert!(today_db.exists(), "today partition should exist");

        // Simulate WAL/SHM files for the old partition (SQLite WAL mode creates these)
        let old_wal = tmp.path().join(format!("{old_key}.db-wal"));
        let old_shm = tmp.path().join(format!("{old_key}.db-shm"));
        std::fs::write(&old_wal, b"wal data").unwrap();
        std::fs::write(&old_shm, b"shm data").unwrap();

        // Run cleanup with 7-day retention
        let removed = pm.cleanup_older_than(7).unwrap();

        assert_eq!(removed, 1);
        assert!(!old_db.exists(), "old .db should be deleted");
        assert!(!old_wal.exists(), "old .db-wal should be deleted");
        assert!(!old_shm.exists(), "old .db-shm should be deleted");
        assert!(today_db.exists(), "today partition should still exist");
    }

    #[test]
    fn test_cleanup_keeps_recent_partitions() {
        let tmp = TempDir::new().unwrap();
        let pm = PartitionManager::new(tmp.path()).unwrap();

        // Create partitions for the last 3 days
        for i in 0..3 {
            let ts = Utc::now() - Duration::days(i);
            pm.get_or_create(ts).unwrap();
        }

        let removed = pm.cleanup_older_than(7).unwrap();
        assert_eq!(removed, 0);
    }
}
