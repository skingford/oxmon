use crate::partition::PartitionManager;
use crate::{MetricQuery, StorageEngine};
use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricBatch, MetricDataPoint, Severity};
use std::collections::HashMap;
use std::path::Path;

pub struct SqliteStorageEngine {
    partitions: PartitionManager,
}

impl SqliteStorageEngine {
    pub fn new(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            partitions: PartitionManager::new(data_dir)?,
        })
    }
}

impl StorageEngine for SqliteStorageEngine {
    fn write_batch(&self, batch: &MetricBatch) -> Result<()> {
        let key = self.partitions.get_or_create(batch.timestamp)?;
        self.partitions.with_partition(&key, |conn| {
            let tx = conn.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT INTO metrics (timestamp, agent_id, metric_name, value, labels) VALUES (?1, ?2, ?3, ?4, ?5)",
                )?;
                for dp in &batch.data_points {
                    let labels_json = serde_json::to_string(&dp.labels)?;
                    stmt.execute(rusqlite::params![
                        dp.timestamp.timestamp_millis(),
                        &dp.agent_id,
                        &dp.metric_name,
                        dp.value,
                        labels_json,
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    fn query(&self, query: &MetricQuery) -> Result<Vec<MetricDataPoint>> {
        let keys = self.partitions.partitions_in_range(query.from, query.to)?;
        let mut results = Vec::new();
        let from_ms = query.from.timestamp_millis();
        let to_ms = query.to.timestamp_millis();

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT timestamp, agent_id, metric_name, value, labels FROM metrics
                     WHERE agent_id = ?1 AND metric_name = ?2 AND timestamp >= ?3 AND timestamp <= ?4
                     ORDER BY timestamp ASC",
                )?;
                let rows = stmt.query_map(
                    rusqlite::params![&query.agent_id, &query.metric_name, from_ms, to_ms],
                    |row| {
                        let ts_ms: i64 = row.get(0)?;
                        let agent_id: String = row.get(1)?;
                        let metric_name: String = row.get(2)?;
                        let value: f64 = row.get(3)?;
                        let labels_str: String = row.get(4)?;
                        Ok((ts_ms, agent_id, metric_name, value, labels_str))
                    },
                )?;
                for row in rows {
                    let (ts_ms, agent_id, metric_name, value, labels_str) = row?;
                    let timestamp = DateTime::from_timestamp_millis(ts_ms)
                        .unwrap_or_default();
                    let labels: HashMap<String, String> =
                        serde_json::from_str(&labels_str).unwrap_or_default();
                    results.push(MetricDataPoint {
                        timestamp,
                        agent_id,
                        metric_name,
                        value,
                        labels,
                    });
                }
                Ok(())
            })?;
        }

        results.sort_by_key(|dp| dp.timestamp);
        Ok(results)
    }

    fn cleanup(&self, retention_days: u32) -> Result<u32> {
        self.partitions.cleanup_older_than(retention_days)
    }

    fn write_alert_event(&self, event: &AlertEvent) -> Result<()> {
        let key = self.partitions.get_or_create(event.timestamp)?;
        self.partitions.with_partition(&key, |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO alert_events (id, rule_id, agent_id, metric_name, severity, message, value, threshold, timestamp, predicted_breach)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    &event.id,
                    &event.rule_id,
                    &event.agent_id,
                    &event.metric_name,
                    event.severity.to_string(),
                    &event.message,
                    event.value,
                    event.threshold,
                    event.timestamp.timestamp_millis(),
                    event.predicted_breach.map(|t| t.timestamp_millis()),
                ],
            )?;
            Ok(())
        })
    }

    fn query_alert_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        severity: Option<&str>,
        agent_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AlertEvent>> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let mut results = Vec::new();
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut sql = String::from(
                    "SELECT id, rule_id, agent_id, metric_name, severity, message, value, threshold, timestamp, predicted_breach
                     FROM alert_events WHERE timestamp >= ?1 AND timestamp <= ?2",
                );
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![
                    Box::new(from_ms),
                    Box::new(to_ms),
                ];

                if let Some(sev) = severity {
                    sql.push_str(" AND severity = ?3");
                    params.push(Box::new(sev.to_string()));
                }
                if let Some(aid) = agent_id {
                    let idx = params.len() + 1;
                    sql.push_str(&format!(" AND agent_id = ?{idx}"));
                    params.push(Box::new(aid.to_string()));
                }

                sql.push_str(" ORDER BY timestamp DESC");

                let mut stmt = conn.prepare(&sql)?;
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    let ts_ms: i64 = row.get(8)?;
                    let predicted_ms: Option<i64> = row.get(9)?;
                    let sev_str: String = row.get(4)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        sev_str,
                        row.get::<_, String>(5)?,
                        row.get::<_, f64>(6)?,
                        row.get::<_, f64>(7)?,
                        ts_ms,
                        predicted_ms,
                    ))
                })?;

                for row in rows {
                    let (id, rule_id, agent_id, metric_name, sev_str, message, value, threshold, ts_ms, predicted_ms) = row?;
                    let timestamp = DateTime::from_timestamp_millis(ts_ms)
                        .unwrap_or_default();
                    let predicted_breach = predicted_ms
                        .and_then(DateTime::from_timestamp_millis);
                    let severity_val: Severity = sev_str.parse().unwrap_or(Severity::Info);
                    results.push(AlertEvent {
                        id,
                        rule_id,
                        agent_id,
                        metric_name,
                        severity: severity_val,
                        message,
                        value,
                        threshold,
                        timestamp,
                        predicted_breach,
                    });
                }
                Ok(())
            })?;
        }

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        let results = results.into_iter().skip(offset).take(limit).collect();
        Ok(results)
    }
}
