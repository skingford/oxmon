use crate::partition::PartitionManager;
use crate::{AlertSummary, MetricQuery, MetricSummary, PartitionInfo, StorageEngine};
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
                    "INSERT INTO metrics (id, timestamp, agent_id, metric_name, value, labels, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )?;
                for dp in &batch.data_points {
                    let labels_json = serde_json::to_string(&dp.labels)?;
                    let now = chrono::Utc::now().timestamp();
                    stmt.execute(rusqlite::params![
                        dp.id,
                        dp.timestamp.timestamp_millis(),
                        &dp.agent_id,
                        &dp.metric_name,
                        dp.value,
                        labels_json,
                        now,
                        now,
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
                    "SELECT id, timestamp, agent_id, metric_name, value, labels, created_at, updated_at FROM metrics
                     WHERE agent_id = ?1 AND metric_name = ?2 AND timestamp >= ?3 AND timestamp <= ?4
                     ORDER BY timestamp ASC",
                )?;
                let rows = stmt.query_map(
                    rusqlite::params![&query.agent_id, &query.metric_name, from_ms, to_ms],
                    |row| {
                        let id: String = row.get(0)?;
                        let ts_ms: i64 = row.get(1)?;
                        let agent_id: String = row.get(2)?;
                        let metric_name: String = row.get(3)?;
                        let value: f64 = row.get(4)?;
                        let labels_str: String = row.get(5)?;
                        let created_at: i64 = row.get(6)?;
                        let updated_at: i64 = row.get(7)?;
                        Ok((id, ts_ms, agent_id, metric_name, value, labels_str, created_at, updated_at))
                    },
                )?;
                for row in rows {
                    let (id, ts_ms, agent_id, metric_name, value, labels_str, created_at, updated_at) = row?;
                    let timestamp = DateTime::from_timestamp_millis(ts_ms)
                        .unwrap_or_default();
                    let labels: HashMap<String, String> =
                        serde_json::from_str(&labels_str).unwrap_or_default();
                    results.push(MetricDataPoint {
                        id,
                        timestamp,
                        agent_id,
                        metric_name,
                        value,
                        labels,
                        created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
                        updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_default(),
                    });
                }
                Ok(())
            })?;
        }

        results.sort_by_key(|dp| dp.timestamp);
        Ok(results)
    }

    fn query_metrics_paginated(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MetricDataPoint>> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let mut results = Vec::new();
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut sql = String::from(
                    "SELECT id, timestamp, agent_id, metric_name, value, labels, created_at, updated_at
                     FROM metrics WHERE timestamp >= ?1 AND timestamp <= ?2",
                );
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![
                    Box::new(from_ms),
                    Box::new(to_ms),
                ];

                if let Some(agent) = agent_id {
                    let idx = params.len() + 1;
                    sql.push_str(&format!(" AND agent_id = ?{idx}"));
                    params.push(Box::new(agent.to_string()));
                }

                if let Some(metric) = metric_name {
                    let idx = params.len() + 1;
                    sql.push_str(&format!(" AND metric_name = ?{idx}"));
                    params.push(Box::new(metric.to_string()));
                }

                sql.push_str(" ORDER BY created_at DESC, timestamp DESC");

                let mut stmt = conn.prepare(&sql)?;
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    let id: String = row.get(0)?;
                    let ts_ms: i64 = row.get(1)?;
                    let agent_id: String = row.get(2)?;
                    let metric_name: String = row.get(3)?;
                    let value: f64 = row.get(4)?;
                    let labels_str: String = row.get(5)?;
                    let created_at: i64 = row.get(6)?;
                    let updated_at: i64 = row.get(7)?;
                    Ok((id, ts_ms, agent_id, metric_name, value, labels_str, created_at, updated_at))
                })?;

                for row in rows {
                    let (id, ts_ms, row_agent_id, row_metric_name, value, labels_str, created_at, updated_at) = row?;
                    let timestamp = DateTime::from_timestamp_millis(ts_ms)
                        .unwrap_or_default();
                    let labels: HashMap<String, String> =
                        serde_json::from_str(&labels_str).unwrap_or_default();
                    results.push(MetricDataPoint {
                        id,
                        timestamp,
                        agent_id: row_agent_id,
                        metric_name: row_metric_name,
                        value,
                        labels,
                        created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
                        updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_default(),
                    });
                }

                Ok(())
            })?;
        }

        results.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.timestamp.cmp(&a.timestamp))
        });
        let results = results.into_iter().skip(offset).take(limit).collect();
        Ok(results)
    }

    fn cleanup(&self, retention_days: u32) -> Result<u32> {
        self.partitions.cleanup_older_than(retention_days)
    }

    fn write_alert_event(&self, event: &AlertEvent) -> Result<()> {
        let key = self.partitions.get_or_create(event.timestamp)?;
        self.partitions.with_partition(&key, |conn| {
            let now = chrono::Utc::now().timestamp();
            let labels_json = serde_json::to_string(&event.labels)?;
            conn.execute(
                "INSERT OR REPLACE INTO alert_events (id, rule_id, rule_name, agent_id, metric_name, severity, message, value, threshold, timestamp, predicted_breach, labels, first_triggered_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                rusqlite::params![
                    &event.id,
                    &event.rule_id,
                    &event.rule_name,
                    &event.agent_id,
                    &event.metric_name,
                    event.severity.to_string(),
                    &event.message,
                    event.value,
                    event.threshold,
                    event.timestamp.timestamp_millis(),
                    event.predicted_breach.map(|t| t.timestamp_millis()),
                    labels_json,
                    event.first_triggered_at.map(|t| t.timestamp_millis()),
                    now,
                    now,
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
                    "SELECT id, rule_id, agent_id, metric_name, severity, message, value, threshold, timestamp, predicted_breach, created_at, updated_at, status, rule_name, labels, first_triggered_at
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

                sql.push_str(" ORDER BY created_at DESC");

                let mut stmt = conn.prepare(&sql)?;
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let rows = stmt.query_map(param_refs.as_slice(), |row| {
                    let ts_ms: i64 = row.get(8)?;
                    let predicted_ms: Option<i64> = row.get(9)?;
                    let sev_str: String = row.get(4)?;
                    let created_at: i64 = row.get(10)?;
                    let updated_at: i64 = row.get(11)?;
                    let status_str: Option<String> = row.get(12)?;
                    let rule_name: String = row.get(13)?;
                    let labels_str: String = row.get(14)?;
                    let first_triggered_ms: Option<i64> = row.get(15)?;
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
                        created_at,
                        updated_at,
                        status_str,
                        rule_name,
                        labels_str,
                        first_triggered_ms,
                    ))
                })?;

                for row in rows {
                    let (id, rule_id, agent_id, metric_name, sev_str, message, value, threshold, ts_ms, predicted_ms, created_at, updated_at, status_str, rule_name, labels_str, first_triggered_ms) = row?;
                    let timestamp = DateTime::from_timestamp_millis(ts_ms)
                        .unwrap_or_default();
                    let predicted_breach = predicted_ms
                        .and_then(DateTime::from_timestamp_millis);
                    let severity_val: Severity = sev_str.parse().unwrap_or(Severity::Info);
                    let status = match status_str.as_deref() {
                        Some("acknowledged") => 2,
                        Some("resolved") => 3,
                        _ => 1,
                    };
                    let labels: HashMap<String, String> = serde_json::from_str(&labels_str)
                        .unwrap_or_default();
                    let first_triggered_at = first_triggered_ms
                        .and_then(DateTime::from_timestamp_millis);
                    results.push(AlertEvent {
                        id,
                        rule_id,
                        rule_name,
                        agent_id,
                        metric_name,
                        severity: severity_val,
                        message,
                        value,
                        threshold,
                        timestamp,
                        predicted_breach,
                        status,
                        labels,
                        first_triggered_at,
                        created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
                        updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_default(),
                    });
                }
                Ok(())
            })?;
        }

        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let results = results.into_iter().skip(offset).take(limit).collect();
        Ok(results)
    }

    fn query_distinct_metric_names(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();
        let mut names = std::collections::HashSet::new();

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT DISTINCT metric_name FROM metrics WHERE timestamp >= ?1 AND timestamp <= ?2",
                )?;
                let rows = stmt.query_map(rusqlite::params![from_ms, to_ms], |row| {
                    row.get::<_, String>(0)
                })?;
                for row in rows {
                    names.insert(row?);
                }
                Ok(())
            })?;
        }

        let mut result: Vec<String> = names.into_iter().collect();
        result.sort();
        let result = result.into_iter().skip(offset).take(limit).collect();
        Ok(result)
    }

    fn query_distinct_agent_ids(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();
        let mut ids = std::collections::HashSet::new();

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT DISTINCT agent_id FROM metrics WHERE timestamp >= ?1 AND timestamp <= ?2",
                )?;
                let rows = stmt.query_map(rusqlite::params![from_ms, to_ms], |row| {
                    row.get::<_, String>(0)
                })?;
                for row in rows {
                    ids.insert(row?);
                }
                Ok(())
            })?;
        }

        let mut result: Vec<String> = ids.into_iter().collect();
        result.sort();
        let result = result.into_iter().skip(offset).take(limit).collect();
        Ok(result)
    }

    fn query_metric_summary(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: &str,
        metric_name: &str,
    ) -> Result<MetricSummary> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let mut total_sum: f64 = 0.0;
        let mut total_count: u64 = 0;
        let mut global_min: f64 = f64::MAX;
        let mut global_max: f64 = f64::MIN;

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT MIN(value), MAX(value), AVG(value), COUNT(*) FROM metrics
                     WHERE agent_id = ?1 AND metric_name = ?2 AND timestamp >= ?3 AND timestamp <= ?4",
                )?;
                let row = stmt.query_row(
                    rusqlite::params![agent_id, metric_name, from_ms, to_ms],
                    |row| {
                        Ok((
                            row.get::<_, Option<f64>>(0)?,
                            row.get::<_, Option<f64>>(1)?,
                            row.get::<_, Option<f64>>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )?;
                let (min_val, max_val, avg_val, count) = row;
                if count > 0 {
                    if let Some(mn) = min_val {
                        global_min = global_min.min(mn);
                    }
                    if let Some(mx) = max_val {
                        global_max = global_max.max(mx);
                    }
                    if let Some(av) = avg_val {
                        total_sum += av * count as f64;
                    }
                    total_count += count as u64;
                }
                Ok(())
            })?;
        }

        Ok(MetricSummary {
            min: if total_count > 0 { global_min } else { 0.0 },
            max: if total_count > 0 { global_max } else { 0.0 },
            avg: if total_count > 0 {
                total_sum / total_count as f64
            } else {
                0.0
            },
            count: total_count,
        })
    }

    fn query_alert_summary(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<AlertSummary> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let mut total: u64 = 0;
        let mut by_severity: HashMap<String, u64> = HashMap::new();
        let mut by_rule: HashMap<String, u64> = HashMap::new();
        let mut by_agent: HashMap<String, u64> = HashMap::new();
        let mut by_metric: HashMap<String, u64> = HashMap::new();
        let mut active_count: u64 = 0;
        let mut recovered_count: u64 = 0;

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT severity, rule_id, agent_id, metric_name, status, COUNT(*) FROM alert_events
                     WHERE timestamp >= ?1 AND timestamp <= ?2
                     GROUP BY severity, rule_id, agent_id, metric_name, status",
                )?;
                let rows = stmt.query_map(rusqlite::params![from_ms, to_ms], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })?;
                for row in rows {
                    let (sev, rule, agent, metric, status, count) = row?;
                    let count = count as u64;
                    total += count;
                    *by_severity.entry(sev).or_insert(0) += count;
                    *by_rule.entry(rule).or_insert(0) += count;
                    *by_agent.entry(agent).or_insert(0) += count;
                    *by_metric.entry(metric).or_insert(0) += count;
                    match status.as_deref() {
                        Some("resolved") => recovered_count += count,
                        _ => active_count += count,
                    }
                }
                Ok(())
            })?;
        }

        Ok(AlertSummary {
            total,
            by_severity,
            by_rule,
            by_agent,
            by_metric,
            active_count,
            recovered_count,
        })
    }

    fn list_partitions(&self) -> Result<Vec<PartitionInfo>> {
        self.partitions.list_partition_info()
    }

    fn acknowledge_alert(&self, event_id: &str) -> Result<bool> {
        self.partitions
            .update_alert_status(event_id, "acknowledged")
    }

    fn resolve_alert(&self, event_id: &str) -> Result<bool> {
        self.partitions.update_alert_status(event_id, "resolved")
    }

    fn get_alert_event_by_id(&self, event_id: &str) -> Result<Option<AlertEvent>> {
        // Search last 30 days for the alert event
        let to = Utc::now();
        let from = to - chrono::Duration::days(30);
        let keys = self.partitions.partitions_in_range(from, to)?;

        for key in keys {
            let found = self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, rule_id, agent_id, metric_name, severity, message, value, threshold, timestamp, predicted_breach, created_at, updated_at, status, rule_name, labels, first_triggered_at
                     FROM alert_events WHERE id = ?1",
                )?;
                let row = stmt.query_row(rusqlite::params![event_id], |row| {
                    let ts_ms: i64 = row.get(8)?;
                    let predicted_ms: Option<i64> = row.get(9)?;
                    let sev_str: String = row.get(4)?;
                    let created_at: i64 = row.get(10)?;
                    let updated_at: i64 = row.get(11)?;
                    let status_str: Option<String> = row.get(12)?;
                    let rule_name: String = row.get(13)?;
                    let labels_str: String = row.get(14)?;
                    let first_triggered_ms: Option<i64> = row.get(15)?;

                    let timestamp = DateTime::from_timestamp_millis(ts_ms).unwrap_or_default();
                    let predicted_breach = predicted_ms.and_then(DateTime::from_timestamp_millis);
                    let severity_val: Severity = sev_str.parse().unwrap_or(Severity::Info);
                    let status = match status_str.as_deref() {
                        Some("acknowledged") => 2,
                        Some("resolved") => 3,
                        _ => 1,
                    };
                    let labels: std::collections::HashMap<String, String> =
                        serde_json::from_str(&labels_str).unwrap_or_default();
                    let first_triggered_at =
                        first_triggered_ms.and_then(DateTime::from_timestamp_millis);

                    Ok(AlertEvent {
                        id: row.get(0)?,
                        rule_id: row.get(1)?,
                        agent_id: row.get(2)?,
                        metric_name: row.get(3)?,
                        severity: severity_val,
                        message: row.get(5)?,
                        value: row.get(6)?,
                        threshold: row.get(7)?,
                        timestamp,
                        predicted_breach,
                        created_at: DateTime::from_timestamp_millis(created_at).unwrap_or_default(),
                        updated_at: DateTime::from_timestamp_millis(updated_at).unwrap_or_default(),
                        status,
                        rule_name,
                        labels,
                        first_triggered_at,
                    })
                });

                match row {
                    Ok(event) => Ok(Some(event)),
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })?;

            if found.is_some() {
                return Ok(found);
            }
        }

        Ok(None)
    }

    fn query_active_alerts(&self, limit: usize, offset: usize) -> Result<Vec<AlertEvent>> {
        // Query last 7 days for active alerts
        let to = Utc::now();
        let from = to - chrono::Duration::days(7);
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();
        let mut results = Vec::new();

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, rule_id, agent_id, metric_name, severity, message, value, threshold, timestamp, predicted_breach, created_at, updated_at, status, rule_name, labels, first_triggered_at
                     FROM alert_events
                     WHERE timestamp >= ?1 AND timestamp <= ?2
                       AND (status IS NULL OR status NOT IN ('resolved'))
                     ORDER BY created_at DESC",
                )?;
                let rows = stmt.query_map(rusqlite::params![from_ms, to_ms], |row| {
                    let ts_ms: i64 = row.get(8)?;
                    let predicted_ms: Option<i64> = row.get(9)?;
                    let sev_str: String = row.get(4)?;
                    let created_at: i64 = row.get(10)?;
                    let updated_at: i64 = row.get(11)?;
                    let status_str: Option<String> = row.get(12)?;
                    let rule_name: String = row.get(13)?;
                    let labels_str: String = row.get(14)?;
                    let first_triggered_ms: Option<i64> = row.get(15)?;
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
                        created_at,
                        updated_at,
                        status_str,
                        rule_name,
                        labels_str,
                        first_triggered_ms,
                    ))
                })?;
                for row in rows {
                    let (id, rule_id, agent_id, metric_name, sev_str, message, value, threshold, ts_ms, predicted_ms, created_at, updated_at, status_str, rule_name, labels_str, first_triggered_ms) = row?;
                    let timestamp = DateTime::from_timestamp_millis(ts_ms).unwrap_or_default();
                    let predicted_breach = predicted_ms.and_then(DateTime::from_timestamp_millis);
                    let severity_val: Severity = sev_str.parse().unwrap_or(Severity::Info);
                    let status = match status_str.as_deref() {
                        Some("acknowledged") => 2,
                        Some("resolved") => 3,
                        _ => 1,
                    };
                    let labels: HashMap<String, String> = serde_json::from_str(&labels_str)
                        .unwrap_or_default();
                    let first_triggered_at = first_triggered_ms
                        .and_then(DateTime::from_timestamp_millis);
                    results.push(AlertEvent {
                        id, rule_id, rule_name, agent_id, metric_name,
                        severity: severity_val, message, value, threshold, timestamp,
                        predicted_breach, status, labels, first_triggered_at,
                        created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
                        updated_at: DateTime::from_timestamp(updated_at, 0).unwrap_or_default(),
                    });
                }
                Ok(())
            })?;
        }

        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let results = results.into_iter().skip(offset).take(limit).collect();
        Ok(results)
    }

    fn count_metrics(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
    ) -> Result<u64> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();
        let mut total: u64 = 0;

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut sql = String::from(
                    "SELECT COUNT(*) FROM metrics WHERE timestamp >= ?1 AND timestamp <= ?2",
                );
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> =
                    vec![Box::new(from_ms), Box::new(to_ms)];
                if let Some(agent) = agent_id {
                    let idx = params.len() + 1;
                    sql.push_str(&format!(" AND agent_id = ?{idx}"));
                    params.push(Box::new(agent.to_string()));
                }
                if let Some(metric) = metric_name {
                    let idx = params.len() + 1;
                    sql.push_str(&format!(" AND metric_name = ?{idx}"));
                    params.push(Box::new(metric.to_string()));
                }
                let mut stmt = conn.prepare(&sql)?;
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let count: i64 = stmt.query_row(param_refs.as_slice(), |row| row.get(0))?;
                total += count as u64;
                Ok(())
            })?;
        }
        Ok(total)
    }

    fn count_alert_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        severity: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<u64> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();
        let mut total: u64 = 0;

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut sql = String::from(
                    "SELECT COUNT(*) FROM alert_events WHERE timestamp >= ?1 AND timestamp <= ?2",
                );
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> =
                    vec![Box::new(from_ms), Box::new(to_ms)];
                if let Some(sev) = severity {
                    sql.push_str(" AND severity = ?3");
                    params.push(Box::new(sev.to_string()));
                }
                if let Some(aid) = agent_id {
                    let idx = params.len() + 1;
                    sql.push_str(&format!(" AND agent_id = ?{idx}"));
                    params.push(Box::new(aid.to_string()));
                }
                let mut stmt = conn.prepare(&sql)?;
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let count: i64 = stmt.query_row(param_refs.as_slice(), |row| row.get(0))?;
                total += count as u64;
                Ok(())
            })?;
        }
        Ok(total)
    }

    fn count_distinct_metric_names(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<u64> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();
        let mut all_names = std::collections::HashSet::new();

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare(
                    "SELECT DISTINCT metric_name FROM metrics WHERE timestamp >= ?1 AND timestamp <= ?2",
                )?;
                let rows = stmt.query_map(rusqlite::params![from_ms, to_ms], |row| {
                    row.get::<_, String>(0)
                })?;
                for row in rows {
                    all_names.insert(row?);
                }
                Ok(())
            })?;
        }
        Ok(all_names.len() as u64)
    }

    fn count_distinct_agent_ids(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<u64> {
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();
        let mut all_ids = std::collections::HashSet::new();

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let mut stmt = conn.prepare(
                    "SELECT DISTINCT agent_id FROM metrics WHERE timestamp >= ?1 AND timestamp <= ?2",
                )?;
                let rows = stmt.query_map(rusqlite::params![from_ms, to_ms], |row| {
                    row.get::<_, String>(0)
                })?;
                for row in rows {
                    all_ids.insert(row?);
                }
                Ok(())
            })?;
        }
        Ok(all_ids.len() as u64)
    }

    fn count_active_alerts(&self) -> Result<u64> {
        // Query last 7 days for active alerts
        let to = Utc::now();
        let from = to - chrono::Duration::days(7);
        let keys = self.partitions.partitions_in_range(from, to)?;
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();
        let mut total: u64 = 0;

        for key in keys {
            self.partitions.with_partition(&key, |conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM alert_events WHERE timestamp >= ?1 AND timestamp <= ?2 AND (status IS NULL OR status NOT IN ('resolved'))",
                    rusqlite::params![from_ms, to_ms],
                    |row| row.get(0),
                )?;
                total += count as u64;
                Ok(())
            })?;
        }
        Ok(total)
    }
}
