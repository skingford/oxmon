//! Time-series storage layer for metrics and alert events.
//!
//! The default implementation ([`engine::SqliteStorageEngine`]) uses daily
//! time-partitioned SQLite databases with WAL mode for concurrent reads.
//! Certificate and agent-whitelist data are stored in a separate
//! [`cert_store::CertStore`] database.

pub mod auth;
pub mod cert_store;
pub mod engine;
pub mod partition;

#[cfg(test)]
mod tests;

use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricBatch, MetricDataPoint};

/// Parameters for a time-range metric query, scoped to a single agent and
/// metric name.
///
/// # Examples
///
/// ```
/// use oxmon_storage::MetricQuery;
/// use chrono::{Duration, Utc};
///
/// let now = Utc::now();
/// let query = MetricQuery {
///     agent_id: "prod-web-01".into(),
///     metric_name: "cpu.usage".into(),
///     from: now - Duration::hours(1),
///     to: now,
/// };
/// assert_eq!(query.metric_name, "cpu.usage");
/// ```
pub struct MetricQuery {
    pub agent_id: String,
    pub metric_name: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

/// Persistence backend for metrics and alert events.
///
/// Implementations must be safe to share across threads (`Send + Sync`)
/// because the storage is accessed from both the gRPC ingestion handler
/// and the REST API concurrently.
pub trait StorageEngine: Send + Sync {
    /// Writes a batch of metric data points, typically received from an agent.
    fn write_batch(&self, batch: &MetricBatch) -> Result<()>;

    /// Queries metric data points matching the given agent, metric name, and
    /// time range.
    fn query(&self, query: &MetricQuery) -> Result<Vec<MetricDataPoint>>;

    /// Queries metric data points with optional filters and pagination.
    fn query_metrics_paginated(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MetricDataPoint>>;

    /// Removes partitions older than `retention_days`. Returns the number of
    /// partitions removed.
    fn cleanup(&self, retention_days: u32) -> Result<u32>;

    /// Persists a fired alert event for historical queries.
    fn write_alert_event(&self, event: &AlertEvent) -> Result<()>;

    /// Queries historical alert events with optional severity and agent filters.
    fn query_alert_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        severity: Option<&str>,
        agent_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AlertEvent>>;

    /// Returns distinct metric names observed in the given time range.
    fn query_distinct_metric_names(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>>;

    /// Returns distinct agent IDs observed in the given time range.
    fn query_distinct_agent_ids(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>>;

    /// Returns aggregated metric statistics (min, max, avg, count) for the
    /// given agent, metric, and time range.
    fn query_metric_summary(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: &str,
        metric_name: &str,
    ) -> Result<MetricSummary>;

    /// Returns alert event counts grouped by severity in the given time range.
    fn query_alert_summary(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<AlertSummary>;

    /// Returns partition (daily database) information.
    fn list_partitions(&self) -> Result<Vec<PartitionInfo>>;

    /// Acknowledges an alert event by ID. Returns true if found and updated.
    fn acknowledge_alert(&self, event_id: &str) -> Result<bool>;

    /// Resolves an alert event by ID. Returns true if found and updated.
    fn resolve_alert(&self, event_id: &str) -> Result<bool>;

    /// Gets a single alert event by ID.
    fn get_alert_event_by_id(&self, event_id: &str) -> Result<Option<AlertEvent>>;

    /// Queries active (non-resolved) alert events.
    fn query_active_alerts(
        &self,
        agent_id_contains: Option<&str>,
        severity: Option<&str>,
        rule_id: Option<&str>,
        metric_name: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AlertEvent>>;

    /// Returns total count for paginated metrics query.
    fn count_metrics(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
    ) -> Result<u64>;

    /// Returns total count for paginated alert history.
    fn count_alert_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        severity: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<u64>;

    /// Returns total count of distinct metric names in the given time range.
    fn count_distinct_metric_names(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<u64>;

    /// Returns total count of distinct agent IDs in the given time range.
    fn count_distinct_agent_ids(&self, from: DateTime<Utc>, to: DateTime<Utc>) -> Result<u64>;

    /// Returns total count of active (non-resolved) alert events.
    fn count_active_alerts(
        &self,
        agent_id_contains: Option<&str>,
        severity: Option<&str>,
        rule_id: Option<&str>,
        metric_name: Option<&str>,
    ) -> Result<u64>;
}

/// Aggregated metric statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricSummary {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub count: u64,
}

/// Alert summary with counts by severity.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AlertSummary {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_rule: std::collections::HashMap<String, u64>,
    pub by_agent: std::collections::HashMap<String, u64>,
    pub by_metric: std::collections::HashMap<String, u64>,
    pub active_count: u64,
    pub recovered_count: u64,
}

/// Information about a storage partition (daily SQLite database).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PartitionInfo {
    pub date: String,
    pub size_bytes: u64,
    pub path: String,
}
