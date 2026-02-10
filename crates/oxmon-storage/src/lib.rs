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
}
