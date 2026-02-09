pub mod auth;
pub mod cert_store;
pub mod engine;
pub mod partition;

#[cfg(test)]
mod tests;

use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricBatch, MetricDataPoint};

pub struct MetricQuery {
    pub agent_id: String,
    pub metric_name: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

pub trait StorageEngine: Send + Sync {
    fn write_batch(&self, batch: &MetricBatch) -> Result<()>;
    fn query(&self, query: &MetricQuery) -> Result<Vec<MetricDataPoint>>;
    fn query_metrics_paginated(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MetricDataPoint>>;
    fn cleanup(&self, retention_days: u32) -> Result<u32>;
    fn write_alert_event(&self, event: &AlertEvent) -> Result<()>;
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
