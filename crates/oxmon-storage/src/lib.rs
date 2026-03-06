//! 存储层：时序指标与告警事件统一使用 SeaORM 管理，与管理数据库（oxmon.db）共享同一连接池。

pub mod auth;
pub mod engine;
pub mod entities;
pub mod error;
pub mod store;

#[cfg(test)]
mod tests;

pub use engine::SeaOrmStorageEngine;
pub use store::CertStore;
pub use store::{
    AIAccountRow, AIAccountUpdate, AICheckJobRow, ActiveAlertFilter, AgentListFilter,
    AgentReportLogRow, AgentWhitelistFilter, AlertRuleFilter, AlertRuleRow, AlertRuleUpdate,
    AuditLogFilter, AuditLogRow, CertDomainSummary, CertHealthSummary, CertStatusFilter,
    CertStatusSummary, CloudAccountRow, CloudAccountSummary, CloudCollectionStateRow,
    CloudInstanceRow, CloudInstanceStatusSummary, DictTypeFilter, NotificationChannelFilter,
    NotificationChannelRow, NotificationChannelUpdate, NotificationLogFilter, NotificationLogRow,
    NotificationRecipientRow, SilenceWindowFilter, SilenceWindowRow, SystemConfigFilter,
    SystemConfigRow, SystemConfigUpdate,
};

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricBatch, MetricDataPoint};

/// 单 agent、单指标名的时间范围查询参数。
pub struct MetricQuery {
    pub agent_id: String,
    pub metric_name: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

/// 时序存储后端 trait（全异步）。
///
/// 所有实现均需 `Send + Sync`，以便在 axum/gRPC handler 中并发访问。
#[async_trait]
pub trait StorageEngine: Send + Sync {
    async fn write_batch(&self, batch: &MetricBatch) -> Result<()>;

    async fn query(&self, query: &MetricQuery) -> Result<Vec<MetricDataPoint>>;

    async fn query_metrics_paginated(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MetricDataPoint>>;

    async fn cleanup(&self, retention_days: u32) -> Result<u32>;

    async fn write_alert_event(&self, event: &AlertEvent) -> Result<()>;

    async fn query_alert_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        severity: Option<&str>,
        agent_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AlertEvent>>;

    async fn query_distinct_metric_names(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>>;

    async fn query_distinct_agent_ids(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>>;

    async fn query_metric_summary(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: &str,
        metric_name: &str,
    ) -> Result<MetricSummary>;

    async fn query_alert_summary(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<AlertSummary>;

    async fn list_partitions(&self) -> Result<Vec<PartitionInfo>>;

    async fn acknowledge_alert(&self, event_id: &str) -> Result<bool>;

    async fn resolve_alert(&self, event_id: &str) -> Result<bool>;

    async fn get_alert_event_by_id(&self, event_id: &str) -> Result<Option<AlertEvent>>;

    async fn query_active_alerts(
        &self,
        agent_id_contains: Option<&str>,
        severity: Option<&str>,
        rule_id: Option<&str>,
        metric_name: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AlertEvent>>;

    async fn count_metrics(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
    ) -> Result<u64>;

    async fn count_alert_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        severity: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<u64>;

    async fn count_distinct_metric_names(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64>;

    async fn count_distinct_agent_ids(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64>;

    async fn count_active_alerts(
        &self,
        agent_id_contains: Option<&str>,
        severity: Option<&str>,
        rule_id: Option<&str>,
        metric_name: Option<&str>,
    ) -> Result<u64>;

    async fn query_latest_metrics_for_agent(
        &self,
        agent_id: &str,
        metric_names: &[&str],
        lookback_days: u32,
    ) -> Result<Vec<MetricDataPoint>>;

    async fn query_all_latest_for_agent(
        &self,
        agent_id: &str,
        lookback_days: u32,
    ) -> Result<Vec<MetricDataPoint>>;
}

/// 聚合指标统计结果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricSummary {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub count: u64,
}

/// 告警事件按维度统计结果。
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

/// 分区信息（已废弃，兼容保留）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct PartitionInfo {
    pub date: String,
    pub size_bytes: u64,
    pub path: String,
}
