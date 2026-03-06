use crate::entities::alert_event::{Column as AeCol, Entity as AeEntity};
use crate::entities::metric::{Column as MCol, Entity as MEntity};
use crate::{AlertSummary, MetricQuery, MetricSummary, PartitionInfo, StorageEngine};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricBatch, MetricDataPoint, Severity};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, Condition, DatabaseConnection, EntityTrait,
    FromQueryResult, Order, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Statement, Value,
    sea_query::OnConflict,
};
use std::collections::HashMap;

// ---- 辅助转换函数 ----

fn model_to_dp(m: crate::entities::metric::Model) -> Result<MetricDataPoint> {
    let labels: HashMap<String, String> =
        serde_json::from_str(&m.labels).unwrap_or_default();
    let timestamp = DateTime::from_timestamp_millis(m.timestamp).unwrap_or_default();
    let created_at = DateTime::from_timestamp_millis(m.created_at).unwrap_or_default();
    let updated_at = DateTime::from_timestamp_millis(m.updated_at).unwrap_or_default();
    Ok(MetricDataPoint {
        id: m.id,
        timestamp,
        agent_id: m.agent_id,
        metric_name: m.metric_name,
        value: m.value,
        labels,
        created_at,
        updated_at,
    })
}

fn ae_model_to_event(m: crate::entities::alert_event::Model) -> AlertEvent {
    let labels: HashMap<String, String> =
        serde_json::from_str(&m.labels).unwrap_or_default();
    let timestamp = DateTime::from_timestamp_millis(m.timestamp).unwrap_or_default();
    let predicted_breach = m.predicted_breach.and_then(DateTime::from_timestamp_millis);
    let first_triggered_at =
        m.first_triggered_at.and_then(DateTime::from_timestamp_millis);
    let created_at = DateTime::from_timestamp_millis(m.created_at).unwrap_or_default();
    let updated_at = DateTime::from_timestamp_millis(m.updated_at).unwrap_or_default();
    let severity: Severity = m.severity.parse().unwrap_or(Severity::Info);
    let status = match m.status.as_deref() {
        Some("acknowledged") => 2,
        Some("resolved") => 3,
        _ => 1,
    };
    AlertEvent {
        id: m.id,
        rule_id: m.rule_id,
        rule_name: m.rule_name,
        agent_id: m.agent_id,
        metric_name: m.metric_name,
        severity,
        message: m.message,
        value: m.value,
        threshold: m.threshold,
        timestamp,
        predicted_breach,
        labels,
        first_triggered_at,
        status,
        created_at,
        updated_at,
    }
}

// ---- 聚合查询结果结构（模块级别，供 FromQueryResult 派生） ----

#[derive(Debug, FromQueryResult)]
struct MetricNameRow {
    metric_name: String,
}

#[derive(Debug, FromQueryResult)]
struct AgentIdRow {
    agent_id: String,
}

#[derive(Debug, FromQueryResult)]
struct SummaryRow {
    min_val: Option<f64>,
    max_val: Option<f64>,
    avg_val: Option<f64>,
    cnt: i64,
}

#[derive(Debug, FromQueryResult)]
struct AlertGroupRow {
    severity: String,
    rule_id: String,
    agent_id: String,
    metric_name: String,
    status: Option<String>,
    cnt: i64,
}

#[derive(Debug, FromQueryResult)]
struct CountRow {
    cnt: i64,
}

// ---- SeaOrmStorageEngine ----

pub struct SeaOrmStorageEngine {
    pub(crate) db: DatabaseConnection,
}

impl SeaOrmStorageEngine {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    async fn update_alert_status(&self, event_id: &str, new_status: &str) -> Result<bool> {
        let now = Utc::now().timestamp_millis();
        let result = AeEntity::update_many()
            .col_expr(
                AeCol::Status,
                sea_orm::sea_query::Expr::value(new_status),
            )
            .col_expr(
                AeCol::UpdatedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .filter(AeCol::Id.eq(event_id))
            .exec(&self.db)
            .await?;
        Ok(result.rows_affected > 0)
    }
}

#[async_trait]
impl StorageEngine for SeaOrmStorageEngine {
    // ---- 指标写入 ----

    async fn write_batch(&self, batch: &MetricBatch) -> Result<()> {
        if batch.data_points.is_empty() {
            return Ok(());
        }
        let now = Utc::now().timestamp_millis();
        let models: Vec<crate::entities::metric::ActiveModel> = batch
            .data_points
            .iter()
            .map(|dp| {
                let labels_json =
                    serde_json::to_string(&dp.labels).unwrap_or_else(|_| "{}".to_string());
                crate::entities::metric::ActiveModel {
                    id: Set(dp.id.clone()),
                    timestamp: Set(dp.timestamp.timestamp_millis()),
                    agent_id: Set(dp.agent_id.clone()),
                    metric_name: Set(dp.metric_name.clone()),
                    value: Set(dp.value),
                    labels: Set(labels_json),
                    created_at: Set(now),
                    updated_at: Set(now),
                }
            })
            .collect();

        MEntity::insert_many(models)
            .on_conflict(
                OnConflict::column(MCol::Id)
                    .do_nothing()
                    .to_owned(),
            )
            .exec_without_returning(&self.db)
            .await?;

        Ok(())
    }

    // ---- 指标查询 ----

    async fn query(&self, query: &MetricQuery) -> Result<Vec<MetricDataPoint>> {
        let from_ms = query.from.timestamp_millis();
        let to_ms = query.to.timestamp_millis();

        let models = MEntity::find()
            .filter(MCol::AgentId.eq(&query.agent_id))
            .filter(MCol::MetricName.eq(&query.metric_name))
            .filter(MCol::Timestamp.gte(from_ms))
            .filter(MCol::Timestamp.lte(to_ms))
            .order_by(MCol::Timestamp, Order::Asc)
            .all(&self.db)
            .await?;

        models.into_iter().map(model_to_dp).collect()
    }

    async fn query_metrics_paginated(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<MetricDataPoint>> {
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let mut q = MEntity::find()
            .filter(MCol::Timestamp.gte(from_ms))
            .filter(MCol::Timestamp.lte(to_ms));

        if let Some(aid) = agent_id {
            q = q.filter(MCol::AgentId.eq(aid));
        }
        if let Some(mn) = metric_name {
            q = q.filter(MCol::MetricName.eq(mn));
        }

        let models = q
            .order_by(MCol::CreatedAt, Order::Desc)
            .order_by(MCol::Timestamp, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(&self.db)
            .await?;

        models.into_iter().map(model_to_dp).collect()
    }

    // ---- 数据清理 ----

    async fn cleanup(&self, retention_days: u32) -> Result<u32> {
        let cutoff_ms = (Utc::now() - chrono::Duration::days(retention_days as i64))
            .timestamp_millis();

        let metric_result = MEntity::delete_many()
            .filter(MCol::Timestamp.lt(cutoff_ms))
            .exec(&self.db)
            .await?;

        let alert_result = AeEntity::delete_many()
            .filter(AeCol::Timestamp.lt(cutoff_ms))
            .exec(&self.db)
            .await?;

        Ok((metric_result.rows_affected + alert_result.rows_affected) as u32)
    }

    // ---- 告警事件写入 ----

    async fn write_alert_event(&self, event: &AlertEvent) -> Result<()> {
        let now = Utc::now().timestamp_millis();
        let labels_json = serde_json::to_string(&event.labels)?;
        let status_str = match event.status {
            2 => Some("acknowledged".to_string()),
            3 => Some("resolved".to_string()),
            _ => None,
        };

        let am = crate::entities::alert_event::ActiveModel {
            id: Set(event.id.clone()),
            rule_id: Set(event.rule_id.clone()),
            rule_name: Set(event.rule_name.clone()),
            agent_id: Set(event.agent_id.clone()),
            metric_name: Set(event.metric_name.clone()),
            severity: Set(event.severity.to_string()),
            message: Set(event.message.clone()),
            value: Set(event.value),
            threshold: Set(event.threshold),
            timestamp: Set(event.timestamp.timestamp_millis()),
            predicted_breach: Set(event.predicted_breach.map(|t| t.timestamp_millis())),
            labels: Set(labels_json),
            first_triggered_at: Set(
                event.first_triggered_at.map(|t| t.timestamp_millis()),
            ),
            status: Set(status_str),
            created_at: Set(now),
            updated_at: Set(now),
        };

        AeEntity::insert(am)
            .on_conflict(
                OnConflict::column(AeCol::Id)
                    .update_columns([
                        AeCol::RuleId,
                        AeCol::RuleName,
                        AeCol::AgentId,
                        AeCol::MetricName,
                        AeCol::Severity,
                        AeCol::Message,
                        AeCol::Value,
                        AeCol::Threshold,
                        AeCol::Timestamp,
                        AeCol::PredictedBreach,
                        AeCol::Labels,
                        AeCol::FirstTriggeredAt,
                        AeCol::Status,
                        AeCol::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;

        Ok(())
    }

    // ---- 告警历史查询 ----

    async fn query_alert_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        severity: Option<&str>,
        agent_id: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AlertEvent>> {
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let mut q = AeEntity::find()
            .filter(AeCol::Timestamp.gte(from_ms))
            .filter(AeCol::Timestamp.lte(to_ms));

        if let Some(sev) = severity {
            q = q.filter(AeCol::Severity.eq(sev));
        }
        if let Some(aid) = agent_id {
            q = q.filter(AeCol::AgentId.eq(aid));
        }

        let models = q
            .order_by(AeCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(&self.db)
            .await?;

        Ok(models.into_iter().map(ae_model_to_event).collect())
    }

    // ---- DISTINCT 查询 ----

    async fn query_distinct_metric_names(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>> {
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let rows = MetricNameRow::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            "SELECT DISTINCT metric_name FROM metrics
             WHERE timestamp >= $1 AND timestamp <= $2
             ORDER BY metric_name
             LIMIT $3 OFFSET $4",
            vec![
                Value::BigInt(Some(from_ms)),
                Value::BigInt(Some(to_ms)),
                Value::BigInt(Some(limit as i64)),
                Value::BigInt(Some(offset as i64)),
            ],
        ))
        .all(&self.db)
        .await?;

        Ok(rows.into_iter().map(|r| r.metric_name).collect())
    }

    async fn query_distinct_agent_ids(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<String>> {
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let rows = AgentIdRow::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            "SELECT DISTINCT agent_id FROM metrics
             WHERE timestamp >= $1 AND timestamp <= $2
             ORDER BY agent_id
             LIMIT $3 OFFSET $4",
            vec![
                Value::BigInt(Some(from_ms)),
                Value::BigInt(Some(to_ms)),
                Value::BigInt(Some(limit as i64)),
                Value::BigInt(Some(offset as i64)),
            ],
        ))
        .all(&self.db)
        .await?;

        Ok(rows.into_iter().map(|r| r.agent_id).collect())
    }

    // ---- 聚合统计 ----

    async fn query_metric_summary(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: &str,
        metric_name: &str,
    ) -> Result<MetricSummary> {
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let row = SummaryRow::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            "SELECT MIN(value) AS min_val, MAX(value) AS max_val,
                    AVG(value) AS avg_val, COUNT(*) AS cnt
             FROM metrics
             WHERE agent_id = $1 AND metric_name = $2
               AND timestamp >= $3 AND timestamp <= $4",
            vec![
                Value::String(Some(agent_id.to_string())),
                Value::String(Some(metric_name.to_string())),
                Value::BigInt(Some(from_ms)),
                Value::BigInt(Some(to_ms)),
            ],
        ))
        .one(&self.db)
        .await?
        .unwrap_or(SummaryRow {
            min_val: None,
            max_val: None,
            avg_val: None,
            cnt: 0,
        });

        Ok(MetricSummary {
            min: row.min_val.unwrap_or(0.0),
            max: row.max_val.unwrap_or(0.0),
            avg: row.avg_val.unwrap_or(0.0),
            count: row.cnt as u64,
        })
    }

    async fn query_alert_summary(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<AlertSummary> {
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let rows = AlertGroupRow::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            "SELECT severity, rule_id, agent_id, metric_name, status,
                    COUNT(*) AS cnt
             FROM alert_events
             WHERE timestamp >= $1 AND timestamp <= $2
             GROUP BY severity, rule_id, agent_id, metric_name, status",
            vec![
                Value::BigInt(Some(from_ms)),
                Value::BigInt(Some(to_ms)),
            ],
        ))
        .all(&self.db)
        .await?;

        let mut total: u64 = 0;
        let mut by_severity: HashMap<String, u64> = HashMap::new();
        let mut by_rule: HashMap<String, u64> = HashMap::new();
        let mut by_agent: HashMap<String, u64> = HashMap::new();
        let mut by_metric: HashMap<String, u64> = HashMap::new();
        let mut active_count: u64 = 0;
        let mut recovered_count: u64 = 0;

        for r in rows {
            let cnt = r.cnt as u64;
            total += cnt;
            *by_severity.entry(r.severity).or_insert(0) += cnt;
            *by_rule.entry(r.rule_id).or_insert(0) += cnt;
            *by_agent.entry(r.agent_id).or_insert(0) += cnt;
            *by_metric.entry(r.metric_name).or_insert(0) += cnt;
            match r.status.as_deref() {
                Some("resolved") => recovered_count += cnt,
                _ => active_count += cnt,
            }
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

    // ---- 分区信息（已废弃，返回空列表） ----

    async fn list_partitions(&self) -> Result<Vec<PartitionInfo>> {
        Ok(vec![])
    }

    // ---- 告警状态更新 ----

    async fn acknowledge_alert(&self, event_id: &str) -> Result<bool> {
        self.update_alert_status(event_id, "acknowledged").await
    }

    async fn resolve_alert(&self, event_id: &str) -> Result<bool> {
        self.update_alert_status(event_id, "resolved").await
    }

    async fn get_alert_event_by_id(&self, event_id: &str) -> Result<Option<AlertEvent>> {
        let model = AeEntity::find_by_id(event_id).one(&self.db).await?;
        Ok(model.map(ae_model_to_event))
    }

    // ---- 活跃告警查询 ----

    async fn query_active_alerts(
        &self,
        agent_id_contains: Option<&str>,
        severity: Option<&str>,
        rule_id: Option<&str>,
        metric_name: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AlertEvent>> {
        let to = Utc::now();
        let from = to - chrono::Duration::days(7);
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let not_resolved = Condition::any()
            .add(AeCol::Status.is_null())
            .add(AeCol::Status.ne("resolved"));

        let mut q = AeEntity::find()
            .filter(AeCol::Timestamp.gte(from_ms))
            .filter(AeCol::Timestamp.lte(to_ms))
            .filter(not_resolved);

        if let Some(v) = agent_id_contains {
            q = q.filter(AeCol::AgentId.contains(v));
        }
        if let Some(v) = severity {
            q = q.filter(AeCol::Severity.eq(v));
        }
        if let Some(v) = rule_id {
            q = q.filter(AeCol::RuleId.eq(v));
        }
        if let Some(v) = metric_name {
            q = q.filter(AeCol::MetricName.eq(v));
        }

        let models = q
            .order_by(AeCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(&self.db)
            .await?;

        Ok(models.into_iter().map(ae_model_to_event).collect())
    }

    // ---- COUNT 查询 ----

    async fn count_metrics(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        agent_id: Option<&str>,
        metric_name: Option<&str>,
    ) -> Result<u64> {
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let mut q = MEntity::find()
            .filter(MCol::Timestamp.gte(from_ms))
            .filter(MCol::Timestamp.lte(to_ms));
        if let Some(aid) = agent_id {
            q = q.filter(MCol::AgentId.eq(aid));
        }
        if let Some(mn) = metric_name {
            q = q.filter(MCol::MetricName.eq(mn));
        }

        let count = q.count(&self.db).await?;
        Ok(count)
    }

    async fn count_alert_history(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        severity: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<u64> {
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let mut q = AeEntity::find()
            .filter(AeCol::Timestamp.gte(from_ms))
            .filter(AeCol::Timestamp.lte(to_ms));
        if let Some(sev) = severity {
            q = q.filter(AeCol::Severity.eq(sev));
        }
        if let Some(aid) = agent_id {
            q = q.filter(AeCol::AgentId.eq(aid));
        }

        let count = q.count(&self.db).await?;
        Ok(count)
    }

    async fn count_distinct_metric_names(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64> {
        let row = CountRow::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            "SELECT COUNT(DISTINCT metric_name) AS cnt FROM metrics
             WHERE timestamp >= $1 AND timestamp <= $2",
            vec![
                Value::BigInt(Some(from.timestamp_millis())),
                Value::BigInt(Some(to.timestamp_millis())),
            ],
        ))
        .one(&self.db)
        .await?;
        Ok(row.map(|r| r.cnt as u64).unwrap_or(0))
    }

    async fn count_distinct_agent_ids(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<u64> {
        let row = CountRow::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            "SELECT COUNT(DISTINCT agent_id) AS cnt FROM metrics
             WHERE timestamp >= $1 AND timestamp <= $2",
            vec![
                Value::BigInt(Some(from.timestamp_millis())),
                Value::BigInt(Some(to.timestamp_millis())),
            ],
        ))
        .one(&self.db)
        .await?;
        Ok(row.map(|r| r.cnt as u64).unwrap_or(0))
    }

    async fn count_active_alerts(
        &self,
        agent_id_contains: Option<&str>,
        severity: Option<&str>,
        rule_id: Option<&str>,
        metric_name: Option<&str>,
    ) -> Result<u64> {
        let to = Utc::now();
        let from = to - chrono::Duration::days(7);
        let from_ms = from.timestamp_millis();
        let to_ms = to.timestamp_millis();

        let not_resolved = Condition::any()
            .add(AeCol::Status.is_null())
            .add(AeCol::Status.ne("resolved"));

        let mut q = AeEntity::find()
            .filter(AeCol::Timestamp.gte(from_ms))
            .filter(AeCol::Timestamp.lte(to_ms))
            .filter(not_resolved);

        if let Some(v) = agent_id_contains {
            q = q.filter(AeCol::AgentId.contains(v));
        }
        if let Some(v) = severity {
            q = q.filter(AeCol::Severity.eq(v));
        }
        if let Some(v) = rule_id {
            q = q.filter(AeCol::RuleId.eq(v));
        }
        if let Some(v) = metric_name {
            q = q.filter(AeCol::MetricName.eq(v));
        }

        let count = q.count(&self.db).await?;
        Ok(count)
    }

    // ---- 最新指标查询 ----

    async fn query_latest_metrics_for_agent(
        &self,
        agent_id: &str,
        metric_names: &[&str],
        lookback_days: u32,
    ) -> Result<Vec<MetricDataPoint>> {
        if metric_names.is_empty() {
            return Ok(vec![]);
        }

        let to = Utc::now();
        let from = to - chrono::Duration::days(lookback_days as i64);
        let from_ms = from.timestamp_millis();

        let placeholders: String = metric_names
            .iter()
            .enumerate()
            .map(|(i, _)| format!("${}", i + 3))
            .collect::<Vec<_>>()
            .join(", ");

        let sql = format!(
            "SELECT m.id, m.timestamp, m.agent_id, m.metric_name, m.value,
                    m.labels, m.created_at, m.updated_at
             FROM metrics m
             INNER JOIN (
                 SELECT metric_name, MAX(timestamp) AS max_ts
                 FROM metrics
                 WHERE agent_id = $1 AND timestamp >= $2
                   AND metric_name IN ({placeholders})
                 GROUP BY metric_name
             ) latest
               ON m.agent_id = $1
              AND m.metric_name = latest.metric_name
              AND m.timestamp = latest.max_ts"
        );

        let mut values: Vec<Value> = vec![
            Value::String(Some(agent_id.to_string())),
            Value::BigInt(Some(from_ms)),
        ];
        for name in metric_names {
            values.push(Value::String(Some((*name).to_string())));
        }

        let models = crate::entities::metric::Model::find_by_statement(
            Statement::from_sql_and_values(self.db.get_database_backend(), &sql, values),
        )
        .all(&self.db)
        .await?;

        models.into_iter().map(model_to_dp).collect()
    }

    async fn query_all_latest_for_agent(
        &self,
        agent_id: &str,
        lookback_days: u32,
    ) -> Result<Vec<MetricDataPoint>> {
        let to = Utc::now();
        let from = to - chrono::Duration::days(lookback_days as i64);
        let from_ms = from.timestamp_millis();

        let models = crate::entities::metric::Model::find_by_statement(
            Statement::from_sql_and_values(
                self.db.get_database_backend(),
                "SELECT m.id, m.timestamp, m.agent_id, m.metric_name, m.value,
                        m.labels, m.created_at, m.updated_at
                 FROM metrics m
                 INNER JOIN (
                     SELECT metric_name, labels, MAX(timestamp) AS max_ts
                     FROM metrics
                     WHERE agent_id = $1 AND timestamp >= $2
                     GROUP BY metric_name, labels
                 ) latest
                   ON m.agent_id = $1
                  AND m.metric_name = latest.metric_name
                  AND m.labels = latest.labels
                  AND m.timestamp = latest.max_ts",
                vec![
                    Value::String(Some(agent_id.to_string())),
                    Value::BigInt(Some(from_ms)),
                ],
            ),
        )
        .all(&self.db)
        .await?;

        models.into_iter().map(model_to_dp).collect()
    }
}
