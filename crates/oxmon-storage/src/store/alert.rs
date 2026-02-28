use anyhow::Result;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};

use crate::entities::alert_rule::{self, Column, Entity};
use crate::store::CertStore;

/// 告警规则数据行（来自 alert_rules 表）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleRow {
    pub id: String,
    pub name: String,
    pub rule_type: String,
    pub metric: String,
    pub agent_pattern: String,
    pub severity: String,
    pub enabled: bool,
    pub config_json: String,
    pub silence_secs: i64,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 告警规则更新请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleUpdate {
    pub name: Option<String>,
    pub metric: Option<String>,
    pub agent_pattern: Option<String>,
    pub severity: Option<String>,
    pub enabled: Option<bool>,
    pub config_json: Option<String>,
    pub silence_secs: Option<i64>,
}

/// 告警规则列表过滤器
#[derive(Debug, Clone, Default)]
pub struct AlertRuleFilter {
    pub name_contains: Option<String>,
    pub rule_type_eq: Option<String>,
    pub metric_eq: Option<String>,
    pub severity_eq: Option<String>,
    pub enabled_eq: Option<bool>,
}

fn to_row(m: alert_rule::Model) -> AlertRuleRow {
    AlertRuleRow {
        id: m.id,
        name: m.name,
        rule_type: m.rule_type,
        metric: m.metric,
        agent_pattern: m.agent_pattern,
        severity: m.severity,
        enabled: m.enabled,
        config_json: m.config_json,
        silence_secs: m.silence_secs,
        source: m.source,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

impl CertStore {
    pub async fn insert_alert_rule(&self, row: &AlertRuleRow) -> Result<AlertRuleRow> {
        let now = Utc::now().fixed_offset();
        let am = alert_rule::ActiveModel {
            id: Set(row.id.clone()),
            name: Set(row.name.clone()),
            rule_type: Set(row.rule_type.clone()),
            metric: Set(row.metric.clone()),
            agent_pattern: Set(row.agent_pattern.clone()),
            severity: Set(row.severity.clone()),
            enabled: Set(row.enabled),
            config_json: Set(row.config_json.clone()),
            silence_secs: Set(row.silence_secs),
            source: Set(row.source.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let model = am.insert(self.db()).await?;
        Ok(to_row(model))
    }

    pub async fn get_alert_rule_by_id(&self, id: &str) -> Result<Option<AlertRuleRow>> {
        let model = Entity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(to_row))
    }

    pub async fn list_alert_rules(
        &self,
        rule_type: Option<&str>,
        enabled: Option<bool>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AlertRuleRow>> {
        let mut q = Entity::find();
        if let Some(rt) = rule_type {
            q = q.filter(Column::RuleType.eq(rt));
        }
        if let Some(en) = enabled {
            q = q.filter(Column::Enabled.eq(en));
        }
        let rows = q
            .order_by(Column::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(to_row).collect())
    }

    pub async fn count_alert_rules(
        &self,
        rule_type: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<u64> {
        let mut q = Entity::find();
        if let Some(rt) = rule_type {
            q = q.filter(Column::RuleType.eq(rt));
        }
        if let Some(en) = enabled {
            q = q.filter(Column::Enabled.eq(en));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn update_alert_rule(
        &self,
        id: &str,
        row: &AlertRuleRow,
    ) -> Result<Option<AlertRuleRow>> {
        let model = Entity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: alert_rule::ActiveModel = m.into();
            am.name = Set(row.name.clone());
            am.rule_type = Set(row.rule_type.clone());
            am.metric = Set(row.metric.clone());
            am.agent_pattern = Set(row.agent_pattern.clone());
            am.severity = Set(row.severity.clone());
            am.enabled = Set(row.enabled);
            am.config_json = Set(row.config_json.clone());
            am.silence_secs = Set(row.silence_secs);
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            Ok(Some(to_row(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_alert_rule(&self, id: &str) -> Result<bool> {
        let res = Entity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn set_alert_rule_enabled(&self, id: &str, enabled: bool) -> Result<Option<AlertRuleRow>> {
        let model = Entity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: alert_rule::ActiveModel = m.into();
            am.enabled = Set(enabled);
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            Ok(Some(to_row(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn list_enabled_alert_rules(&self) -> Result<Vec<AlertRuleRow>> {
        let rows = Entity::find()
            .filter(Column::Enabled.eq(true))
            .order_by(Column::CreatedAt, Order::Asc)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(to_row).collect())
    }
}
