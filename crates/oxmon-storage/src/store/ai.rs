use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AIReportRow, CreateAIReportRequest};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};

use crate::entities::ai_account::{self, Column as AccCol, Entity as AccEntity};
use crate::entities::ai_report::{self, Column as RepCol, Entity as RepEntity};
use crate::store::CertStore;

/// AI 账号数据行
#[derive(Debug, Clone)]
pub struct AIAccountRow {
    pub id: String,
    pub config_key: String,
    pub provider: String,
    pub display_name: String,
    pub description: Option<String>,
    pub api_key: String,
    pub api_secret: Option<String>,
    pub model: Option<String>,
    pub extra_config: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn model_to_account(m: ai_account::Model) -> AIAccountRow {
    AIAccountRow {
        id: m.id,
        config_key: m.config_key,
        provider: m.provider,
        display_name: m.display_name,
        description: m.description,
        api_key: m.api_key,
        api_secret: m.api_secret,
        model: m.model,
        extra_config: m.extra_config,
        enabled: m.enabled,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

fn model_to_report(m: ai_report::Model) -> AIReportRow {
    AIReportRow {
        id: m.id,
        report_date: m.report_date,
        ai_account_id: m.ai_account_id,
        ai_provider: m.ai_provider,
        ai_model: m.ai_model,
        total_agents: m.total_agents,
        risk_level: m.risk_level,
        ai_analysis: m.ai_analysis,
        html_content: m.html_content,
        raw_metrics_json: m.raw_metrics_json,
        notified: m.notified,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

impl CertStore {
    // ---- AI Accounts ----

    pub async fn insert_ai_account(&self, row: &AIAccountRow) -> Result<AIAccountRow> {
        let now = Utc::now().fixed_offset();
        let am = ai_account::ActiveModel {
            id: Set(row.id.clone()),
            config_key: Set(row.config_key.clone()),
            provider: Set(row.provider.clone()),
            display_name: Set(row.display_name.clone()),
            description: Set(row.description.clone()),
            api_key: Set(row.api_key.clone()),
            api_secret: Set(row.api_secret.clone()),
            model: Set(row.model.clone()),
            extra_config: Set(row.extra_config.clone()),
            enabled: Set(row.enabled),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let m = am.insert(self.db()).await?;
        Ok(model_to_account(m))
    }

    pub async fn get_ai_account_by_id(&self, id: &str) -> Result<Option<AIAccountRow>> {
        let m = AccEntity::find_by_id(id).one(self.db()).await?;
        Ok(m.map(model_to_account))
    }

    pub async fn get_ai_account_by_config_key(
        &self,
        config_key: &str,
    ) -> Result<Option<AIAccountRow>> {
        let m = AccEntity::find()
            .filter(AccCol::ConfigKey.eq(config_key))
            .one(self.db())
            .await?;
        Ok(m.map(model_to_account))
    }

    pub async fn list_ai_accounts(
        &self,
        provider: Option<&str>,
        enabled: Option<bool>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AIAccountRow>> {
        let mut q = AccEntity::find();
        if let Some(p) = provider {
            q = q.filter(AccCol::Provider.eq(p));
        }
        if let Some(e) = enabled {
            q = q.filter(AccCol::Enabled.eq(e));
        }
        let rows = q
            .order_by(AccCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_account).collect())
    }

    pub async fn count_ai_accounts(
        &self,
        provider: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<u64> {
        let mut q = AccEntity::find();
        if let Some(p) = provider {
            q = q.filter(AccCol::Provider.eq(p));
        }
        if let Some(e) = enabled {
            q = q.filter(AccCol::Enabled.eq(e));
        }
        Ok(q.count(self.db()).await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_ai_account(
        &self,
        id: &str,
        display_name: Option<String>,
        description: Option<String>,
        api_key: Option<String>,
        api_secret: Option<String>,
        model: Option<String>,
        extra_config: Option<String>,
        enabled: Option<bool>,
    ) -> Result<bool> {
        let m = AccEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = m {
            let now = Utc::now().fixed_offset();
            let mut am: ai_account::ActiveModel = m.into();
            if let Some(v) = display_name {
                am.display_name = Set(v);
            }
            if let Some(v) = description {
                am.description = Set(Some(v));
            }
            if let Some(v) = api_key {
                am.api_key = Set(v);
            }
            if let Some(v) = api_secret {
                am.api_secret = Set(Some(v));
            }
            if let Some(v) = model {
                am.model = Set(Some(v));
            }
            if let Some(v) = extra_config {
                am.extra_config = Set(Some(v));
            }
            if let Some(v) = enabled {
                am.enabled = Set(v);
            }
            am.updated_at = Set(now);
            am.update(self.db()).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn delete_ai_account(&self, id: &str) -> Result<bool> {
        let res = AccEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    // ---- AI Reports ----

    pub async fn save_ai_report(&self, report: &CreateAIReportRequest) -> Result<String> {
        let now = Utc::now().fixed_offset();
        let report_id = oxmon_common::id::next_id();
        let am = ai_report::ActiveModel {
            id: Set(report_id.clone()),
            report_date: Set(report.report_date.clone()),
            ai_account_id: Set(report.ai_account_id.clone()),
            ai_provider: Set(report.ai_provider.clone()),
            ai_model: Set(report.ai_model.clone()),
            total_agents: Set(report.total_agents),
            risk_level: Set(report.risk_level.clone()),
            ai_analysis: Set(report.ai_analysis.clone()),
            html_content: Set(report.html_content.clone()),
            raw_metrics_json: Set(report.raw_metrics_json.clone()),
            notified: Set(false),
            created_at: Set(now),
            updated_at: Set(now),
        };
        am.insert(self.db()).await?;
        Ok(report_id)
    }

    pub async fn get_ai_report_by_id(&self, id: &str) -> Result<Option<AIReportRow>> {
        let m = RepEntity::find_by_id(id).one(self.db()).await?;
        Ok(m.map(model_to_report))
    }

    pub async fn get_ai_report_by_date(&self, date: &str) -> Result<Option<AIReportRow>> {
        let m = RepEntity::find()
            .filter(RepCol::ReportDate.eq(date))
            .one(self.db())
            .await?;
        Ok(m.map(model_to_report))
    }

    /// 获取指定 AI 账号（按 config_key）最新一条报告
    pub async fn get_latest_ai_report_by_account(
        &self,
        account_config_key: &str,
    ) -> Result<Option<AIReportRow>> {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        let sql = format!(
            "SELECT r.id, r.report_date, r.ai_account_id, r.ai_provider, r.ai_model, \
             r.total_agents, r.risk_level, r.ai_analysis, r.html_content, r.raw_metrics_json, \
             r.notified, r.created_at, r.updated_at \
             FROM ai_reports r \
             INNER JOIN ai_accounts a ON a.id = r.ai_account_id \
             WHERE a.config_key = '{}' \
             ORDER BY r.created_at DESC LIMIT 1",
            account_config_key.replace('\'', "''")
        );
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await?;
        if let Some(row) = rows.into_iter().next() {
            let notified_i: i32 = row.try_get("", "notified")?;
            let created_at_str: String = row.try_get("", "created_at")?;
            let updated_at_str: String = row.try_get("", "updated_at")?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_default();
            let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_default();
            Ok(Some(AIReportRow {
                id: row.try_get("", "id")?,
                report_date: row.try_get("", "report_date")?,
                ai_account_id: row.try_get("", "ai_account_id")?,
                ai_provider: row.try_get("", "ai_provider")?,
                ai_model: row.try_get("", "ai_model")?,
                total_agents: row.try_get("", "total_agents")?,
                risk_level: row.try_get("", "risk_level")?,
                ai_analysis: row.try_get("", "ai_analysis")?,
                html_content: row.try_get("", "html_content")?,
                raw_metrics_json: row.try_get("", "raw_metrics_json")?,
                notified: notified_i != 0,
                created_at,
                updated_at,
            }))
        } else {
            Ok(None)
        }
    }

    pub async fn list_ai_reports(
        &self,
        report_date: Option<&str>,
        risk_level: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AIReportRow>> {
        let mut q = RepEntity::find();
        if let Some(date) = report_date {
            q = q.filter(RepCol::ReportDate.eq(date));
        }
        if let Some(level) = risk_level {
            q = q.filter(RepCol::RiskLevel.eq(level));
        }
        let rows = q
            .order_by(RepCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_report).collect())
    }

    pub async fn count_ai_reports(
        &self,
        report_date: Option<&str>,
        risk_level: Option<&str>,
    ) -> Result<u64> {
        let mut q = RepEntity::find();
        if let Some(date) = report_date {
            q = q.filter(RepCol::ReportDate.eq(date));
        }
        if let Some(level) = risk_level {
            q = q.filter(RepCol::RiskLevel.eq(level));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn mark_ai_report_notified(&self, id: &str) -> Result<()> {
        let m = RepEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = m {
            let now = Utc::now().fixed_offset();
            let mut am: ai_report::ActiveModel = m.into();
            am.notified = Set(true);
            am.updated_at = Set(now);
            am.update(self.db()).await?;
        }
        Ok(())
    }

    pub async fn delete_ai_report(&self, id: &str) -> Result<bool> {
        let res = RepEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }
}
