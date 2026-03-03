use anyhow::Result;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};

use crate::entities::ai_check_job::{self, Column as Col, Entity};
use crate::store::CertStore;

/// AI 检测任务数据行
#[derive(Debug, Clone)]
pub struct AICheckJobRow {
    pub id: String,
    /// "cloud_all" | "cloud_instance:{db_id}"
    pub job_type: String,
    /// "running" | "succeeded" | "failed"
    pub status: String,
    pub ai_account_id: String,
    pub report_id: Option<String>,
    pub error_message: Option<String>,
    pub started_at: chrono::DateTime<Utc>,
    pub finished_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
}

fn model_to_row(m: ai_check_job::Model) -> AICheckJobRow {
    AICheckJobRow {
        id: m.id,
        job_type: m.job_type,
        status: m.status,
        ai_account_id: m.ai_account_id,
        report_id: m.report_id,
        error_message: m.error_message,
        started_at: m.started_at.with_timezone(&Utc),
        finished_at: m.finished_at.map(|dt| dt.with_timezone(&Utc)),
        created_at: m.created_at.with_timezone(&Utc),
    }
}

impl CertStore {
    /// 创建一条处于 running 状态的任务记录。
    pub async fn create_ai_check_job(
        &self,
        job_id: &str,
        job_type: &str,
        ai_account_id: &str,
    ) -> Result<AICheckJobRow> {
        let now = Utc::now().fixed_offset();
        let am = ai_check_job::ActiveModel {
            id: Set(job_id.to_string()),
            job_type: Set(job_type.to_string()),
            status: Set("running".to_string()),
            ai_account_id: Set(ai_account_id.to_string()),
            report_id: Set(None),
            error_message: Set(None),
            started_at: Set(now),
            finished_at: Set(None),
            created_at: Set(now),
        };
        let m = am.insert(self.db()).await?;
        Ok(model_to_row(m))
    }

    /// 将任务标记为成功，记录报告 ID。
    pub async fn finish_ai_check_job(&self, job_id: &str, report_id: &str) -> Result<()> {
        let m = Entity::find_by_id(job_id).one(self.db()).await?;
        if let Some(m) = m {
            let now = Utc::now().fixed_offset();
            let mut am: ai_check_job::ActiveModel = m.into();
            am.status = Set("succeeded".to_string());
            am.report_id = Set(Some(report_id.to_string()));
            am.finished_at = Set(Some(now));
            am.update(self.db()).await?;
        }
        Ok(())
    }

    /// 将任务标记为失败，记录错误信息。
    pub async fn fail_ai_check_job(&self, job_id: &str, error_message: &str) -> Result<()> {
        let m = Entity::find_by_id(job_id).one(self.db()).await?;
        if let Some(m) = m {
            let now = Utc::now().fixed_offset();
            let mut am: ai_check_job::ActiveModel = m.into();
            am.status = Set("failed".to_string());
            am.error_message = Set(Some(error_message.to_string()));
            am.finished_at = Set(Some(now));
            am.update(self.db()).await?;
        }
        Ok(())
    }

    /// 按 ID 查询任务。
    pub async fn get_ai_check_job_by_id(&self, id: &str) -> Result<Option<AICheckJobRow>> {
        let m = Entity::find_by_id(id).one(self.db()).await?;
        Ok(m.map(model_to_row))
    }

    /// 查询指定类型是否存在正在运行的任务（用于防重复触发）。
    pub async fn get_running_ai_check_job(&self, job_type: &str) -> Result<Option<AICheckJobRow>> {
        let m = Entity::find()
            .filter(Col::JobType.eq(job_type))
            .filter(Col::Status.eq("running"))
            .order_by(Col::CreatedAt, Order::Desc)
            .one(self.db())
            .await?;
        Ok(m.map(model_to_row))
    }

    /// 列出任务记录（分页），可按状态过滤。
    pub async fn list_ai_check_jobs(
        &self,
        status: Option<&str>,
        job_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AICheckJobRow>> {
        let mut q = Entity::find();
        if let Some(s) = status {
            q = q.filter(Col::Status.eq(s));
        }
        if let Some(t) = job_type {
            q = q.filter(Col::JobType.eq(t));
        }
        let rows = q
            .order_by(Col::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_row).collect())
    }

    /// 统计任务数量，可按状态过滤。
    pub async fn count_ai_check_jobs(
        &self,
        status: Option<&str>,
        job_type: Option<&str>,
    ) -> Result<u64> {
        let mut q = Entity::find();
        if let Some(s) = status {
            q = q.filter(Col::Status.eq(s));
        }
        if let Some(t) = job_type {
            q = q.filter(Col::JobType.eq(t));
        }
        Ok(q.count(self.db()).await?)
    }
}
