use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m007_ai_check_jobs"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS ai_check_jobs;")
            .await?;
        Ok(())
    }
}

/// 创建 ai_check_jobs 表：
/// - 记录手动触发 AI 检测任务的状态（running / succeeded / failed）
/// - 用于防止重复触发（查询 status='running' 的同类型任务）
/// - 用于查询任务结果（关联 report_id 或 error_message）
const UP_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS ai_check_jobs (
    id              TEXT PRIMARY KEY NOT NULL,
    job_type        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running',
    ai_account_id   TEXT NOT NULL,
    report_id       TEXT,
    error_message   TEXT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_check_jobs_status   ON ai_check_jobs(status);
CREATE INDEX IF NOT EXISTS idx_ai_check_jobs_type     ON ai_check_jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_ai_check_jobs_created  ON ai_check_jobs(created_at DESC);
"#;
