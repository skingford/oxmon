use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m006_ai_reports_remove_date_unique"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

/// 移除 ai_reports.report_date 的 UNIQUE 约束：
/// - 调度器通过应用层逻辑保证每账号每日最多一条（should_collect 检查）
/// - 手动触发接口允许随时创建新报告，不受每日限制
const UP_SQL: &str = r#"
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS ai_reports__new (
    id TEXT PRIMARY KEY NOT NULL,
    report_date TEXT NOT NULL,
    ai_account_id TEXT NOT NULL,
    ai_provider TEXT NOT NULL,
    ai_model TEXT NOT NULL,
    total_agents INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL,
    ai_analysis TEXT NOT NULL,
    html_content TEXT NOT NULL,
    raw_metrics_json TEXT NOT NULL,
    notified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO ai_reports__new SELECT * FROM ai_reports;

DROP TABLE ai_reports;
ALTER TABLE ai_reports__new RENAME TO ai_reports;

CREATE INDEX IF NOT EXISTS idx_ai_reports_date ON ai_reports(report_date);
CREATE INDEX IF NOT EXISTS idx_ai_reports_provider ON ai_reports(ai_provider);
CREATE INDEX IF NOT EXISTS idx_ai_reports_account ON ai_reports(ai_account_id);

COMMIT;
PRAGMA foreign_keys=ON;
"#;
