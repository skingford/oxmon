use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m010_agent_report_logs"
    }
}

const UP_SQL: &str = "
CREATE TABLE IF NOT EXISTS agent_report_logs (
    id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL,
    metric_count INTEGER NOT NULL DEFAULT 0,
    hostname TEXT,
    os TEXT,
    os_version TEXT,
    arch TEXT,
    kernel_version TEXT,
    cpu_cores INTEGER,
    memory_gb REAL,
    disk_gb REAL,
    reported_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_report_logs_agent_id ON agent_report_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_report_logs_reported_at ON agent_report_logs(reported_at DESC);
";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "DROP INDEX IF EXISTS idx_agent_report_logs_reported_at; \
             DROP INDEX IF EXISTS idx_agent_report_logs_agent_id; \
             DROP TABLE IF EXISTS agent_report_logs;",
        )
        .await?;
        Ok(())
    }
}
