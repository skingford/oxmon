use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m012_audit_logs"
    }
}

const UP_SQL: &str = "
CREATE TABLE IF NOT EXISTS audit_logs (
    id            TEXT    PRIMARY KEY NOT NULL,
    user_id       TEXT    NOT NULL,
    username      TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    resource_type TEXT    NOT NULL,
    resource_id   TEXT,
    method        TEXT    NOT NULL,
    path          TEXT    NOT NULL,
    status_code   INTEGER NOT NULL DEFAULT 0,
    ip_address    TEXT,
    user_agent    TEXT,
    trace_id      TEXT,
    request_body  TEXT,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
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
            "DROP INDEX IF EXISTS idx_audit_logs_action; \
             DROP INDEX IF EXISTS idx_audit_logs_resource_type; \
             DROP INDEX IF EXISTS idx_audit_logs_created_at; \
             DROP INDEX IF EXISTS idx_audit_logs_user_id; \
             DROP TABLE IF EXISTS audit_logs;",
        )
        .await?;
        Ok(())
    }
}
