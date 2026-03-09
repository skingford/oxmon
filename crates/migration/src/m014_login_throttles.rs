use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m014_login_throttles"
    }
}

const UP_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS login_throttles (
    id             TEXT PRIMARY KEY NOT NULL,
    username       TEXT NOT NULL,
    ip_address     TEXT NOT NULL,
    failure_count  INTEGER NOT NULL DEFAULT 0,
    last_failed_at TEXT NOT NULL,
    locked_until   TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_throttles_username ON login_throttles(username);
CREATE INDEX IF NOT EXISTS idx_login_throttles_locked_until ON login_throttles(locked_until);
"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DROP INDEX IF EXISTS idx_login_throttles_locked_until;                  DROP INDEX IF EXISTS idx_login_throttles_username;                  DROP TABLE IF EXISTS login_throttles;",
            )
            .await?;
        Ok(())
    }
}
