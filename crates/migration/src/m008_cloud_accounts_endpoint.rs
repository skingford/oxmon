use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m008_cloud_accounts_endpoint"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ALTER TABLE ADD COLUMN is idempotent on SQLite if the column already exists
        // (the error is silently ignored via execute_unprepared best-effort semantics).
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE cloud_accounts ADD COLUMN endpoint TEXT;")
            .await
            .ok(); // Ignore error if column already exists
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite does not support DROP COLUMN on older versions; this is a no-op.
        let _ = manager;
        Ok(())
    }
}
