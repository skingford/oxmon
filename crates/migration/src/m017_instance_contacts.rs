use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m017_instance_contacts"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TABLE IF NOT EXISTS instance_contacts (
                    id TEXT PRIMARY KEY NOT NULL,
                    agent_patterns TEXT NOT NULL DEFAULT '[]',
                    contact_name TEXT NOT NULL,
                    contact_email TEXT,
                    contact_phone TEXT,
                    contact_dingtalk TEXT,
                    contact_webhook TEXT,
                    enabled BOOLEAN NOT NULL DEFAULT 1,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS instance_contacts;")
            .await?;
        Ok(())
    }
}
