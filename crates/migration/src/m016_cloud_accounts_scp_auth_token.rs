use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m016_cloud_accounts_scp_auth_token"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 为深信服 SCP 6.3.0 及更早版本添加 Cookie 认证 Token 字段
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE cloud_accounts ADD COLUMN scp_auth_token TEXT;",
            )
            .await
            .ok(); // Ignore error if column already exists
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let _ = manager;
        Ok(())
    }
}
