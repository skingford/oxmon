use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m015_cloud_accounts_region_for_sign"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 为深信服 SCP 账户添加 region_for_sign 字段，默认 cn-south-1
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE cloud_accounts ADD COLUMN region_for_sign TEXT;",
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
