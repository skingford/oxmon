use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m013_users_extended_fields"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // status：账号状态，默认 active
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .add_column(
                        ColumnDef::new(Alias::new("status"))
                            .string()
                            .not_null()
                            .default("active"),
                    )
                    .to_owned(),
            )
            .await?;

        // avatar：头像 URL，可为空
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .add_column(ColumnDef::new(Alias::new("avatar")).string().null())
                    .to_owned(),
            )
            .await?;

        // phone：手机号，可为空
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .add_column(ColumnDef::new(Alias::new("phone")).string().null())
                    .to_owned(),
            )
            .await?;

        // email：邮箱，可为空
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("users"))
                    .add_column(ColumnDef::new(Alias::new("email")).string().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite 不支持 DROP COLUMN，使用重建表方式回退
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE TABLE users_backup AS SELECT id, username, password_hash, token_version, created_at, updated_at FROM users",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE users")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE users_backup RENAME TO users")
            .await?;
        Ok(())
    }
}
