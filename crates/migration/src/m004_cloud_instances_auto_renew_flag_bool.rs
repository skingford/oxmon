use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m004_cloud_instances_auto_renew_flag_bool"
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

const UP_SQL: &str = r#"
UPDATE cloud_instances
SET auto_renew_flag = CASE
    WHEN auto_renew_flag IS NULL THEN NULL
    WHEN typeof(auto_renew_flag) = 'integer' THEN CASE WHEN auto_renew_flag = 0 THEN 0 ELSE 1 END
    WHEN typeof(auto_renew_flag) = 'real' THEN CASE WHEN auto_renew_flag = 0 THEN 0 ELSE 1 END
    WHEN lower(trim(CAST(auto_renew_flag AS TEXT))) IN ('1', 'true', 'yes', 'y', 'on') THEN 1
    WHEN lower(trim(CAST(auto_renew_flag AS TEXT))) IN ('0', 'false', 'no', 'n', 'off', '') THEN 0
    ELSE NULL
END
WHERE
    auto_renew_flag IS NOT NULL;
"#;

