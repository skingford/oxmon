use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m009_agents_system_info"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for sql in [
            "ALTER TABLE agents ADD COLUMN hostname TEXT;",
            "ALTER TABLE agents ADD COLUMN os TEXT;",
            "ALTER TABLE agents ADD COLUMN os_version TEXT;",
            "ALTER TABLE agents ADD COLUMN arch TEXT;",
            "ALTER TABLE agents ADD COLUMN kernel_version TEXT;",
            "ALTER TABLE agents ADD COLUMN cpu_cores INTEGER;",
            "ALTER TABLE agents ADD COLUMN memory_gb REAL;",
            "ALTER TABLE agents ADD COLUMN disk_gb REAL;",
        ] {
            conn.execute_unprepared(sql).await.ok(); // Ignore error if column already exists
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite does not support DROP COLUMN on older versions; this is a no-op.
        let _ = manager;
        Ok(())
    }
}
