use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m003_cloud_instances_datetime_rfc3339"
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
SET created_at = CASE
    WHEN typeof(created_at) = 'integer' OR typeof(created_at) = 'real' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', created_at, 'unixepoch')
    WHEN typeof(created_at) = 'text' AND trim(created_at) GLOB '-[0-9][0-9]*' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', CAST(trim(created_at) AS INTEGER), 'unixepoch')
    WHEN typeof(created_at) = 'text' AND trim(created_at) GLOB '[0-9][0-9]*' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', CAST(trim(created_at) AS INTEGER), 'unixepoch')
    ELSE created_at
END
WHERE
    (typeof(created_at) = 'integer' OR typeof(created_at) = 'real')
    OR (typeof(created_at) = 'text' AND trim(created_at) GLOB '-[0-9][0-9]*')
    OR (typeof(created_at) = 'text' AND trim(created_at) GLOB '[0-9][0-9]*');

UPDATE cloud_instances
SET updated_at = CASE
    WHEN typeof(updated_at) = 'integer' OR typeof(updated_at) = 'real' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', updated_at, 'unixepoch')
    WHEN typeof(updated_at) = 'text' AND trim(updated_at) GLOB '-[0-9][0-9]*' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', CAST(trim(updated_at) AS INTEGER), 'unixepoch')
    WHEN typeof(updated_at) = 'text' AND trim(updated_at) GLOB '[0-9][0-9]*' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', CAST(trim(updated_at) AS INTEGER), 'unixepoch')
    ELSE updated_at
END
WHERE
    (typeof(updated_at) = 'integer' OR typeof(updated_at) = 'real')
    OR (typeof(updated_at) = 'text' AND trim(updated_at) GLOB '-[0-9][0-9]*')
    OR (typeof(updated_at) = 'text' AND trim(updated_at) GLOB '[0-9][0-9]*');

UPDATE cloud_instances
SET last_seen_at = CASE
    WHEN typeof(last_seen_at) = 'integer' OR typeof(last_seen_at) = 'real' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', last_seen_at, 'unixepoch')
    WHEN typeof(last_seen_at) = 'text' AND trim(last_seen_at) GLOB '-[0-9][0-9]*' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', CAST(trim(last_seen_at) AS INTEGER), 'unixepoch')
    WHEN typeof(last_seen_at) = 'text' AND trim(last_seen_at) GLOB '[0-9][0-9]*' THEN strftime('%Y-%m-%dT%H:%M:%f+00:00', CAST(trim(last_seen_at) AS INTEGER), 'unixepoch')
    ELSE last_seen_at
END
WHERE
    (typeof(last_seen_at) = 'integer' OR typeof(last_seen_at) = 'real')
    OR (typeof(last_seen_at) = 'text' AND trim(last_seen_at) GLOB '-[0-9][0-9]*')
    OR (typeof(last_seen_at) = 'text' AND trim(last_seen_at) GLOB '[0-9][0-9]*');
"#;
