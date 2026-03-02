use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m005_drop_ai_accounts_api_secret"
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

/// 将 ai_accounts 表重构为显式字段方式：
/// - 移除 extra_config JSON 字段和 api_secret 字段
/// - 新增 base_url、api_mode、timeout_secs、max_tokens、temperature、collection_interval_secs 显式字段
/// - 从旧 extra_config JSON 中迁移数据到对应字段
const UP_SQL: &str = r#"
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS ai_accounts__new (
    id TEXT PRIMARY KEY NOT NULL,
    config_key TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    api_key TEXT NOT NULL,
    model TEXT,
    base_url TEXT,
    api_mode TEXT,
    timeout_secs INTEGER,
    max_tokens INTEGER,
    temperature REAL,
    collection_interval_secs INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO ai_accounts__new (
    id, config_key, provider, display_name, description,
    api_key, model, enabled, created_at, updated_at,
    base_url, api_mode, timeout_secs, max_tokens, temperature, collection_interval_secs
)
SELECT
    id, config_key, provider, display_name, description,
    api_key, model, enabled, created_at, updated_at,
    CASE WHEN typeof(json_extract(extra_config, '$.base_url')) = 'null' THEN NULL ELSE json_extract(extra_config, '$.base_url') END,
    CASE WHEN typeof(json_extract(extra_config, '$.api_mode')) = 'null' THEN NULL ELSE json_extract(extra_config, '$.api_mode') END,
    CASE WHEN typeof(json_extract(extra_config, '$.timeout_secs')) = 'null' THEN NULL ELSE json_extract(extra_config, '$.timeout_secs') END,
    CASE WHEN typeof(json_extract(extra_config, '$.max_tokens')) = 'null' THEN NULL ELSE json_extract(extra_config, '$.max_tokens') END,
    CASE WHEN typeof(json_extract(extra_config, '$.temperature')) = 'null' THEN NULL ELSE json_extract(extra_config, '$.temperature') END,
    CASE WHEN typeof(json_extract(extra_config, '$.collection_interval_secs')) = 'null' THEN NULL ELSE json_extract(extra_config, '$.collection_interval_secs') END
FROM ai_accounts;

DROP TABLE ai_accounts;
ALTER TABLE ai_accounts__new RENAME TO ai_accounts;

CREATE INDEX IF NOT EXISTS idx_ai_accounts_provider ON ai_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_ai_accounts_enabled ON ai_accounts(enabled);

COMMIT;
PRAGMA foreign_keys=ON;
"#;
