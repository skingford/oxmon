use anyhow::{Context, Result};
use oxmon_storage::cert_store::{CertStore, SystemConfigRow};

/// Initialize default AI accounts (only when DB has none)
pub fn init_default_ai_accounts(cert_store: &CertStore) -> Result<()> {
    let existing = cert_store.list_system_configs(Some("ai_account"), None, None, 1000, 0)?;

    if !existing.is_empty() {
        tracing::debug!(
            count = existing.len(),
            "AI accounts already exist, skipping default initialization"
        );
        return Ok(());
    }

    tracing::info!("No AI accounts found, initializing default AI account (disabled)");

    // Create a default disabled GLM-5 account as example
    let default_config = serde_json::json!({
        "api_key": "your-api-key-here",
        "model": "glm-5",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "timeout_secs": 60,
        "max_tokens": 4000,
        "temperature": 0.7,
        "collection_interval_secs": 86400
    });

    let row = SystemConfigRow {
        id: oxmon_common::id::next_id(),
        config_key: "ai_account_default".to_string(),
        config_type: "ai_account".to_string(),
        provider: Some("zhipu".to_string()),
        display_name: "默认 AI 账号 (GLM-5)".to_string(),
        description: Some("默认的 GLM-5 AI 账号配置,需要配置 API Key 后启用".to_string()),
        config_json: default_config.to_string(),
        enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    cert_store
        .insert_system_config(&row)
        .context("Failed to insert default AI account")?;

    tracing::info!(
        config_key = %row.config_key,
        "Default AI account created (disabled)"
    );

    Ok(())
}
