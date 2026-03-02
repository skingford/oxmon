use chrono::Utc;
use oxmon_storage::{AIAccountRow, AIAccountUpdate, CertStore};
use std::collections::HashSet;

const SEED_AI_PREFIX: &str = "seed_ai_";

struct AIAccountDef {
    config_key: &'static str,
    provider: &'static str,
    display_name: &'static str,
    description: &'static str,
    model: &'static str,
    base_url: Option<&'static str>,
    api_mode: Option<&'static str>,
}

const DEFAULT_AI_ACCOUNTS: &[AIAccountDef] = &[
    // ── 智谱 GLM（OpenAI 兼容模式）──────────────────────────────────────────
    AIAccountDef {
        config_key: "seed_ai_glm",
        provider: "zhipu",
        display_name: "默认 GLM 账号（OpenAI 兼容）",
        description: "智谱 GLM，使用 OpenAI 兼容端点（/api/paas/v4），请填写 API Key 后启用",
        model: "glm-5",
        base_url: Some("https://open.bigmodel.cn/api/paas/v4"),
        api_mode: Some("openai"),
    },
    // ── 智谱 GLM（Anthropic 兼容模式）──────────────────────────────────────
    AIAccountDef {
        config_key: "seed_ai_glm_anthropic",
        provider: "zhipu",
        display_name: "默认 GLM 账号（Anthropic 兼容）",
        description: "智谱 GLM，使用 Anthropic 兼容端点（/api/anthropic），请填写 API Key 后启用",
        model: "glm-5",
        base_url: Some("https://open.bigmodel.cn/api/anthropic"),
        api_mode: Some("anthropic"),
    },
    // ── Codex ────────────────────────────────────────────────────────────────
    AIAccountDef {
        config_key: "seed_ai_codex",
        provider: "codex",
        display_name: "默认 Codex 账号",
        description: "系统预置 AI 账号（Codex），请填写 API Key 后启用",
        model: "codex",
        base_url: None,
        api_mode: None,
    },
    // ── Claude ───────────────────────────────────────────────────────────────
    AIAccountDef {
        config_key: "seed_ai_claude",
        provider: "claude",
        display_name: "默认 Claude 账号",
        description: "系统预置 AI 账号（Claude），请填写 API Key 后启用",
        model: "claude-sonnet-4-6",
        base_url: None,
        api_mode: None,
    },
];

/// 初始化默认 AI 账号（GLM/Codex/Claude）。
///
/// 行为：
/// 1. 按 `config_key` 幂等创建/更新默认账号；
/// 2. 新增默认账号时 api_key 置空并默认禁用；
/// 3. 已存在默认账号不会覆盖敏感字段，也不会强制改 enabled；
/// 4. 清理不在默认集合中的历史 `seed_ai_*` 账号。
pub async fn init_default_ai_accounts(cert_store: &CertStore) -> anyhow::Result<usize> {
    let mut synced = 0usize;
    let mut default_keys = HashSet::new();

    for def in DEFAULT_AI_ACCOUNTS {
        default_keys.insert(def.config_key);

        if let Some(existing) = cert_store
            .get_ai_account_by_config_key(def.config_key)
            .await?
        {
            let updated = cert_store
                .update_ai_account(
                    &existing.id,
                    AIAccountUpdate {
                        display_name: Some(def.display_name.to_string()),
                        description: Some(def.description.to_string()),
                        model: if existing.model.is_none() {
                            Some(def.model.to_string())
                        } else {
                            None
                        },
                        ..Default::default()
                    },
                )
                .await?;
            if updated {
                synced += 1;
                tracing::info!(
                    config_key = def.config_key,
                    "Updated default AI account seed"
                );
            }
            continue;
        }

        let now = Utc::now();
        let row = AIAccountRow {
            id: oxmon_common::id::next_id(),
            config_key: def.config_key.to_string(),
            provider: def.provider.to_string(),
            display_name: def.display_name.to_string(),
            description: Some(def.description.to_string()),
            api_key: String::new(),
            model: Some(def.model.to_string()),
            base_url: def.base_url.map(|s| s.to_string()),
            api_mode: def.api_mode.map(|s| s.to_string()),
            timeout_secs: None,
            max_tokens: None,
            temperature: None,
            collection_interval_secs: None,
            enabled: false,
            created_at: now,
            updated_at: now,
        };
        cert_store.insert_ai_account(&row).await?;
        synced += 1;
        tracing::info!(
            config_key = def.config_key,
            "Inserted default AI account seed"
        );
    }

    let existing_accounts = cert_store.list_ai_accounts(None, None, 10_000, 0).await?;
    let mut removed = 0usize;
    for account in existing_accounts {
        if account.config_key.starts_with(SEED_AI_PREFIX)
            && !default_keys.contains(account.config_key.as_str())
            && cert_store.delete_ai_account(&account.id).await?
        {
            removed += 1;
            tracing::info!(
                config_key = %account.config_key,
                id = %account.id,
                "Removed stale AI account seed"
            );
        }
    }

    tracing::info!(
        synced,
        removed,
        total = DEFAULT_AI_ACCOUNTS.len(),
        "Default AI accounts initialized"
    );
    Ok(synced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use tempfile::TempDir;

    async fn setup_cert_store() -> anyhow::Result<(CertStore, TempDir)> {
        oxmon_common::id::init(1, 1);
        let temp_dir = tempfile::tempdir()?;
        let mut db_cfg = crate::config::DatabaseConfig::default();
        db_cfg.data_dir = temp_dir.path().to_string_lossy().to_string();
        let db_url = db_cfg.connection_url();
        let cert_store = CertStore::new(&db_url, temp_dir.path()).await?;
        Ok((cert_store, temp_dir))
    }

    #[tokio::test]
    async fn seeds_default_ai_accounts_and_cleans_stale_seed_accounts() -> anyhow::Result<()> {
        let (cert_store, _temp_dir) = setup_cert_store().await?;

        let inserted = init_default_ai_accounts(&cert_store).await?;
        assert_eq!(inserted, 4);

        let glm = cert_store
            .get_ai_account_by_config_key("seed_ai_glm")
            .await?
            .context("seed_ai_glm should exist")?;
        assert_eq!(glm.provider, "zhipu");
        assert_eq!(glm.api_key, "");
        assert_eq!(glm.model.as_deref(), Some("glm-5"));
        assert!(!glm.enabled);
        assert_eq!(glm.api_mode.as_deref(), Some("openai"));
        assert_eq!(
            glm.base_url.as_deref(),
            Some("https://open.bigmodel.cn/api/paas/v4")
        );

        // 验证 Anthropic 模式种子账号
        let glm_ant = cert_store
            .get_ai_account_by_config_key("seed_ai_glm_anthropic")
            .await?
            .context("seed_ai_glm_anthropic should exist")?;
        assert_eq!(glm_ant.provider, "zhipu");
        assert_eq!(glm_ant.model.as_deref(), Some("glm-5"));
        assert!(!glm_ant.enabled);
        assert_eq!(glm_ant.api_mode.as_deref(), Some("anthropic"));
        assert!(glm_ant
            .base_url
            .as_deref()
            .unwrap_or("")
            .contains("/api/anthropic"));

        // 修改 GLM 账号（模拟用户配置）
        cert_store
            .update_ai_account(
                &glm.id,
                AIAccountUpdate {
                    display_name: Some("临时账号".to_string()),
                    description: Some("临时描述".to_string()),
                    api_key: Some("temp-api-key".to_string()),
                    model: Some("glm-5-air".to_string()),
                    enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;

        let now = Utc::now();
        cert_store
            .insert_ai_account(&AIAccountRow {
                id: oxmon_common::id::next_id(),
                config_key: "seed_ai_legacy".to_string(),
                provider: "custom".to_string(),
                display_name: "Legacy".to_string(),
                description: Some("legacy seed".to_string()),
                api_key: "legacy".to_string(),
                model: Some("legacy".to_string()),
                base_url: None,
                api_mode: None,
                timeout_secs: None,
                max_tokens: None,
                temperature: None,
                collection_interval_secs: None,
                enabled: true,
                created_at: now,
                updated_at: now,
            })
            .await?;

        let updated = init_default_ai_accounts(&cert_store).await?;
        assert_eq!(updated, 4);

        let glm_after = cert_store
            .get_ai_account_by_config_key("seed_ai_glm")
            .await?
            .context("seed_ai_glm should still exist")?;
        assert_eq!(glm_after.display_name, "默认 GLM 账号（OpenAI 兼容）");
        assert_eq!(glm_after.api_key, "temp-api-key");
        assert_eq!(glm_after.model.as_deref(), Some("glm-5-air"));
        assert!(glm_after.enabled);

        let legacy = cert_store
            .get_ai_account_by_config_key("seed_ai_legacy")
            .await?;
        assert!(legacy.is_none());

        let all_accounts = cert_store.list_ai_accounts(None, None, 100, 0).await?;
        assert_eq!(all_accounts.len(), 4);

        Ok(())
    }
}
