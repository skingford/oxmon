use chrono::Utc;
use oxmon_storage::{CertStore, CloudAccountRow};
use std::collections::{HashMap, HashSet};

const SEED_CLOUD_PREFIX: &str = "seed_cloud_";

struct CloudAccountDef {
    config_key: &'static str,
    provider: &'static str,
    display_name: &'static str,
    description: &'static str,
    regions: &'static [&'static str],
}

const DEFAULT_CLOUD_ACCOUNTS: &[CloudAccountDef] = &[
    CloudAccountDef {
        config_key: "seed_cloud_tencent",
        provider: "tencent",
        display_name: "默认腾讯云账号",
        description: "系统预置腾讯云账号，请填写 SecretId/SecretKey 后启用",
        regions: &["ap-guangzhou"],
    },
    CloudAccountDef {
        config_key: "seed_cloud_alibaba",
        provider: "alibaba",
        display_name: "默认阿里云账号",
        description: "系统预置阿里云账号，请填写 AccessKey 后启用",
        regions: &["cn-hangzhou"],
    },
];

/// 初始化默认云账号（腾讯云/阿里云）。
///
/// 行为：
/// 1. 按 `config_key` 幂等创建/更新默认账号；
/// 2. 默认账号凭据字段（secret_id/secret_key/account_name）统一清空，且默认禁用；
/// 3. 清理不在默认集合中的历史 `seed_cloud_*` 账号。
pub async fn init_default_cloud_accounts(
    cert_store: &CertStore,
    default_interval_secs: u64,
) -> anyhow::Result<usize> {
    let interval_secs = i64::try_from(default_interval_secs).unwrap_or(i64::MAX);
    let existing_accounts = cert_store
        .list_cloud_accounts(None, None, 10_000, 0)
        .await?;
    let existing_by_key: HashMap<String, CloudAccountRow> = existing_accounts
        .iter()
        .cloned()
        .map(|account| (account.config_key.clone(), account))
        .collect();

    let mut synced = 0usize;
    let mut default_keys = HashSet::new();

    for def in DEFAULT_CLOUD_ACCOUNTS {
        default_keys.insert(def.config_key);

        let seed_row = CloudAccountRow {
            id: existing_by_key
                .get(def.config_key)
                .map(|row| row.id.clone())
                .unwrap_or_else(oxmon_common::id::next_id),
            config_key: def.config_key.to_string(),
            provider: def.provider.to_string(),
            display_name: def.display_name.to_string(),
            description: Some(def.description.to_string()),
            account_name: String::new(),
            secret_id: String::new(),
            secret_key: String::new(),
            regions: def.regions.iter().map(|v| (*v).to_string()).collect(),
            collection_interval_secs: interval_secs,
            enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        if let Some(existing) = existing_by_key.get(def.config_key) {
            cert_store
                .update_cloud_account(&existing.id, &seed_row)
                .await?;
            synced += 1;
            tracing::info!(config_key = def.config_key, "Updated default cloud account seed");
            continue;
        }

        cert_store.insert_cloud_account(&seed_row).await?;
        synced += 1;
        tracing::info!(config_key = def.config_key, "Inserted default cloud account seed");
    }

    let mut removed = 0usize;
    for account in existing_accounts {
        if account.config_key.starts_with(SEED_CLOUD_PREFIX)
            && !default_keys.contains(account.config_key.as_str())
            && cert_store.delete_cloud_account(&account.id).await?
        {
            removed += 1;
            tracing::info!(
                config_key = %account.config_key,
                id = %account.id,
                "Removed stale cloud account seed"
            );
        }
    }

    tracing::info!(
        synced,
        removed,
        total = DEFAULT_CLOUD_ACCOUNTS.len(),
        "Default cloud accounts initialized"
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
    async fn seeds_default_cloud_accounts_and_cleans_stale_seed_accounts() -> anyhow::Result<()> {
        let (cert_store, _temp_dir) = setup_cert_store().await?;

        let inserted = init_default_cloud_accounts(&cert_store, 7200).await?;
        assert_eq!(inserted, 2);

        let tencent = cert_store
            .get_cloud_account_by_config_key("seed_cloud_tencent")
            .await
            .context("seed_cloud_tencent should exist")?;
        assert_eq!(tencent.provider, "tencent");
        assert_eq!(tencent.secret_id, "");
        assert_eq!(tencent.secret_key, "");
        assert_eq!(tencent.account_name, "");
        assert_eq!(tencent.collection_interval_secs, 7200);
        assert!(!tencent.enabled);

        let mut dirty = tencent.clone();
        dirty.secret_id = "temp-id".to_string();
        dirty.secret_key = "temp-key".to_string();
        dirty.account_name = "temp-account".to_string();
        dirty.enabled = true;
        cert_store.update_cloud_account(&dirty.id, &dirty).await?;

        let now = Utc::now();
        cert_store
            .insert_cloud_account(&CloudAccountRow {
                id: oxmon_common::id::next_id(),
                config_key: "seed_cloud_legacy".to_string(),
                provider: "tencent".to_string(),
                display_name: "Legacy".to_string(),
                description: Some("legacy seed".to_string()),
                account_name: "legacy".to_string(),
                secret_id: "legacy".to_string(),
                secret_key: "legacy".to_string(),
                regions: vec!["ap-shanghai".to_string()],
                collection_interval_secs: 300,
                enabled: true,
                created_at: now,
                updated_at: now,
            })
            .await?;

        let updated = init_default_cloud_accounts(&cert_store, 3600).await?;
        assert_eq!(updated, 2);

        let tencent_after = cert_store
            .get_cloud_account_by_config_key("seed_cloud_tencent")
            .await
            .context("seed_cloud_tencent should still exist")?;
        assert_eq!(tencent_after.secret_id, "");
        assert_eq!(tencent_after.secret_key, "");
        assert_eq!(tencent_after.account_name, "");
        assert_eq!(tencent_after.collection_interval_secs, 3600);
        assert!(!tencent_after.enabled);

        let legacy = cert_store
            .get_cloud_account_by_config_key("seed_cloud_legacy")
            .await;
        assert!(legacy.is_err());

        let all_accounts = cert_store.list_cloud_accounts(None, None, 100, 0).await?;
        assert_eq!(all_accounts.len(), 2);

        Ok(())
    }
}
