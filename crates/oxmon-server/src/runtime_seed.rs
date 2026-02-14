use chrono::Utc;
use oxmon_storage::cert_store::{CertStore, SystemConfigRow};

/// Default runtime settings definitions for first-time startup.
struct RuntimeSettingDef {
    config_key: &'static str,
    display_name: &'static str,
    description: &'static str,
    default_value: u64,
}

const DEFAULT_RUNTIME_SETTINGS: &[RuntimeSettingDef] = &[
    RuntimeSettingDef {
        config_key: "notification_aggregation_window",
        display_name: "通知聚合窗口时长",
        description: "聚合窗口时长（秒），相同告警在窗口期内会被合并发送",
        default_value: 60,
    },
    RuntimeSettingDef {
        config_key: "notification_log_retention",
        display_name: "通知日志保留天数",
        description: "通知发送日志的保留天数，超过该天数的日志将被自动清理",
        default_value: 30,
    },
];

/// Initialize default runtime settings in the database (only when they don't exist).
/// This runs on first-time server startup before the notification manager is created.
pub fn init_default_runtime_settings(cert_store: &CertStore) -> anyhow::Result<usize> {
    let mut inserted_count = 0;

    for def in DEFAULT_RUNTIME_SETTINGS {
        // Check if setting already exists
        if cert_store
            .get_system_config_by_key(def.config_key)?
            .is_some()
        {
            tracing::debug!(
                config_key = def.config_key,
                "Runtime setting already exists, skipping"
            );
            continue;
        }

        // Insert new runtime setting
        let row = SystemConfigRow {
            id: oxmon_common::id::next_id(),
            config_key: def.config_key.to_string(),
            config_type: "runtime".to_string(),
            provider: None,
            display_name: def.display_name.to_string(),
            description: Some(def.description.to_string()),
            config_json: serde_json::json!({"value": def.default_value}).to_string(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        match cert_store.insert_system_config(&row) {
            Ok(_) => {
                tracing::info!(
                    config_key = def.config_key,
                    value = def.default_value,
                    "Initialized default runtime setting"
                );
                inserted_count += 1;
            }
            Err(e) => {
                tracing::warn!(
                    config_key = def.config_key,
                    error = %e,
                    "Failed to insert default runtime setting"
                );
            }
        }
    }

    if inserted_count > 0 {
        tracing::info!(
            count = inserted_count,
            "Initialized default runtime settings"
        );
    }

    Ok(inserted_count)
}
