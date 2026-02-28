use chrono::Utc;
use oxmon_storage::{CertStore, NotificationChannelFilter, NotificationChannelRow};

/// Default notification channel definitions for first-time startup.
/// All channels are created with `enabled = false` so the user must
/// explicitly configure and enable them.
struct ChannelDef {
    name: &'static str,
    channel_type: &'static str,
    description: &'static str,
    min_severity: &'static str,
}

const DEFAULT_CHANNELS: &[ChannelDef] = &[
    ChannelDef {
        name: "默认邮件通知",
        channel_type: "email",
        description: "SMTP 邮件通知渠道，启用前请先配置系统邮件发送方或填写渠道级 config_json",
        min_severity: "warning",
    },
    ChannelDef {
        name: "默认 Webhook 通知",
        channel_type: "webhook",
        description: "HTTP Webhook 回调通知，启用前请填写 webhook URL",
        min_severity: "warning",
    },
    ChannelDef {
        name: "默认钉钉通知",
        channel_type: "dingtalk",
        description: "钉钉机器人通知，启用前请填写 access_token",
        min_severity: "warning",
    },
    ChannelDef {
        name: "默认企业微信通知",
        channel_type: "weixin",
        description: "企业微信机器人通知，启用前请填写 webhook key",
        min_severity: "warning",
    },
    ChannelDef {
        name: "默认阿里云短信",
        channel_type: "sms_aliyun",
        description: "阿里云短信通知，启用前请配置系统短信发送方或填写渠道级 config_json",
        min_severity: "critical",
    },
    ChannelDef {
        name: "默认腾讯云短信",
        channel_type: "sms_tencent",
        description: "腾讯云短信通知，启用前请配置系统短信发送方或填写渠道级 config_json",
        min_severity: "critical",
    },
    ChannelDef {
        name: "默认通用短信",
        channel_type: "sms_generic",
        description: "通用 HTTP 短信网关通知，启用前请填写网关 URL 及参数",
        min_severity: "critical",
    },
];

/// Initialize default notification channels if the database has no channels yet.
///
/// All channels are created with `enabled = false` and empty `config_json` so
/// the user must configure and enable them before they take effect.
pub async fn init_default_channels(cert_store: &CertStore) -> anyhow::Result<usize> {
    let existing = cert_store
        .list_notification_channels(
            &NotificationChannelFilter {
                name_contains: None,
                channel_type_eq: None,
                enabled_eq: None,
                min_severity_eq: None,
            },
            1,
            0,
        )
        .await?;
    if !existing.is_empty() {
        tracing::debug!("Notification channels already exist, skipping seed initialization");
        return Ok(0);
    }

    let now = Utc::now();
    let mut inserted = 0usize;

    for def in DEFAULT_CHANNELS {
        let row = NotificationChannelRow {
            id: oxmon_common::id::next_id(),
            name: def.name.to_string(),
            channel_type: def.channel_type.to_string(),
            description: Some(def.description.to_string()),
            min_severity: def.min_severity.to_string(),
            enabled: false,
            config_json: "{}".to_string(),
            created_at: now,
            updated_at: now,
        };
        match cert_store.insert_notification_channel(&row).await {
            Ok(_) => {
                inserted += 1;
                tracing::info!(
                    name = %def.name,
                    channel_type = %def.channel_type,
                    "Seeded notification channel (disabled)"
                );
            }
            Err(e) => {
                tracing::warn!(name = %def.name, error = %e, "Failed to seed notification channel");
            }
        }
    }

    tracing::info!(
        inserted,
        total = DEFAULT_CHANNELS.len(),
        "Default notification channels initialized (all disabled)"
    );
    Ok(inserted)
}
