use crate::plugin::ChannelPlugin;
use crate::NotificationChannel;
use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, Mac};
use oxmon_common::types::AlertEvent;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use tracing;

type HmacSha256 = Hmac<Sha256>;

pub struct DingTalkChannel {
    instance_id: String,
    client: reqwest::Client,
    webhook_url: String,
    secret: Option<String>,
}

impl DingTalkChannel {
    pub fn new(instance_id: &str, webhook_url: &str, secret: Option<String>) -> Self {
        Self {
            instance_id: instance_id.to_string(),
            client: reqwest::Client::new(),
            webhook_url: webhook_url.to_string(),
            secret,
        }
    }

    pub fn sign_url(&self, base_url: &str) -> String {
        let Some(secret) = &self.secret else {
            return base_url.to_string();
        };

        let timestamp = chrono::Utc::now().timestamp_millis();
        let string_to_sign = format!("{}\n{}", timestamp, secret);

        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        mac.update(string_to_sign.as_bytes());
        let result = mac.finalize();
        let sign = base64::engine::general_purpose::STANDARD.encode(result.into_bytes());
        let sign_encoded = urlencoding::encode(&sign);

        format!("{}&timestamp={}&sign={}", base_url, timestamp, sign_encoded)
    }

    fn format_markdown(alert: &AlertEvent) -> (String, String) {
        let title = format!(
            "[oxmon][{}] {} - {}",
            alert.severity, alert.metric_name, alert.agent_id
        );
        let text = format!(
            "### {title}\n\n\
             - **Severity**: {severity}\n\
             - **Agent**: {agent}\n\
             - **Metric**: {metric}\n\
             - **Value**: {value:.2}\n\
             - **Threshold**: {threshold:.2}\n\
             - **Time**: {time}\n\n\
             > {message}",
            title = title,
            severity = alert.severity,
            agent = alert.agent_id,
            metric = alert.metric_name,
            value = alert.value,
            threshold = alert.threshold,
            time = alert.timestamp.to_rfc3339(),
            message = alert.message,
        );
        (title, text)
    }

    async fn send_to_url(&self, url: &str, payload: &Value) -> Result<()> {
        let mut last_err = None;
        for attempt in 0..3u32 {
            match self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .json(payload)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<Value>().await {
                        Ok(body) => {
                            if body.get("errcode").and_then(|v| v.as_i64()) == Some(0) {
                                return Ok(());
                            }
                            let errmsg = body
                                .get("errmsg")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            tracing::warn!(
                                attempt = attempt + 1,
                                errmsg = errmsg,
                                "DingTalk API returned error, retrying"
                            );
                            last_err = Some(anyhow::anyhow!("DingTalk error: {errmsg}"));
                        }
                        Err(e) => {
                            tracing::warn!(
                                attempt = attempt + 1,
                                error = %e,
                                "Failed to parse DingTalk response, retrying"
                            );
                            last_err = Some(e.into());
                        }
                    }
                }
                Ok(resp) => {
                    let status = resp.status();
                    tracing::warn!(
                        attempt = attempt + 1,
                        status = %status,
                        "DingTalk webhook returned HTTP error, retrying"
                    );
                    last_err = Some(anyhow::anyhow!("HTTP {status}"));
                }
                Err(e) => {
                    tracing::warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "DingTalk webhook request failed, retrying"
                    );
                    last_err = Some(e.into());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt))).await;
        }

        if let Some(e) = last_err {
            tracing::error!(error = %e, "DingTalk notification failed after 3 retries");
        }
        Ok(())
    }
}

#[async_trait]
impl NotificationChannel for DingTalkChannel {
    async fn send(&self, alert: &AlertEvent, recipients: &[String]) -> Result<()> {
        let (title, text) = Self::format_markdown(alert);
        let payload = serde_json::json!({
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": text,
            }
        });

        if recipients.is_empty() {
            // 使用 config 中的默认 webhook_url
            let url = self.sign_url(&self.webhook_url);
            self.send_to_url(&url, &payload).await?;
        } else {
            // recipients 是额外的 webhook URL 列表
            for webhook in recipients {
                let url = self.sign_url(webhook);
                self.send_to_url(&url, &payload).await?;
            }
        }

        Ok(())
    }

    fn channel_type(&self) -> &str {
        "dingtalk"
    }

    fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

// Plugin

#[derive(Deserialize)]
struct DingTalkConfig {
    webhook_url: String,
    secret: Option<String>,
}

pub struct DingTalkPlugin;

impl ChannelPlugin for DingTalkPlugin {
    fn name(&self) -> &str {
        "dingtalk"
    }

    fn recipient_type(&self) -> &str {
        "webhook_url"
    }

    fn validate_config(&self, config: &Value) -> Result<()> {
        serde_json::from_value::<DingTalkConfig>(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid dingtalk config: {e}"))?;
        Ok(())
    }

    fn create_channel(&self, instance_id: &str, config: &Value) -> Result<Box<dyn NotificationChannel>> {
        let cfg: DingTalkConfig = serde_json::from_value(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid dingtalk config: {e}"))?;
        Ok(Box::new(DingTalkChannel::new(instance_id, &cfg.webhook_url, cfg.secret)))
    }

    fn redact_config(&self, config: &Value) -> Value {
        let mut redacted = config.clone();
        if let Some(obj) = redacted.as_object_mut() {
            if obj.contains_key("secret") {
                obj.insert("secret".to_string(), Value::String("***".to_string()));
            }
        }
        redacted
    }
}
