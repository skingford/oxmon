use crate::plugin::ChannelPlugin;
use crate::NotificationChannel;
use anyhow::Result;
use async_trait::async_trait;
use oxmon_common::types::AlertEvent;
use serde::Deserialize;
use serde_json::Value;
use tracing;

pub struct SmsChannel {
    instance_id: String,
    client: reqwest::Client,
    gateway_url: String,
    api_key: String,
}

impl SmsChannel {
    pub fn new(instance_id: &str, gateway_url: &str, api_key: &str) -> Self {
        Self {
            instance_id: instance_id.to_string(),
            client: reqwest::Client::new(),
            gateway_url: gateway_url.to_string(),
            api_key: api_key.to_string(),
        }
    }

    fn format_message(alert: &AlertEvent) -> String {
        format!(
            "[oxmon][{severity}] {agent}: {message}",
            severity = alert.severity,
            agent = alert.agent_id,
            message = alert.message,
        )
    }
}

#[async_trait]
impl NotificationChannel for SmsChannel {
    async fn send(&self, alert: &AlertEvent, recipients: &[String]) -> Result<()> {
        if recipients.is_empty() {
            return Ok(());
        }

        let message = Self::format_message(alert);

        for phone in recipients {
            let payload = serde_json::json!({
                "to": phone,
                "message": message,
            });

            let mut last_err = None;
            for attempt in 0..3u32 {
                match self
                    .client
                    .post(&self.gateway_url)
                    .header("Authorization", format!("Bearer {}", self.api_key))
                    .json(&payload)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        last_err = None;
                        break;
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        tracing::warn!(
                            attempt = attempt + 1,
                            phone = %phone,
                            status = %status,
                            "SMS gateway returned error, retrying"
                        );
                        last_err = Some(anyhow::anyhow!("HTTP {status}"));
                    }
                    Err(e) => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            phone = %phone,
                            error = %e,
                            "SMS send failed, retrying"
                        );
                        last_err = Some(e.into());
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt))).await;
            }

            if let Some(e) = last_err {
                tracing::error!(phone = %phone, error = %e, "SMS failed after 3 retries");
            }
        }

        Ok(())
    }

    fn channel_type(&self) -> &str {
        "sms"
    }

    fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

// Plugin

#[derive(Deserialize)]
struct SmsConfig {
    gateway_url: String,
    api_key: String,
}

pub struct SmsPlugin;

impl ChannelPlugin for SmsPlugin {
    fn name(&self) -> &str {
        "sms"
    }

    fn recipient_type(&self) -> &str {
        "phone"
    }

    fn validate_config(&self, config: &Value) -> Result<()> {
        serde_json::from_value::<SmsConfig>(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid sms config: {e}"))?;
        Ok(())
    }

    fn create_channel(&self, instance_id: &str, config: &Value) -> Result<Box<dyn NotificationChannel>> {
        let cfg: SmsConfig = serde_json::from_value(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid sms config: {e}"))?;
        Ok(Box::new(SmsChannel::new(
            instance_id,
            &cfg.gateway_url,
            &cfg.api_key,
        )))
    }

    fn redact_config(&self, config: &Value) -> Value {
        let mut redacted = config.clone();
        if let Some(obj) = redacted.as_object_mut() {
            if obj.contains_key("api_key") {
                obj.insert("api_key".to_string(), Value::String("***".to_string()));
            }
        }
        redacted
    }
}
