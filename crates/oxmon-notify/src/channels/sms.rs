use crate::{ChannelType, NotificationChannel};
use anyhow::Result;
use async_trait::async_trait;
use oxmon_common::types::AlertEvent;
use tracing;

pub struct SmsChannel {
    client: reqwest::Client,
    gateway_url: String,
    api_key: String,
    phone_numbers: Vec<String>,
}

impl SmsChannel {
    pub fn new(gateway_url: &str, api_key: &str, phone_numbers: Vec<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            gateway_url: gateway_url.to_string(),
            api_key: api_key.to_string(),
            phone_numbers,
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
    async fn send(&self, alert: &AlertEvent) -> Result<()> {
        let message = Self::format_message(alert);

        for phone in &self.phone_numbers {
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
                tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt)))
                    .await;
            }

            if let Some(e) = last_err {
                tracing::error!(phone = %phone, error = %e, "SMS failed after 3 retries");
            }
        }

        Ok(())
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Sms
    }
}
