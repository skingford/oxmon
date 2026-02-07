use crate::plugin::ChannelPlugin;
use crate::NotificationChannel;
use anyhow::Result;
use async_trait::async_trait;
use oxmon_common::types::AlertEvent;
use serde::Deserialize;
use serde_json::Value;
use tracing;

pub struct WebhookChannel {
    client: reqwest::Client,
    url: String,
    body_template: Option<String>,
}

impl WebhookChannel {
    pub fn new(url: &str, body_template: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_string(),
            body_template,
        }
    }

    fn render_body(&self, alert: &AlertEvent) -> String {
        if let Some(template) = &self.body_template {
            template
                .replace("{{agent_id}}", &alert.agent_id)
                .replace("{{metric}}", &alert.metric_name)
                .replace("{{value}}", &format!("{:.2}", alert.value))
                .replace("{{severity}}", &alert.severity.to_string())
                .replace("{{message}}", &alert.message)
                .replace("{{threshold}}", &format!("{:.2}", alert.threshold))
                .replace("{{timestamp}}", &alert.timestamp.to_rfc3339())
        } else {
            serde_json::json!({
                "alert_id": alert.id,
                "rule_id": alert.rule_id,
                "agent_id": alert.agent_id,
                "metric": alert.metric_name,
                "severity": alert.severity.to_string(),
                "message": alert.message,
                "value": alert.value,
                "threshold": alert.threshold,
                "timestamp": alert.timestamp.to_rfc3339(),
            })
            .to_string()
        }
    }
}

#[async_trait]
impl NotificationChannel for WebhookChannel {
    async fn send(&self, alert: &AlertEvent) -> Result<()> {
        let body = self.render_body(alert);

        let mut last_err = None;
        for attempt in 0..3u32 {
            match self
                .client
                .post(&self.url)
                .header("Content-Type", "application/json")
                .body(body.clone())
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
                        status = %status,
                        "Webhook returned non-success status, retrying"
                    );
                    last_err = Some(anyhow::anyhow!("HTTP {status}"));
                }
                Err(e) => {
                    tracing::warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "Webhook send failed, retrying"
                    );
                    last_err = Some(e.into());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt))).await;
        }

        if let Some(e) = last_err {
            tracing::error!(url = %self.url, error = %e, "Webhook failed after 3 retries");
        }

        Ok(())
    }

    fn channel_name(&self) -> &str {
        "webhook"
    }
}

// Plugin

#[derive(Deserialize)]
struct WebhookConfig {
    url: String,
    body_template: Option<String>,
}

pub struct WebhookPlugin;

impl ChannelPlugin for WebhookPlugin {
    fn name(&self) -> &str {
        "webhook"
    }

    fn validate_config(&self, config: &Value) -> Result<()> {
        serde_json::from_value::<WebhookConfig>(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid webhook config: {e}"))?;
        Ok(())
    }

    fn create_channel(&self, config: &Value) -> Result<Box<dyn NotificationChannel>> {
        let cfg: WebhookConfig = serde_json::from_value(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid webhook config: {e}"))?;
        Ok(Box::new(WebhookChannel::new(&cfg.url, cfg.body_template)))
    }
}
