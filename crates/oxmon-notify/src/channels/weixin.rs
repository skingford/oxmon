use crate::plugin::ChannelPlugin;
use crate::NotificationChannel;
use anyhow::Result;
use async_trait::async_trait;
use oxmon_common::types::AlertEvent;
use serde::Deserialize;
use serde_json::Value;
use tracing;

pub struct WeixinChannel {
    instance_id: String,
    client: reqwest::Client,
    webhook_url: String,
}

impl WeixinChannel {
    pub fn new(instance_id: &str, webhook_url: &str) -> Self {
        Self {
            instance_id: instance_id.to_string(),
            client: reqwest::Client::new(),
            webhook_url: webhook_url.to_string(),
        }
    }

    fn format_markdown(alert: &AlertEvent) -> String {
        format!(
            "### [oxmon][{severity}] {metric} - {agent}\n\
             > **Severity**: {severity}\n\
             > **Agent**: {agent}\n\
             > **Metric**: {metric}\n\
             > **Value**: {value:.2}\n\
             > **Threshold**: {threshold:.2}\n\
             > **Time**: {time}\n\n\
             {message}",
            severity = alert.severity,
            agent = alert.agent_id,
            metric = alert.metric_name,
            value = alert.value,
            threshold = alert.threshold,
            time = alert.timestamp.to_rfc3339(),
            message = alert.message,
        )
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
                                "WeChat Work API returned error, retrying"
                            );
                            last_err = Some(anyhow::anyhow!("WeChat Work error: {errmsg}"));
                        }
                        Err(e) => {
                            tracing::warn!(
                                attempt = attempt + 1,
                                error = %e,
                                "Failed to parse WeChat Work response, retrying"
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
                        "WeChat Work webhook returned HTTP error, retrying"
                    );
                    last_err = Some(anyhow::anyhow!("HTTP {status}"));
                }
                Err(e) => {
                    tracing::warn!(
                        attempt = attempt + 1,
                        error = %e,
                        "WeChat Work webhook request failed, retrying"
                    );
                    last_err = Some(e.into());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt))).await;
        }

        if let Some(e) = last_err {
            tracing::error!(error = %e, "WeChat Work notification failed after 3 retries");
        }
        Ok(())
    }
}

#[async_trait]
impl NotificationChannel for WeixinChannel {
    async fn send(&self, alert: &AlertEvent, recipients: &[String]) -> Result<()> {
        let content = Self::format_markdown(alert);
        let payload = serde_json::json!({
            "msgtype": "markdown",
            "markdown": {
                "content": content,
            }
        });

        if recipients.is_empty() {
            self.send_to_url(&self.webhook_url, &payload).await?;
        } else {
            for webhook in recipients {
                self.send_to_url(webhook, &payload).await?;
            }
        }

        Ok(())
    }

    fn channel_type(&self) -> &str {
        "weixin"
    }

    fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

// Plugin

#[derive(Deserialize)]
struct WeixinConfig {
    webhook_url: String,
}

pub struct WeixinPlugin;

impl ChannelPlugin for WeixinPlugin {
    fn name(&self) -> &str {
        "weixin"
    }

    fn recipient_type(&self) -> &str {
        "webhook_url"
    }

    fn validate_config(&self, config: &Value) -> Result<()> {
        serde_json::from_value::<WeixinConfig>(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid weixin config: {e}"))?;
        Ok(())
    }

    fn create_channel(&self, instance_id: &str, config: &Value) -> Result<Box<dyn NotificationChannel>> {
        let cfg: WeixinConfig = serde_json::from_value(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid weixin config: {e}"))?;
        Ok(Box::new(WeixinChannel::new(instance_id, &cfg.webhook_url)))
    }
}
