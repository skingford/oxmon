use crate::plugin::ChannelPlugin;
use crate::utils::{truncate_string, MAX_BODY_LENGTH};
use crate::{NotificationChannel, RecipientResult, SendResponse};
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

struct SendResult {
    status_code: Option<u16>,
    response_body: Option<String>,
    error_code: Option<String>,
    retries: u32,
    error: Option<anyhow::Error>,
}

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
        let status_tag = if alert.status == 3 { "[RECOVERED]" } else { "" };
        let rule_display = if alert.rule_name.is_empty() {
            alert.metric_name.clone()
        } else {
            alert.rule_name.clone()
        };
        let title = format!(
            "[oxmon][{}]{} {} - {}",
            alert.severity, status_tag, rule_display, alert.agent_id
        );
        let labels_str = oxmon_common::types::format_labels(&alert.labels);
        let labels_line = if labels_str.is_empty() {
            String::new()
        } else {
            format!("\n- **Labels**: {}", labels_str)
        };
        let rule_line = if alert.rule_name.is_empty() {
            String::new()
        } else {
            format!("\n- **Rule**: {}", alert.rule_name)
        };
        let text = format!(
            "### {title}\n\n\
             - **Severity**: {severity}{rule_line}\n\
             - **Agent**: {agent}\n\
             - **Metric**: {metric}{labels_line}\n\
             - **Value**: {value:.2}\n\
             - **Threshold**: {threshold:.2}\n\
             - **Time**: {time}\n\n\
             > {message}",
            title = title,
            severity = alert.severity,
            rule_line = rule_line,
            agent = alert.agent_id,
            metric = alert.metric_name,
            labels_line = labels_line,
            value = alert.value,
            threshold = alert.threshold,
            time = alert.timestamp.to_rfc3339(),
            message = alert.message,
        );
        (title, text)
    }

    async fn send_to_url(&self, url: &str, payload: &Value) -> SendResult {
        let mut last_err = None;
        let mut status_code: Option<u16> = None;
        let mut response_body: Option<String> = None;
        let mut error_code: Option<String> = None;
        let mut attempts = 0u32;

        for attempt in 0..3u32 {
            attempts = attempt + 1;
            match self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .json(payload)
                .send()
                .await
            {
                Ok(resp) => {
                    status_code = Some(resp.status().as_u16());
                    if resp.status().is_success() {
                        match resp.json::<Value>().await {
                            Ok(body) => {
                                let body_json = serde_json::to_string(&body).unwrap_or_default();
                                let body_str = truncate_string(&body_json, MAX_BODY_LENGTH);
                                response_body = Some(body_str);

                                let errcode = body.get("errcode").and_then(|v| v.as_i64());
                                if errcode == Some(0) {
                                    return SendResult {
                                        status_code,
                                        response_body,
                                        error_code: None,
                                        retries: attempts.saturating_sub(1),
                                        error: None,
                                    };
                                }

                                let errmsg = body
                                    .get("errmsg")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                error_code = errcode.map(|c| c.to_string());
                                tracing::warn!(
                                    attempt = attempts,
                                    errmsg = errmsg,
                                    "DingTalk API returned error, retrying"
                                );
                                last_err = Some(anyhow::anyhow!("DingTalk error: {errmsg}"));
                            }
                            Err(e) => {
                                response_body = Some(format!("[Failed to parse response: {}]", e));
                                tracing::warn!(
                                    attempt = attempts,
                                    error = %e,
                                    "Failed to parse DingTalk response, retrying"
                                );
                                last_err = Some(e.into());
                            }
                        }
                    } else {
                        let status = resp.status();
                        response_body = match resp.text().await {
                            Ok(text) => Some(truncate_string(&text, MAX_BODY_LENGTH)),
                            Err(_) => Some("[Failed to read response body]".to_string()),
                        };
                        tracing::warn!(
                            attempt = attempts,
                            status = %status,
                            "DingTalk webhook returned HTTP error, retrying"
                        );
                        last_err = Some(anyhow::anyhow!("HTTP {status}"));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        attempt = attempts,
                        error = %e,
                        "DingTalk webhook request failed, retrying"
                    );
                    last_err = Some(e.into());
                }
            }
            if attempt < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt))).await;
            }
        }

        if let Some(ref e) = last_err {
            tracing::error!(error = %e, "DingTalk notification failed after 3 retries");
        }

        SendResult {
            status_code,
            response_body,
            error_code,
            retries: attempts.saturating_sub(1),
            error: last_err,
        }
    }
}

#[async_trait]
impl NotificationChannel for DingTalkChannel {
    async fn send(&self, alert: &AlertEvent, recipients: &[String]) -> Result<SendResponse> {
        let (title, text) = Self::format_markdown(alert);
        let payload = serde_json::json!({
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": text,
            }
        });

        let payload_json = serde_json::to_string(&payload).unwrap_or_default();
        let request_body = truncate_string(&payload_json, MAX_BODY_LENGTH);
        let mut response = SendResponse {
            request_body: Some(request_body),
            ..Default::default()
        };

        let mut recipient_results = Vec::new();
        let mut total_retries = 0u32;
        let mut last_status: Option<u16> = None;
        let mut last_response_body: Option<String> = None;
        let mut last_error_code: Option<String> = None;

        if recipients.is_empty() {
            // 使用 config 中的默认 webhook_url
            let url = self.sign_url(&self.webhook_url);
            let result = self.send_to_url(&url, &payload).await;

            total_retries += result.retries;
            last_status = result.status_code;
            last_response_body = result.response_body.clone();
            last_error_code = result.error_code.clone();

            recipient_results.push(RecipientResult {
                recipient: self.webhook_url.clone(),
                status: if result.error.is_none() { "success".to_string() } else { "failed".to_string() },
                error: result.error.as_ref().map(|e| e.to_string()),
            });
        } else {
            // recipients 是额外的 webhook URL 列表
            for webhook in recipients {
                let url = self.sign_url(webhook);
                let result = self.send_to_url(&url, &payload).await;

                total_retries += result.retries;
                last_status = result.status_code;
                last_response_body = result.response_body.clone();
                last_error_code = result.error_code.clone();

                recipient_results.push(RecipientResult {
                    recipient: webhook.clone(),
                    status: if result.error.is_none() { "success".to_string() } else { "failed".to_string() },
                    error: result.error.as_ref().map(|e| e.to_string()),
                });
            }
        }

        response.retry_count = total_retries;
        response.recipient_results = recipient_results;
        response.http_status = last_status;
        response.response_body = last_response_body;
        response.api_error_code = last_error_code;
        Ok(response)
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
