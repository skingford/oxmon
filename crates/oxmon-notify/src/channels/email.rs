use crate::plugin::ChannelPlugin;
use crate::utils::{truncate_string, MAX_BODY_LENGTH};
use crate::{NotificationChannel, RecipientResult, SendResponse};
use anyhow::Result;
use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::{MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use oxmon_common::types::AlertEvent;
use serde::Deserialize;
use serde_json::Value;
use tracing;

pub struct EmailChannel {
    instance_id: String,
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from_name: String,
    from_email: String,
}

impl EmailChannel {
    pub fn new(
        instance_id: &str,
        smtp_host: &str,
        smtp_port: u16,
        username: Option<&str>,
        password: Option<&str>,
        from_name: &str,
        from_email: &str,
    ) -> Result<Self> {
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_host)?.port(smtp_port);

        if let (Some(user), Some(pass)) = (username, password) {
            builder = builder.credentials(Credentials::new(user.to_string(), pass.to_string()));
        }

        let transport = builder.build();
        Ok(Self {
            instance_id: instance_id.to_string(),
            transport,
            from_name: from_name.to_string(),
            from_email: from_email.to_string(),
        })
    }

    fn format_body(alert: &AlertEvent, locale: &str) -> String {
        use oxmon_common::i18n::TRANSLATIONS;
        let t = &*TRANSLATIONS;
        let labels_str = oxmon_common::types::format_labels(&alert.labels);
        let labels_line = if labels_str.is_empty() {
            String::new()
        } else {
            format!(
                "\n{}: {}",
                t.get(locale, "notify.labels", "Labels"),
                labels_str
            )
        };
        let rule_line = if alert.rule_name.is_empty() {
            String::new()
        } else {
            format!(
                "\n{}: {}",
                t.get(locale, "notify.rule", "Rule"),
                alert.rule_name
            )
        };
        let status_tag = if alert.status == 3 {
            format!(" {}", t.get(locale, "notify.recovered_tag", "[RECOVERED]"))
        } else {
            String::new()
        };
        format!(
            "{alert_label}: {severity}{status_tag}{rule_line}\n{agent_label}: {agent}\n{metric_label}: {metric}{labels_line}\n{value_label}: {value:.2}\n{threshold_label}: {threshold:.2}\n{message_label}: {message}\n{time_label}: {time}",
            alert_label = t.get(locale, "notify.alert", "Alert"),
            severity = alert.severity,
            status_tag = status_tag,
            rule_line = rule_line,
            agent_label = t.get(locale, "notify.agent", "Agent"),
            agent = alert.agent_id,
            metric_label = t.get(locale, "notify.metric", "Metric"),
            metric = alert.metric_name,
            labels_line = labels_line,
            value_label = t.get(locale, "notify.value", "Value"),
            value = alert.value,
            threshold_label = t.get(locale, "notify.threshold", "Threshold"),
            threshold = alert.threshold,
            message_label = t.get(locale, "notify.message", "Message"),
            message = alert.message,
            time_label = t.get(locale, "notify.time", "Time"),
            time = alert.timestamp,
        )
    }

    /// 发送 HTML 邮件（用于 AI 报告等）
    pub async fn send_html(
        &self,
        subject: &str,
        html_body: String,
        plain_body: String,
        recipients: &[String],
    ) -> Result<SendResponse> {
        let request_body = serde_json::json!({
            "from_name": self.from_name,
            "from_email": self.from_email,
            "subject": subject,
            "html_body_length": html_body.len(),
            "plain_body_length": plain_body.len(),
        });
        let request_body_str = serde_json::to_string(&request_body).unwrap_or_default();
        let request_body_truncated = truncate_string(&request_body_str, MAX_BODY_LENGTH);

        let mut response = SendResponse {
            retry_count: 0,
            request_body: Some(request_body_truncated),
            ..Default::default()
        };

        if recipients.is_empty() {
            return Ok(response);
        }

        let mut total_retries = 0u32;
        let mut recipient_results = Vec::new();

        for recipient in recipients {
            let from_address = format!("{} <{}>", self.from_name, self.from_email);

            // 构建 MultiPart alternative（HTML + 纯文本回退）
            let email_body = MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(plain_body.clone()),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(html_body.clone()),
                );

            let email = Message::builder()
                .from(from_address.parse()?)
                .to(recipient.parse()?)
                .subject(subject)
                .multipart(email_body)?;

            let mut last_err = None;
            let mut attempts = 0u32;
            for attempt in 0..3 {
                attempts = attempt + 1;
                match self.transport.send(email.clone()).await {
                    Ok(_) => {
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            attempt = attempts,
                            recipient = %recipient,
                            error = %e,
                            "HTML email send failed, retrying"
                        );
                        last_err = Some(e);
                        if attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(
                                100 * 2u64.pow(attempt),
                            ))
                            .await;
                        }
                    }
                }
            }

            total_retries += attempts.saturating_sub(1);

            if let Some(e) = last_err {
                tracing::error!(recipient = %recipient, error = %e, "HTML email send failed after 3 retries");
                recipient_results.push(RecipientResult {
                    recipient: recipient.clone(),
                    status: "failed".to_string(),
                    error: Some(e.to_string()),
                });
            } else {
                recipient_results.push(RecipientResult {
                    recipient: recipient.clone(),
                    status: "success".to_string(),
                    error: None,
                });
            }
        }

        response.retry_count = total_retries;
        response.recipient_results = recipient_results;
        Ok(response)
    }
}

#[async_trait]
impl NotificationChannel for EmailChannel {
    async fn send_cert_report(
        &self,
        subject: &str,
        html_content: &str,
        _markdown_content: &str,
        plain_content: &str,
        recipients: &[String],
    ) -> Option<Result<SendResponse>> {
        Some(
            self.send_html(subject, html_content.to_string(), plain_content.to_string(), recipients)
                .await,
        )
    }

    async fn send(
        &self,
        alert: &AlertEvent,
        recipients: &[String],
        locale: &str,
    ) -> Result<SendResponse> {
        use oxmon_common::i18n::TRANSLATIONS;
        let recovered_tag = if alert.status == 3 {
            TRANSLATIONS.get(locale, "notify.recovered_tag", "[RECOVERED]")
        } else {
            ""
        };
        let rule_display = if alert.rule_name.is_empty() {
            alert.metric_name.clone()
        } else {
            alert.rule_name.clone()
        };
        let subject = format!(
            "[oxmon][{}]{} {} - {}",
            alert.severity, recovered_tag, rule_display, alert.agent_id
        );
        let body = Self::format_body(alert, locale);

        // 记录 request_body（邮件内容）
        let request_body = serde_json::json!({
            "from_name": self.from_name,
            "from_email": self.from_email,
            "subject": subject,
            "body": body,
        });
        let request_body_str = serde_json::to_string(&request_body).unwrap_or_default();
        let request_body_truncated = truncate_string(&request_body_str, MAX_BODY_LENGTH);

        let mut response = SendResponse {
            retry_count: 0,
            request_body: Some(request_body_truncated),
            ..Default::default()
        };

        if recipients.is_empty() {
            return Ok(response);
        }

        let mut total_retries = 0u32;
        let mut recipient_results = Vec::new();

        for recipient in recipients {
            let from_address = format!("{} <{}>", self.from_name, self.from_email);
            let email = Message::builder()
                .from(from_address.parse()?)
                .to(recipient.parse()?)
                .subject(&subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body.clone())?;

            let mut last_err = None;
            let mut attempts = 0u32;
            for attempt in 0..3 {
                attempts = attempt + 1;
                match self.transport.send(email.clone()).await {
                    Ok(_) => {
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            attempt = attempts,
                            recipient = %recipient,
                            error = %e,
                            "Email send failed, retrying"
                        );
                        last_err = Some(e);
                        if attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(
                                100 * 2u64.pow(attempt),
                            ))
                            .await;
                        }
                    }
                }
            }

            total_retries += attempts.saturating_sub(1);

            if let Some(e) = last_err {
                tracing::error!(recipient = %recipient, error = %e, "Email send failed after 3 retries");
                recipient_results.push(RecipientResult {
                    recipient: recipient.clone(),
                    status: "failed".to_string(),
                    error: Some(e.to_string()),
                });
            } else {
                recipient_results.push(RecipientResult {
                    recipient: recipient.clone(),
                    status: "success".to_string(),
                    error: None,
                });
            }
        }

        response.retry_count = total_retries;
        response.recipient_results = recipient_results;
        Ok(response)
    }

    fn channel_type(&self) -> &str {
        "email"
    }

    fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

// Plugin

#[derive(Deserialize)]
struct EmailConfig {
    smtp_host: String,
    smtp_port: u16,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    from_name: String,
    from_email: String,
}

pub struct EmailPlugin;

impl ChannelPlugin for EmailPlugin {
    fn name(&self) -> &str {
        "email"
    }

    fn recipient_type(&self) -> &str {
        "email"
    }

    fn validate_config(&self, config: &Value) -> Result<()> {
        serde_json::from_value::<EmailConfig>(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid email config: {e}"))?;
        Ok(())
    }

    fn create_channel(
        &self,
        instance_id: &str,
        config: &Value,
    ) -> Result<Box<dyn NotificationChannel>> {
        let cfg: EmailConfig = serde_json::from_value(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid email config: {e}"))?;
        let channel = EmailChannel::new(
            instance_id,
            &cfg.smtp_host,
            cfg.smtp_port,
            cfg.smtp_username.as_deref(),
            cfg.smtp_password.as_deref(),
            &cfg.from_name,
            &cfg.from_email,
        )?;
        Ok(Box::new(channel))
    }

    fn redact_config(&self, config: &Value) -> Value {
        let mut redacted = config.clone();
        if let Some(obj) = redacted.as_object_mut() {
            if obj.contains_key("smtp_password") {
                obj.insert(
                    "smtp_password".to_string(),
                    Value::String("***".to_string()),
                );
            }
        }
        redacted
    }
}
