use crate::plugin::ChannelPlugin;
use crate::NotificationChannel;
use anyhow::Result;
use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use oxmon_common::types::AlertEvent;
use serde::Deserialize;
use serde_json::Value;
use tracing;

pub struct EmailChannel {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
    recipients: Vec<String>,
}

impl EmailChannel {
    pub fn new(
        smtp_host: &str,
        smtp_port: u16,
        username: Option<&str>,
        password: Option<&str>,
        from: &str,
        recipients: Vec<String>,
    ) -> Result<Self> {
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_host)?.port(smtp_port);

        if let (Some(user), Some(pass)) = (username, password) {
            builder = builder.credentials(Credentials::new(user.to_string(), pass.to_string()));
        }

        let transport = builder.build();
        Ok(Self {
            transport,
            from: from.to_string(),
            recipients,
        })
    }

    fn format_body(alert: &AlertEvent) -> String {
        format!(
            "Alert: {severity}\nAgent: {agent}\nMetric: {metric}\nValue: {value:.2}\nThreshold: {threshold:.2}\nMessage: {message}\nTime: {time}",
            severity = alert.severity,
            agent = alert.agent_id,
            metric = alert.metric_name,
            value = alert.value,
            threshold = alert.threshold,
            message = alert.message,
            time = alert.timestamp,
        )
    }
}

#[async_trait]
impl NotificationChannel for EmailChannel {
    async fn send(&self, alert: &AlertEvent) -> Result<()> {
        let subject = format!(
            "[oxmon][{}] {} - {}",
            alert.severity, alert.metric_name, alert.agent_id
        );
        let body = Self::format_body(alert);

        for recipient in &self.recipients {
            let email = Message::builder()
                .from(self.from.parse()?)
                .to(recipient.parse()?)
                .subject(&subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body.clone())?;

            let mut last_err = None;
            for attempt in 0..3 {
                match self.transport.send(email.clone()).await {
                    Ok(_) => {
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            attempt = attempt + 1,
                            recipient = %recipient,
                            error = %e,
                            "Email send failed, retrying"
                        );
                        last_err = Some(e);
                        tokio::time::sleep(std::time::Duration::from_millis(
                            100 * 2u64.pow(attempt),
                        ))
                        .await;
                    }
                }
            }

            if let Some(e) = last_err {
                tracing::error!(recipient = %recipient, error = %e, "Email send failed after 3 retries");
            }
        }

        Ok(())
    }

    fn channel_name(&self) -> &str {
        "email"
    }
}

// Plugin

#[derive(Deserialize)]
struct EmailConfig {
    smtp_host: String,
    smtp_port: u16,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    from: String,
    recipients: Vec<String>,
}

pub struct EmailPlugin;

impl ChannelPlugin for EmailPlugin {
    fn name(&self) -> &str {
        "email"
    }

    fn validate_config(&self, config: &Value) -> Result<()> {
        serde_json::from_value::<EmailConfig>(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid email config: {e}"))?;
        Ok(())
    }

    fn create_channel(&self, config: &Value) -> Result<Box<dyn NotificationChannel>> {
        let cfg: EmailConfig = serde_json::from_value(config.clone())
            .map_err(|e| anyhow::anyhow!("Invalid email config: {e}"))?;
        let channel = EmailChannel::new(
            &cfg.smtp_host,
            cfg.smtp_port,
            cfg.smtp_username.as_deref(),
            cfg.smtp_password.as_deref(),
            &cfg.from,
            cfg.recipients,
        )?;
        Ok(Box::new(channel))
    }
}
