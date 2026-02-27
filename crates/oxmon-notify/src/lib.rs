//! Notification delivery framework with pluggable channel support.
//!
//! Alert events are routed to one or more [`NotificationChannel`]
//! implementations based on severity and routing configuration.
//! Built-in channels include email (SMTP), webhook, SMS, DingTalk,
//! and WeCom (WeChat Work).

pub mod cert_report_template;
pub mod channels;
pub mod manager;
pub mod plugin;
pub mod report_template;
pub mod routing;
pub mod utils;

#[cfg(test)]
mod tests;

use anyhow::Result;
use async_trait::async_trait;
use oxmon_common::types::AlertEvent;

pub use manager::{RecipientResult, SendResponse};

/// A notification delivery channel that sends alert events to an external
/// service (e.g., SMTP, webhook, SMS gateway).
///
/// Implementations are created by the corresponding [`plugin::ChannelPlugin`]
/// and registered in the notification manager's routing table.
///
/// Each channel instance carries an `instance_id` (database primary key) and
/// a `channel_type` (plugin type name). The `recipients` parameter enables
/// the same channel instance to target multiple addresses without embedding
/// them in the channel struct.
#[async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Delivers the alert event to the given recipients.
    ///
    /// `recipients` contains addresses relevant to the channel type:
    /// email addresses, phone numbers, webhook URLs, etc.
    /// An empty slice means the channel should skip delivery.
    ///
    /// The `locale` parameter controls the language of notification messages
    /// (e.g., `"zh-CN"`, `"en"`).
    ///
    /// Returns detailed response information including HTTP status,
    /// response/request bodies, retry count, and per-recipient results.
    ///
    /// # Errors
    ///
    /// Returns an error if delivery fails after retries (if applicable).
    async fn send(
        &self,
        alert: &AlertEvent,
        recipients: &[String],
        locale: &str,
    ) -> Result<SendResponse>;

    /// Send a structured cert alert report with format-specific content.
    ///
    /// Channel implementations that support rich formatting (e.g., email → HTML,
    /// DingTalk / WeChat Work → Markdown) should override this method.
    /// The manager falls back to [`send`] with a plain-text synthetic event when
    /// this returns `None`.
    ///
    /// - `subject`          – email subject / message title
    /// - `html_content`     – full HTML string (for email)
    /// - `markdown_content` – Markdown string (for DingTalk / WeChat Work)
    /// - `plain_content`    – plain text (for SMS / webhook / fallback)
    async fn send_cert_report(
        &self,
        subject: &str,
        html_content: &str,
        markdown_content: &str,
        plain_content: &str,
        recipients: &[String],
    ) -> Option<Result<SendResponse>> {
        let _ = (subject, html_content, markdown_content, plain_content, recipients);
        None
    }

    /// Returns the channel type name (e.g., `"email"`, `"webhook"`).
    fn channel_type(&self) -> &str;

    /// Returns the unique instance ID (database row ID) for this channel.
    fn instance_id(&self) -> &str;
}
