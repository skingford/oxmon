//! Notification delivery framework with pluggable channel support.
//!
//! Alert events are routed to one or more [`NotificationChannel`]
//! implementations based on severity and routing configuration.
//! Built-in channels include email (SMTP), webhook, SMS, DingTalk,
//! and WeCom (WeChat Work).

pub mod channels;
pub mod manager;
pub mod plugin;
pub mod routing;

#[cfg(test)]
mod tests;

use anyhow::Result;
use async_trait::async_trait;
use oxmon_common::types::AlertEvent;

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
    /// # Errors
    ///
    /// Returns an error if delivery fails after retries (if applicable).
    async fn send(&self, alert: &AlertEvent, recipients: &[String]) -> Result<()>;

    /// Returns the channel type name (e.g., `"email"`, `"webhook"`).
    fn channel_type(&self) -> &str;

    /// Returns the unique instance ID (database row ID) for this channel.
    fn instance_id(&self) -> &str;
}
