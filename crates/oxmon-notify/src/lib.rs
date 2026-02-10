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
#[async_trait]
pub trait NotificationChannel: Send + Sync {
    /// Delivers the alert event through this channel.
    ///
    /// # Errors
    ///
    /// Returns an error if delivery fails after retries (if applicable).
    async fn send(&self, alert: &AlertEvent) -> Result<()>;

    /// Returns the channel type name (e.g., `"email"`, `"webhook"`).
    fn channel_name(&self) -> &str;
}
