pub mod channels;
pub mod manager;
pub mod routing;

#[cfg(test)]
mod tests;

use anyhow::Result;
use async_trait::async_trait;
use oxmon_common::types::AlertEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    Email,
    Webhook,
    Sms,
}

#[async_trait]
pub trait NotificationChannel: Send + Sync {
    async fn send(&self, alert: &AlertEvent) -> Result<()>;
    fn channel_type(&self) -> ChannelType;
}
