pub mod channels;
pub mod manager;
pub mod plugin;
pub mod routing;

#[cfg(test)]
mod tests;

use anyhow::Result;
use async_trait::async_trait;
use oxmon_common::types::AlertEvent;

#[async_trait]
pub trait NotificationChannel: Send + Sync {
    async fn send(&self, alert: &AlertEvent) -> Result<()>;
    fn channel_name(&self) -> &str;
}
