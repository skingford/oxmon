use crate::NotificationChannel;
use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

pub trait ChannelPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn validate_config(&self, config: &Value) -> Result<()>;
    fn create_channel(&self, config: &Value) -> Result<Box<dyn NotificationChannel>>;
}

pub struct ChannelRegistry {
    plugins: HashMap<String, Box<dyn ChannelPlugin>>,
}

impl ChannelRegistry {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    pub fn register(&mut self, plugin: Box<dyn ChannelPlugin>) {
        let name = plugin.name().to_string();
        self.plugins.insert(name, plugin);
    }

    pub fn create_channel(
        &self,
        type_name: &str,
        config: &Value,
    ) -> Result<Box<dyn NotificationChannel>> {
        let plugin = self
            .plugins
            .get(type_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown channel plugin type: {type_name}"))?;
        plugin.validate_config(config)?;
        plugin.create_channel(config)
    }

    pub fn has_plugin(&self, type_name: &str) -> bool {
        self.plugins.contains_key(type_name)
    }

    pub fn plugin_names(&self) -> Vec<&str> {
        self.plugins.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ChannelRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(crate::channels::email::EmailPlugin));
        registry.register(Box::new(crate::channels::webhook::WebhookPlugin));
        registry.register(Box::new(crate::channels::sms::SmsPlugin));
        registry.register(Box::new(crate::channels::dingtalk::DingTalkPlugin));
        registry.register(Box::new(crate::channels::weixin::WeixinPlugin));
        registry
    }
}
