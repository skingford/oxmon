## 1. Plugin Trait and Registry (oxmon-notify)

- [x] 1.1 Add `hmac` and `sha2` dependencies to workspace `Cargo.toml` (for DingTalk signing)
- [x] 1.2 Add `hmac`, `sha2`, `base64` to `oxmon-notify/Cargo.toml`
- [x] 1.3 Define `ChannelPlugin` trait in `oxmon-notify/src/plugin.rs` with `name()`, `validate_config()`, `create_channel()` methods
- [x] 1.4 Implement `ChannelRegistry` struct with `HashMap<String, Box<dyn ChannelPlugin>>`, `register()`, `create_channel()`, and `Default` impl that registers all built-in plugins
- [x] 1.5 Export `plugin` module and `ChannelRegistry` from `oxmon-notify/src/lib.rs`

## 2. Refactor Existing Channels as Plugins (oxmon-notify)

- [x] 2.1 Create `EmailPlugin` in `oxmon-notify/src/channels/email.rs` implementing `ChannelPlugin` — deserializes config Value into smtp_host/port/username/password/from/recipients and creates `EmailChannel`
- [x] 2.2 Create `WebhookPlugin` in `oxmon-notify/src/channels/webhook.rs` implementing `ChannelPlugin` — deserializes config Value into url/body_template and creates `WebhookChannel`
- [x] 2.3 Create `SmsPlugin` in `oxmon-notify/src/channels/sms.rs` implementing `ChannelPlugin` — deserializes config Value into gateway_url/api_key/phone_numbers and creates `SmsChannel`

## 3. DingTalk Plugin (oxmon-notify)

- [x] 3.1 Create `oxmon-notify/src/channels/dingtalk.rs` with `DingTalkChannel` struct (webhook_url, secret, reqwest::Client)
- [x] 3.2 Implement `NotificationChannel` for `DingTalkChannel` — POST Markdown message to DingTalk robot webhook, 3-retry with exponential backoff
- [x] 3.3 Implement HMAC-SHA256 message signing: when secret is set, compute sign and append `&timestamp=xxx&sign=xxx` to webhook URL
- [x] 3.4 Create `DingTalkPlugin` implementing `ChannelPlugin` — validate webhook_url required, optional secret, create DingTalkChannel
- [x] 3.5 Register `DingTalkPlugin` in `ChannelRegistry::default()`

## 4. WeChat Work Plugin (oxmon-notify)

- [x] 4.1 Create `oxmon-notify/src/channels/weixin.rs` with `WeixinChannel` struct (webhook_url, reqwest::Client)
- [x] 4.2 Implement `NotificationChannel` for `WeixinChannel` — POST Markdown message to WeChat Work robot webhook, 3-retry with exponential backoff
- [x] 4.3 Create `WeixinPlugin` implementing `ChannelPlugin` — validate webhook_url required, create WeixinChannel
- [x] 4.4 Register `WeixinPlugin` in `ChannelRegistry::default()`

## 5. Server Integration (oxmon-server)

- [x] 5.1 Replace `ChannelConfig` in `config.rs` with `RawChannelConfig` using `#[serde(flatten)]` for plugin-specific fields
- [x] 5.2 Replace `build_notification_channels()` in `main.rs` with registry-based instantiation: create `ChannelRegistry::default()`, iterate configs, call `registry.create_channel(type, config)`
- [x] 5.3 Remove `ChannelType` enum from `oxmon-notify/src/lib.rs` (no longer needed — plugins self-identify by name)

## 6. Config and Documentation

- [x] 6.1 Add DingTalk example channel section to `config/server.example.toml`
- [x] 6.2 Add WeChat Work example channel section to `config/server.example.toml`
- [x] 6.3 Update README.md: add DingTalk and WeChat Work notification channel documentation with config examples
- [x] 6.4 Update OpenAPI spec in `openapi.rs` if notification-related schemas are affected (N/A — no notification schemas in OpenAPI)

## 7. Testing

- [x] 7.1 Unit test: `ChannelRegistry::default()` contains all 5 built-in plugins
- [x] 7.2 Unit test: registry returns error for unknown plugin type
- [x] 7.3 Unit test: `DingTalkPlugin` validates config (accepts valid, rejects missing webhook_url)
- [x] 7.4 Unit test: `WeixinPlugin` validates config (accepts valid, rejects missing webhook_url)
- [x] 7.5 Unit test: DingTalk HMAC-SHA256 signing produces correct URL format
- [x] 7.6 Unit test: existing `EmailPlugin`/`WebhookPlugin`/`SmsPlugin` validate config correctly
