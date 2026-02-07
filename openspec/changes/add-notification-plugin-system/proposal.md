## Why

The current notification system hardcodes three channel types (Email, Webhook, SMS) in both config parsing and instantiation. Adding a new channel (e.g., DingTalk, WeChat, Telegram) requires modifying `ChannelConfig`, `ChannelType` enum, `build_notification_channels()`, and adding new channel-specific fields to the flat config struct. This tight coupling makes it difficult for users to freely select and integrate notification channels. A plugin-based architecture would let each channel be self-contained with its own config schema, and new channels can be added by implementing a single trait without touching core code.

## What Changes

- **BREAKING**: Replace the flat `ChannelConfig` struct with a plugin-based config where each channel type defines its own config schema via `serde_json::Value`
- Introduce a `ChannelPlugin` trait that bundles channel metadata, config validation, and channel instantiation
- Create a `ChannelRegistry` for registering available channel plugins at startup
- Refactor `build_notification_channels()` to use the registry for dynamic channel instantiation
- Add built-in plugins: `email`, `webhook`, `sms`, `dingtalk`, `weixin` (WeChat Work / 企业微信)
- New TOML config format: `type` selects the plugin, all other fields are passed as plugin-specific config

## Capabilities

### New Capabilities
- `notification-plugin`: Plugin trait, registry, and dynamic channel instantiation system
- `channel-dingtalk`: DingTalk (钉钉) robot webhook notification channel plugin
- `channel-weixin`: WeChat Work (企业微信) group robot notification channel plugin

### Modified Capabilities
- `notification`: Config format changes from flat struct to plugin-based `type` + plugin-specific fields; existing email/webhook/sms channels refactored into plugins

## Impact

- **Modified crate**: `oxmon-notify` — new plugin trait, registry, refactored channel implementations
- **Modified crate**: `oxmon-server` — config parsing, `build_notification_channels()` replaced with registry-based instantiation
- **Config format**: `[[notification.channels]]` sections remain, but channel-specific fields are now plugin-defined (email/webhook/sms configs stay backward-compatible)
- **No new dependencies**: DingTalk and WeChat Work use simple HTTP POST (reqwest already available)
- **Breaking change**: `ChannelConfig` struct replaced; custom integrations referencing internal config types need updating
