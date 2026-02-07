## Context

The current notification system in `oxmon-notify` has a clean `NotificationChannel` trait, but channel types are tightly coupled to the server crate:

- `ChannelConfig` is a flat struct mixing fields for all channel types (smtp_host, url, gateway_url, etc.)
- `ChannelType` is a closed enum (`Email`, `Webhook`, `Sms`)
- `build_notification_channels()` in `main.rs` uses a hardcoded `match` on type string to instantiate channels
- Adding a new channel requires touching 4+ files across 2 crates

The user wants to freely select and integrate channels like DingTalk (钉钉), WeChat Work (企业微信), and others without modifying core code.

## Goals / Non-Goals

**Goals:**
- Each channel plugin is self-contained: owns its config validation, instantiation, and send logic
- Adding a new channel requires only implementing a trait and registering it — no changes to core code
- Existing TOML config format remains backward-compatible for email/webhook/sms
- Built-in plugins for DingTalk and WeChat Work group robots

**Non-Goals:**
- Dynamic loading of external plugins (shared libraries / .so / .dylib) — compile-time registration is sufficient for this use case
- Plugin marketplace or hot-reload — channels are registered at startup
- UI for plugin management — config-driven only

## Decisions

### 1. `ChannelPlugin` trait replacing hardcoded instantiation

**Decision**: Introduce a `ChannelPlugin` trait that bundles channel metadata, config validation, and factory method:

```rust
pub trait ChannelPlugin: Send + Sync {
    fn name(&self) -> &str;                    // e.g., "email", "dingtalk"
    fn validate_config(&self, config: &Value) -> Result<()>;
    fn create_channel(&self, config: &Value) -> Result<Box<dyn NotificationChannel>>;
}
```

Config is passed as `serde_json::Value`, allowing each plugin to define its own schema without a shared struct.

**Rationale**: This keeps the existing `NotificationChannel` trait untouched (it's already well-designed for send/routing). The `ChannelPlugin` only handles the creation concern. Each plugin can deserialize the `Value` into its own typed config struct internally.

**Alternatives considered**:
- Merging plugin + channel into one trait — increases complexity of the channel trait which is currently minimal and focused
- Using Rust generics/associated types for config — makes dynamic dispatch harder and complicates the registry

### 2. `ChannelRegistry` for compile-time plugin registration

**Decision**: A simple `ChannelRegistry` struct that maps channel type names to `Box<dyn ChannelPlugin>`:

```rust
pub struct ChannelRegistry {
    plugins: HashMap<String, Box<dyn ChannelPlugin>>,
}
```

Built-in plugins are registered in `ChannelRegistry::default()`. The registry provides `create_channel(type_name, config)` which looks up the plugin and delegates.

**Rationale**: Simple, zero-overhead, no macros needed. Registration happens once at startup. The HashMap lookup by type name naturally maps to the TOML `type = "dingtalk"` field.

**Alternatives considered**:
- `inventory` crate for auto-registration via proc macros — adds a dependency for minimal benefit with <10 built-in plugins
- Global static registry — harder to test, doesn't support dependency injection

### 3. TOML config: type + plugin-specific fields via `serde_json::Value`

**Decision**: Parse each `[[notification.channels]]` section as:

```rust
struct RawChannelConfig {
    #[serde(rename = "type")]
    pub channel_type: String,
    pub min_severity: String,
    #[serde(flatten)]
    pub config: serde_json::Value,  // all remaining fields
}
```

The `#[serde(flatten)]` captures all non-standard fields into a `Value` map, which is passed to the plugin for validation and channel creation.

**Rationale**: This preserves backward compatibility — existing `type = "email"` sections with smtp_host etc. still work unchanged. New channels like `type = "dingtalk"` just add their own fields. No migration needed for existing configs.

**Alternatives considered**:
- Nested table `[notification.channels.config]` — breaks backward compatibility, more verbose
- Per-channel-type TOML sections `[notification.email]` — doesn't support multiple instances of the same channel type

### 4. DingTalk plugin: robot webhook with message signing

**Decision**: DingTalk plugin sends Markdown-formatted messages to DingTalk group robot webhook. Config:

```toml
[[notification.channels]]
type = "dingtalk"
min_severity = "warning"
webhook_url = "https://oapi.dingtalk.com/robot/send?access_token=xxx"
secret = ""  # optional: signing secret for security verification
```

Uses the standard DingTalk robot webhook API with `msgtype: "markdown"` for rich formatting.

**Rationale**: DingTalk robot webhook is the standard integration point. Markdown gives better formatting than plain text. Secret-based signing is optional but recommended.

### 5. WeChat Work plugin: group robot webhook

**Decision**: WeChat Work plugin sends Markdown messages to 企业微信 group robot webhook. Config:

```toml
[[notification.channels]]
type = "weixin"
min_severity = "warning"
webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"
```

Uses the standard WeChat Work robot webhook API with `msgtype: "markdown"`.

**Rationale**: WeChat Work group robot webhook is the simplest integration — no OAuth, no app registration, just a webhook URL per group. Markdown formatting matches the DingTalk approach for consistency.

### 6. Refactor existing channels as plugins

**Decision**: Wrap existing `EmailChannel`, `WebhookChannel`, `SmsChannel` implementations as plugins without changing their internal logic. Each gets a `XxxPlugin` struct implementing `ChannelPlugin` that deserializes config and delegates to the existing constructor.

**Rationale**: Zero risk to existing behavior. The actual send/retry logic in each channel remains untouched. Only the instantiation path changes from hardcoded match to registry lookup.

## Risks / Trade-offs

- **Config validation errors become runtime** instead of compile-time: Plugin receives `Value` and can fail at startup → Mitigation: `validate_config()` is called before `create_channel()`, startup fails fast with clear error messages indicating which plugin and which field is invalid
- **`serde(flatten)` quirk**: When used with TOML, `type` and `min_severity` are excluded from the flattened Value but all other fields pass through → Mitigation: document that plugin config fields must not conflict with `type`/`min_severity`; test with each plugin
- **Breaking change for custom integrations**: Any code directly referencing `ChannelConfig` fields breaks → Mitigation: This is internal to oxmon, not a public API; the TOML config format stays compatible

## Migration Plan

1. Add `ChannelPlugin` trait and `ChannelRegistry` to `oxmon-notify`
2. Wrap existing Email/Webhook/SMS as plugins (no behavior change)
3. Replace `build_notification_channels()` with registry-based instantiation
4. Add DingTalk and WeChat Work plugins
5. Update config docs and examples
6. Existing `server.toml` files work unchanged — no user migration needed
