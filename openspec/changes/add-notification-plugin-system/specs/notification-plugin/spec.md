## ADDED Requirements

### Requirement: Channel plugin trait for self-contained channel definitions
The system SHALL provide a `ChannelPlugin` trait that allows each notification channel to define its own config validation and channel instantiation logic. The trait SHALL include methods for returning the plugin name, validating a plugin-specific config, and creating a `NotificationChannel` instance.

#### Scenario: Plugin provides its name
- **WHEN** the system queries a registered plugin
- **THEN** the plugin SHALL return a unique string identifier (e.g., "email", "dingtalk", "weixin")

#### Scenario: Plugin validates valid config
- **WHEN** `validate_config()` is called with a valid config Value containing all required fields
- **THEN** the plugin SHALL return `Ok(())`

#### Scenario: Plugin rejects invalid config
- **WHEN** `validate_config()` is called with a config Value missing required fields
- **THEN** the plugin SHALL return an error describing which field is missing or invalid

#### Scenario: Plugin creates channel from valid config
- **WHEN** `create_channel()` is called with a validated config Value
- **THEN** the plugin SHALL return a `Box<dyn NotificationChannel>` ready to send notifications

### Requirement: Channel registry for dynamic plugin lookup
The system SHALL provide a `ChannelRegistry` that maps channel type names to `ChannelPlugin` instances. The registry SHALL allow looking up a plugin by its type name and creating channels via the plugin.

#### Scenario: Registry with default built-in plugins
- **WHEN** a `ChannelRegistry` is created with defaults
- **THEN** it SHALL contain plugins for "email", "webhook", "sms", "dingtalk", and "weixin"

#### Scenario: Create channel via registry
- **WHEN** `create_channel("dingtalk", config)` is called on the registry
- **THEN** the registry SHALL look up the "dingtalk" plugin, validate the config, and return the created channel

#### Scenario: Unknown plugin type
- **WHEN** `create_channel("unknown_type", config)` is called
- **THEN** the registry SHALL return an error indicating the plugin type is not registered

### Requirement: Registry-based channel instantiation at startup
The system SHALL use the `ChannelRegistry` to instantiate notification channels from TOML config at server startup, replacing the hardcoded match-based instantiation.

#### Scenario: Startup with mixed channel types
- **WHEN** the server starts with config containing `type = "email"`, `type = "dingtalk"`, and `type = "weixin"` channel sections
- **THEN** the system SHALL use the registry to create all three channels and register them with the NotificationManager

#### Scenario: Startup with invalid plugin config
- **WHEN** the server starts with a channel section where required plugin fields are missing
- **THEN** the system SHALL log an error for that channel and skip it, continuing to process other channels

#### Scenario: Startup with unknown channel type
- **WHEN** the server starts with `type = "nonexistent"` in a channel section
- **THEN** the system SHALL log a warning and skip that channel
