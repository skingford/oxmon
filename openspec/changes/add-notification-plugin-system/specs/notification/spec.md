## MODIFIED Requirements

### Requirement: Notification channels SHALL be configurable via TOML
Notification channels and routing rules SHALL be defined in the Server's TOML configuration file. Each channel section uses `type` to select the channel plugin, and all remaining fields are passed as plugin-specific configuration.

#### Scenario: Configure email channel
- **WHEN** Server starts with an `[[notification.channels]]` section containing type="email", smtp_host, smtp_port, from, recipients, and min_severity
- **THEN** the system SHALL use the "email" plugin from the registry to create and register this email channel

#### Scenario: Configure Webhook channel
- **WHEN** Server starts with an `[[notification.channels]]` section containing type="webhook", url, and optional body_template
- **THEN** the system SHALL use the "webhook" plugin from the registry to create and register this Webhook channel

#### Scenario: Configure DingTalk channel
- **WHEN** Server starts with an `[[notification.channels]]` section containing type="dingtalk", webhook_url, and optional secret
- **THEN** the system SHALL use the "dingtalk" plugin from the registry to create and register this DingTalk channel

#### Scenario: Configure WeChat Work channel
- **WHEN** Server starts with an `[[notification.channels]]` section containing type="weixin" and webhook_url
- **THEN** the system SHALL use the "weixin" plugin from the registry to create and register this WeChat Work channel

#### Scenario: Configure unknown channel type
- **WHEN** Server starts with an `[[notification.channels]]` section containing an unrecognized type value
- **THEN** the system SHALL log a warning and skip this channel without affecting other channels

#### Scenario: Multiple channels of the same type
- **WHEN** Server config contains two `[[notification.channels]]` sections with type="dingtalk" but different webhook_url values
- **THEN** the system SHALL create two separate DingTalk channel instances, each with its own configuration
