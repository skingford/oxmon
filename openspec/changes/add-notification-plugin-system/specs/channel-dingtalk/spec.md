## ADDED Requirements

### Requirement: DingTalk notification channel plugin
The system SHALL provide a built-in "dingtalk" channel plugin that sends alert notifications to DingTalk (钉钉) group robot webhooks using Markdown-formatted messages.

#### Scenario: Send DingTalk notification
- **WHEN** an AlertEvent is routed to a configured DingTalk channel
- **THEN** the system SHALL POST a JSON payload with `msgtype: "markdown"` to the configured DingTalk webhook URL containing alert severity, agent ID, metric name, value, threshold, and timestamp

#### Scenario: DingTalk delivery failure
- **WHEN** the DingTalk webhook returns a non-zero `errcode` or HTTP request fails
- **THEN** the system SHALL log the failure and retry up to 3 times with exponential backoff

### Requirement: DingTalk plugin config validation
The DingTalk plugin SHALL require a `webhook_url` field and optionally accept a `secret` field for message signing.

#### Scenario: Valid DingTalk config
- **WHEN** the plugin validates a config with `webhook_url = "https://oapi.dingtalk.com/robot/send?access_token=xxx"`
- **THEN** validation SHALL succeed

#### Scenario: Missing webhook_url
- **WHEN** the plugin validates a config without `webhook_url`
- **THEN** validation SHALL fail with an error message indicating webhook_url is required

### Requirement: DingTalk message signing
The DingTalk plugin SHALL support optional HMAC-SHA256 message signing when a `secret` is configured.

#### Scenario: Send with signing enabled
- **WHEN** the DingTalk channel config includes a non-empty `secret`
- **THEN** the system SHALL compute a HMAC-SHA256 signature using the secret and current timestamp, and append `&timestamp=xxx&sign=xxx` to the webhook URL

#### Scenario: Send without signing
- **WHEN** the DingTalk channel config has no `secret` or an empty `secret`
- **THEN** the system SHALL POST to the webhook URL without signature parameters
