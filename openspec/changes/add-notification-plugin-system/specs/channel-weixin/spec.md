## ADDED Requirements

### Requirement: WeChat Work notification channel plugin
The system SHALL provide a built-in "weixin" channel plugin that sends alert notifications to WeChat Work (企业微信) group robot webhooks using Markdown-formatted messages.

#### Scenario: Send WeChat Work notification
- **WHEN** an AlertEvent is routed to a configured WeChat Work channel
- **THEN** the system SHALL POST a JSON payload with `msgtype: "markdown"` to the configured WeChat Work webhook URL containing alert severity, agent ID, metric name, value, threshold, and timestamp

#### Scenario: WeChat Work delivery failure
- **WHEN** the WeChat Work webhook returns a non-zero `errcode` or HTTP request fails
- **THEN** the system SHALL log the failure and retry up to 3 times with exponential backoff

### Requirement: WeChat Work plugin config validation
The WeChat Work plugin SHALL require a `webhook_url` field.

#### Scenario: Valid WeChat Work config
- **WHEN** the plugin validates a config with `webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"`
- **THEN** validation SHALL succeed

#### Scenario: Missing webhook_url
- **WHEN** the plugin validates a config without `webhook_url`
- **THEN** validation SHALL fail with an error message indicating webhook_url is required

### Requirement: WeChat Work Markdown message format
The WeChat Work plugin SHALL format alert messages using Markdown supported by the 企业微信 robot API.

#### Scenario: Markdown message content
- **WHEN** an AlertEvent is sent via the WeChat Work channel
- **THEN** the message content SHALL include a header with severity indicator, and body lines for agent ID, metric name, current value, threshold, alert message, and timestamp, formatted in Markdown
