## ADDED Requirements

### Requirement: Notification system SHALL send alerts via email
The notification system SHALL support sending alert notifications through SMTP email.

#### Scenario: Send email notification
- **WHEN** an AlertEvent is generated and an email channel is configured
- **THEN** the system SHALL send an email to all configured recipients containing the alert details (agent, metric, value, severity, timestamp, rule description)

#### Scenario: Email delivery failure
- **WHEN** SMTP delivery fails (connection refused, authentication error, etc.)
- **THEN** the system SHALL log the failure and retry up to 3 times with exponential backoff

### Requirement: Notification system SHALL send alerts via Webhook
The notification system SHALL support sending alert notifications to Webhook endpoints (compatible with Feishu, DingTalk, Slack, and generic HTTP endpoints).

#### Scenario: Send Webhook notification
- **WHEN** an AlertEvent is generated and a Webhook channel is configured
- **THEN** the system SHALL POST a JSON payload to the configured Webhook URL containing alert details

#### Scenario: Webhook with custom template
- **WHEN** a Webhook channel is configured with a custom body template
- **THEN** the system SHALL render the template with alert variables and send the rendered payload

#### Scenario: Webhook delivery failure
- **WHEN** the Webhook endpoint returns a non-2xx status code or connection fails
- **THEN** the system SHALL log the failure and retry up to 3 times with exponential backoff

### Requirement: Notification system SHALL send alerts via SMS
The notification system SHALL support sending alert notifications through configurable SMS gateways.

#### Scenario: Send SMS notification
- **WHEN** an AlertEvent with severity "critical" is generated and an SMS channel is configured
- **THEN** the system SHALL send an SMS to all configured phone numbers containing a concise alert summary

#### Scenario: SMS gateway failure
- **WHEN** SMS gateway returns an error
- **THEN** the system SHALL log the failure and retry up to 3 times with exponential backoff

### Requirement: Notification system SHALL route alerts by severity
The notification system SHALL route AlertEvents to different notification channels based on their severity level.

#### Scenario: Route critical alert to all channels
- **WHEN** an AlertEvent with severity "critical" is generated
- **THEN** the system SHALL send notifications to all channels configured for "critical" severity

#### Scenario: Route info alert to limited channels
- **WHEN** an AlertEvent with severity "info" is generated
- **THEN** the system SHALL send notifications only to channels configured for "info" severity (e.g., Webhook only, not SMS)

#### Scenario: Channel severity filter
- **WHEN** a notification channel is configured with `min_severity = "warning"`
- **THEN** the system SHALL only send "warning" and "critical" alerts through this channel, skipping "info"

### Requirement: Notification system SHALL support silence windows
The notification system SHALL suppress notifications during configured silence windows.

#### Scenario: Alert during silence window
- **WHEN** an AlertEvent is generated during an active silence window (e.g., maintenance period)
- **THEN** the system SHALL NOT send any notifications, but SHALL still record the AlertEvent in history

#### Scenario: Alert outside silence window
- **WHEN** an AlertEvent is generated outside any configured silence window
- **THEN** the system SHALL process notifications normally according to routing rules

#### Scenario: Configure silence window
- **WHEN** Server config contains a silence window with start_time, end_time, and optional recurrence (daily/weekly)
- **THEN** the system SHALL suppress notifications during those time periods

### Requirement: Notification system SHALL aggregate similar alerts
The notification system SHALL aggregate multiple similar AlertEvents into a single notification when they occur in rapid succession.

#### Scenario: Aggregate alerts within window
- **WHEN** 5 AlertEvents for different agents but the same rule fire within a 1-minute aggregation window
- **THEN** the system SHALL send a single aggregated notification summarizing all 5 alerts

#### Scenario: Single alert without aggregation
- **WHEN** only 1 AlertEvent fires and no additional alerts for the same rule occur within the aggregation window
- **THEN** the system SHALL send a single notification for that alert

### Requirement: Notification channels SHALL be configurable via TOML
Notification channels and routing rules SHALL be defined in the Server's TOML configuration file.

#### Scenario: Configure email channel
- **WHEN** Server starts with an `[[notification.channels]]` section containing type="email", smtp_host, smtp_port, from, recipients, and min_severity
- **THEN** the system SHALL register this email channel for alert notifications

#### Scenario: Configure Webhook channel
- **WHEN** Server starts with an `[[notification.channels]]` section containing type="webhook", url, and optional body_template
- **THEN** the system SHALL register this Webhook channel for alert notifications
