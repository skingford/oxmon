## ADDED Requirements

### Requirement: Alert engine SHALL evaluate threshold rules
The alert engine SHALL support static threshold rules that fire when a metric exceeds a configured value for a sustained duration.

#### Scenario: Threshold exceeded for duration
- **WHEN** metric "cpu.usage" for agent "web-01" exceeds 90% continuously for 5 minutes (as configured in the rule)
- **THEN** the alert engine SHALL generate an AlertEvent with severity as configured in the rule

#### Scenario: Threshold not sustained
- **WHEN** metric "cpu.usage" for agent "web-01" exceeds 90% but drops below within the configured duration window
- **THEN** the alert engine SHALL NOT generate an AlertEvent

#### Scenario: Threshold with comparison operators
- **WHEN** a threshold rule is configured with operator "greater_than", "less_than", "greater_equal", or "less_equal"
- **THEN** the alert engine SHALL apply the specified comparison when evaluating the metric value

### Requirement: Alert engine SHALL evaluate rate-of-change rules
The alert engine SHALL support rate-of-change rules that fire when a metric's rate of change within a time window exceeds a threshold.

#### Scenario: Rate of change exceeded
- **WHEN** metric "memory.used_percent" increases by more than 20% within a 5-minute window (as configured)
- **THEN** the alert engine SHALL generate an AlertEvent

#### Scenario: Rate of change within normal range
- **WHEN** metric "memory.used_percent" increases by 5% within the configured 5-minute window (threshold is 20%)
- **THEN** the alert engine SHALL NOT generate an AlertEvent

### Requirement: Alert engine SHALL evaluate trend prediction rules
The alert engine SHALL support trend prediction rules that use linear regression to predict when a metric will reach a critical threshold.

#### Scenario: Predicted threshold breach within horizon
- **WHEN** linear regression on the last N data points of "disk.used_percent" predicts it will reach 95% within 24 hours (as configured)
- **THEN** the alert engine SHALL generate an AlertEvent with the predicted time-to-breach

#### Scenario: No predicted breach within horizon
- **WHEN** linear regression predicts "disk.used_percent" will NOT reach 95% within the configured prediction horizon
- **THEN** the alert engine SHALL NOT generate an AlertEvent

#### Scenario: Insufficient data for prediction
- **WHEN** fewer than the minimum required data points (default 10) are available for regression
- **THEN** the alert engine SHALL skip evaluation and NOT generate an AlertEvent

### Requirement: Alert engine SHALL use sliding windows for evaluation
The alert engine SHALL maintain sliding windows of recent metric data for each active rule.

#### Scenario: Sliding window populated
- **WHEN** new metric data arrives for an agent and metric covered by an active rule
- **THEN** the alert engine SHALL update the sliding window and trigger rule evaluation

#### Scenario: Sliding window eviction
- **WHEN** data points in the sliding window are older than the rule's configured window size
- **THEN** the alert engine SHALL evict those data points from the window

### Requirement: Alert engine SHALL support alert deduplication
The alert engine SHALL prevent duplicate alerts for the same rule and agent within a configurable silence period.

#### Scenario: Suppress duplicate alert during silence period
- **WHEN** a rule fires for agent "web-01" and an AlertEvent for the same rule and agent was generated within the last 10 minutes (configured silence period)
- **THEN** the alert engine SHALL NOT generate a new AlertEvent

#### Scenario: Allow alert after silence period expires
- **WHEN** a rule fires for agent "web-01" and the silence period for the previous AlertEvent has expired
- **THEN** the alert engine SHALL generate a new AlertEvent

### Requirement: Alert engine SHALL support alert severity levels
Each alert rule SHALL have a configurable severity level.

#### Scenario: Alert with configured severity
- **WHEN** a rule with severity "critical" fires
- **THEN** the generated AlertEvent SHALL have severity set to "critical"

#### Scenario: Supported severity levels
- **WHEN** configuring an alert rule
- **THEN** the system SHALL accept severity values of "info", "warning", or "critical"

### Requirement: Alert rules SHALL be configurable via TOML
Alert rules SHALL be defined in the Server's TOML configuration file.

#### Scenario: Define threshold rule in config
- **WHEN** Server starts with an `[[alert.rules]]` section containing type="threshold", metric, agent_pattern, operator, value, duration, and severity
- **THEN** the alert engine SHALL register and evaluate this rule

#### Scenario: Define rule with agent glob pattern
- **WHEN** a rule is configured with `agent_pattern = "web-*"`
- **THEN** the alert engine SHALL evaluate this rule against all agents whose ID matches the glob pattern
