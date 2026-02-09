## ADDED Requirements

### Requirement: Alerts page SHALL display alert rules
The alerts page at `/alerts` SHALL display all configured alert rules in a table from `GET /api/v1/alerts/rules`.

#### Scenario: Alert rules list
- **WHEN** user navigates to `/alerts`
- **THEN** the page SHALL display a table with columns: Rule Name, Type (threshold/rate_of_change/trend_prediction/cert_expiration), Metric, Agent Pattern, Severity (color-coded badge), Parameters

### Requirement: Alerts page SHALL display alert history with filtering
The alerts page SHALL provide an "告警历史" tab showing historical alert events from `GET /api/v1/alerts/history` with filters.

#### Scenario: Alert history default view
- **WHEN** user clicks the "告警历史" tab
- **THEN** the page SHALL display the 50 most recent alerts ordered by timestamp descending, with columns: Severity, Agent, Metric, Message, Value/Threshold, Timestamp

#### Scenario: Filter by severity
- **WHEN** user selects "critical" from the severity filter dropdown
- **THEN** the frontend SHALL call `GET /api/v1/alerts/history?severity=critical` and display only critical alerts

#### Scenario: Filter by agent
- **WHEN** user enters "web-server-01" in the agent filter input
- **THEN** the frontend SHALL call `GET /api/v1/alerts/history?agent=web-server-01` and display only alerts for that agent

#### Scenario: Filter by time range
- **WHEN** user selects a start and end date for alert history
- **THEN** the frontend SHALL include `from` and `to` query parameters

### Requirement: Alert history SHALL support pagination
The alert history SHALL use paginated loading with configurable page size.

#### Scenario: Pagination controls
- **WHEN** alert history returns results
- **THEN** the page SHALL display pagination controls (Previous / Next / page number) and page size selector (10, 25, 50, 100)

#### Scenario: Navigate to next page
- **WHEN** user clicks "Next" on page 1 with page size 50
- **THEN** the frontend SHALL call `GET /api/v1/alerts/history?limit=50&offset=50`

### Requirement: Alert severity SHALL use color-coded badges
Alert severity SHALL be displayed as colored badges consistent with the Apple Light Theme palette.

#### Scenario: Severity badge colors
- **WHEN** alerts are rendered
- **THEN** critical SHALL use `#FF3B30` background, warning SHALL use `#FF9500` background, info SHALL use `#0071E3` background, all with white text and 4px border-radius
