## ADDED Requirements

### Requirement: Dashboard SHALL display system overview
The dashboard page at `/dashboard` SHALL show an overview of the entire monitoring system including agent status, key metrics, and recent alerts.

#### Scenario: Dashboard loads successfully
- **WHEN** user navigates to `/dashboard`
- **THEN** the page SHALL call `GET /api/v1/health`, `GET /api/v1/agents`, and `GET /api/v1/alerts/history?limit=10` and render the overview

### Requirement: Dashboard SHALL show agent online rate
The dashboard SHALL display a summary card showing the total number of agents, the number of active agents, and the online rate as a percentage.

#### Scenario: Agent status summary
- **WHEN** the dashboard loads with 5 agents where 3 are active
- **THEN** the summary card SHALL display "3 / 5 在线" with "60%" online rate and a green/red indicator

### Requirement: Dashboard SHALL show server health metrics
The dashboard SHALL display health cards for server version, uptime, and storage status sourced from the `/api/v1/health` endpoint.

#### Scenario: Server health display
- **WHEN** the health endpoint returns version "0.1.0" and uptime 86400
- **THEN** the health card SHALL display version "0.1.0" and uptime formatted as "1 天"

### Requirement: Dashboard SHALL show recent alerts
The dashboard SHALL display the 10 most recent alert events in a list, ordered by timestamp descending, with severity color-coding.

#### Scenario: Recent alerts list
- **WHEN** the dashboard loads with alert history
- **THEN** each alert row SHALL display severity badge (critical=`#FF3B30`, warning=`#FF9500`, info=`#0071E3`), agent ID, metric name, message, and relative timestamp

#### Scenario: No recent alerts
- **WHEN** the alert history returns an empty array
- **THEN** the dashboard SHALL display an empty state with message "暂无告警记录"

### Requirement: Dashboard SHALL follow Apple Light Theme card layout
The dashboard SHALL use a card-based grid layout on `#F5F5F7` background with white cards, 12px border-radius, and `0 2px 12px rgba(0,0,0,0.08)` shadow.

#### Scenario: Dashboard layout
- **WHEN** the dashboard is rendered on a desktop viewport (>=1024px)
- **THEN** summary cards SHALL display in a horizontal row, and the alerts list SHALL span full width below
