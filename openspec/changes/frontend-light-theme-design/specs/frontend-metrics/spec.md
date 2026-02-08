## ADDED Requirements

### Requirement: Metrics page SHALL query and display time-series data
The metrics page at `/metrics` SHALL allow users to select an agent, metric name, and time range, then display the results as a line chart.

#### Scenario: Query metrics with filters
- **WHEN** user selects agent "web-server-01", metric "cpu.usage", and time range "last 1 hour"
- **THEN** the frontend SHALL call `GET /api/v1/metrics?agent=web-server-01&metric=cpu.usage&from=...&to=...` and render a line chart with timestamp on X-axis and value on Y-axis

#### Scenario: Missing required fields
- **WHEN** user clicks "查询" without selecting agent or metric
- **THEN** the frontend SHALL show inline validation errors on the empty fields

### Requirement: Metrics page SHALL provide time range presets
The metrics page SHALL offer quick time range buttons: 1 hour, 6 hours, 24 hours, 7 days, and a custom date-time picker.

#### Scenario: Preset time range selection
- **WHEN** user clicks "最近 1 小时"
- **THEN** the `from` parameter SHALL be set to current time minus 1 hour, and `to` SHALL be set to current time, and the query SHALL execute automatically

#### Scenario: Custom time range
- **WHEN** user selects "自定义" and picks a start and end date-time
- **THEN** the frontend SHALL use those values as `from` and `to` parameters

### Requirement: Metrics page SHALL populate agent and metric dropdowns
The agent dropdown SHALL be populated from `GET /api/v1/agents`. The metric dropdown SHALL provide common metric names as static options.

#### Scenario: Agent dropdown
- **WHEN** the metrics page loads
- **THEN** the agent dropdown SHALL list all agents returned by `GET /api/v1/agents`

#### Scenario: Metric dropdown
- **WHEN** user opens the metric dropdown
- **THEN** the dropdown SHALL include: cpu.usage, memory.used_percent, disk.used_percent, load.load_1, load.load_5, load.load_15, network.bytes_sent, network.bytes_recv

### Requirement: Metrics chart SHALL follow Apple design style
The chart SHALL use `#0071E3` as the primary line color, `#F5F5F7` as the chart background, Inter font for labels, and subtle grid lines in `#E5E5EA`.

#### Scenario: Chart rendering
- **WHEN** metric data is returned and chart is rendered
- **THEN** the chart SHALL display a smooth line in `#0071E3` with a light blue fill area below, tooltip on hover showing exact timestamp and value
