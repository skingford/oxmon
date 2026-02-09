## ADDED Requirements

### Requirement: API SHALL list registered agents
The REST API SHALL provide an endpoint to list all known agents and their status.

#### Scenario: List all agents
- **WHEN** a GET request is made to `/v1/agents`
- **THEN** the API SHALL return a JSON array of agents with id, last_seen timestamp, and status (active/inactive)

#### Scenario: Agent marked inactive
- **WHEN** an agent has not reported metrics for more than 3x the expected collection interval
- **THEN** the API SHALL return that agent's status as "inactive"

### Requirement: API SHALL query metric data
The REST API SHALL provide an endpoint to query metric time-series data.

#### Scenario: Query metrics with time range
- **WHEN** a GET request is made to `/v1/metrics?agent=web-01&metric=cpu.usage&from=2024-01-01T00:00:00Z&to=2024-01-01T01:00:00Z`
- **THEN** the API SHALL return a JSON array of data points with timestamp and value, ordered by timestamp ascending

#### Scenario: Query with step aggregation
- **WHEN** a GET request includes `&step=5m`
- **THEN** the API SHALL return data points aggregated at 5-minute intervals using average as the default aggregation function

#### Scenario: Query missing required parameters
- **WHEN** a GET request to `/v1/metrics` is missing the "agent" or "metric" parameter
- **THEN** the API SHALL return HTTP 400 with a JSON error describing the missing parameters

### Requirement: API SHALL query latest metric values
The REST API SHALL provide an endpoint to get the most recent value for each metric of an agent.

#### Scenario: Get latest metrics for agent
- **WHEN** a GET request is made to `/v1/agents/web-01/latest`
- **THEN** the API SHALL return a JSON object with the most recent value and timestamp for each metric reported by agent "web-01"

#### Scenario: Agent not found
- **WHEN** a GET request is made to `/v1/agents/unknown-agent/latest`
- **THEN** the API SHALL return HTTP 404 with a JSON error message

### Requirement: API SHALL list alert rules
The REST API SHALL provide an endpoint to list all configured alert rules.

#### Scenario: List all rules
- **WHEN** a GET request is made to `/v1/alerts/rules`
- **THEN** the API SHALL return a JSON array of all alert rules with their id, type, metric, agent_pattern, parameters, severity, and enabled status

### Requirement: API SHALL query alert history
The REST API SHALL provide an endpoint to query historical alert events.

#### Scenario: Query alert history with time range
- **WHEN** a GET request is made to `/v1/alerts/history?from=2024-01-01T00:00:00Z&to=2024-01-02T00:00:00Z`
- **THEN** the API SHALL return a JSON array of AlertEvents within the time range, ordered by timestamp descending

#### Scenario: Filter alert history by severity
- **WHEN** a GET request includes `&severity=critical`
- **THEN** the API SHALL return only AlertEvents with severity "critical"

#### Scenario: Filter alert history by agent
- **WHEN** a GET request includes `&agent=web-01`
- **THEN** the API SHALL return only AlertEvents related to agent "web-01"

#### Scenario: Paginated alert history
- **WHEN** a GET request includes `&limit=50&offset=100`
- **THEN** the API SHALL return at most 50 AlertEvents starting from the 101st result

### Requirement: API SHALL return server health status
The REST API SHALL provide a health check endpoint.

#### Scenario: Health check when healthy
- **WHEN** a GET request is made to `/v1/health`
- **THEN** the API SHALL return HTTP 200 with a JSON body containing server version, uptime, number of connected agents, and storage status

#### Scenario: Health check with storage error
- **WHEN** the storage engine is in an error state
- **THEN** the API SHALL return HTTP 503 with a JSON body describing the storage issue

### Requirement: API SHALL use JSON response format
All REST API endpoints SHALL return responses in JSON format with appropriate HTTP status codes.

#### Scenario: Successful response
- **WHEN** an API request succeeds
- **THEN** the response SHALL have Content-Type "application/json" and HTTP status 200

#### Scenario: Error response format
- **WHEN** an API request fails
- **THEN** the response SHALL have Content-Type "application/json" with a body containing "error" (string) and "code" (string) fields, and an appropriate HTTP status code (400/404/500/503)
