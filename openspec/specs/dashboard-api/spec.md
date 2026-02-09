## ADDED Requirements

### Requirement: API SHALL list registered agents
The REST API SHALL provide an endpoint to list all known agents and their status. This endpoint SHALL require a valid JWT Bearer token in the Authorization header.

#### Scenario: List all agents
- **WHEN** a GET request is made to `/v1/agents` with a valid JWT token
- **THEN** the API SHALL return a JSON array of agents with id, last_seen timestamp, and status (active/inactive)

#### Scenario: Agent marked inactive
- **WHEN** an agent has not reported metrics for more than 3x the expected collection interval
- **THEN** the API SHALL return that agent's status as "inactive"

#### Scenario: List agents without token
- **WHEN** a GET request is made to `/v1/agents` without an Authorization header
- **THEN** the API SHALL return HTTP 401

### Requirement: API SHALL query metric data
The REST API SHALL provide an endpoint to query metric time-series data. This endpoint SHALL require a valid JWT Bearer token in the Authorization header.

#### Scenario: Query metrics with time range
- **WHEN** a GET request is made to `/v1/metrics?agent=web-01&metric=cpu.usage&from=2024-01-01T00:00:00Z&to=2024-01-01T01:00:00Z` with a valid JWT token
- **THEN** the API SHALL return a JSON array of data points with timestamp and value, ordered by timestamp ascending

#### Scenario: Query with step aggregation
- **WHEN** a GET request includes `&step=5m` with a valid JWT token
- **THEN** the API SHALL return data points aggregated at 5-minute intervals using average as the default aggregation function

#### Scenario: Query missing required parameters
- **WHEN** a GET request to `/v1/metrics` with a valid JWT token is missing the "agent" or "metric" parameter
- **THEN** the API SHALL return HTTP 400 with a JSON error describing the missing parameters

#### Scenario: Query metrics without token
- **WHEN** a GET request is made to `/v1/metrics` without an Authorization header
- **THEN** the API SHALL return HTTP 401

### Requirement: API SHALL query latest metric values
The REST API SHALL provide an endpoint to get the most recent value for each metric of an agent. This endpoint SHALL require a valid JWT Bearer token in the Authorization header.

#### Scenario: Get latest metrics for agent
- **WHEN** a GET request is made to `/v1/agents/web-01/latest` with a valid JWT token
- **THEN** the API SHALL return a JSON object with the most recent value and timestamp for each metric reported by agent "web-01"

#### Scenario: Agent not found
- **WHEN** a GET request is made to `/v1/agents/unknown-agent/latest` with a valid JWT token
- **THEN** the API SHALL return HTTP 404 with a JSON error message

#### Scenario: Get latest metrics without token
- **WHEN** a GET request is made to `/v1/agents/web-01/latest` without an Authorization header
- **THEN** the API SHALL return HTTP 401

### Requirement: API SHALL list alert rules
The REST API SHALL provide an endpoint to list all configured alert rules. This endpoint SHALL require a valid JWT Bearer token in the Authorization header.

#### Scenario: List all rules
- **WHEN** a GET request is made to `/v1/alerts/rules` with a valid JWT token
- **THEN** the API SHALL return a JSON array of all alert rules with their id, type, metric, agent_pattern, parameters, severity, and enabled status

#### Scenario: List alert rules without token
- **WHEN** a GET request is made to `/v1/alerts/rules` without an Authorization header
- **THEN** the API SHALL return HTTP 401

### Requirement: API SHALL query alert history
The REST API SHALL provide an endpoint to query historical alert events. This endpoint SHALL require a valid JWT Bearer token in the Authorization header.

#### Scenario: Query alert history with time range
- **WHEN** a GET request is made to `/v1/alerts/history?from=2024-01-01T00:00:00Z&to=2024-01-02T00:00:00Z` with a valid JWT token
- **THEN** the API SHALL return a JSON array of AlertEvents within the time range, ordered by timestamp descending

#### Scenario: Filter alert history by severity
- **WHEN** a GET request includes `&severity=critical` with a valid JWT token
- **THEN** the API SHALL return only AlertEvents with severity "critical"

#### Scenario: Filter alert history by agent
- **WHEN** a GET request includes `&agent=web-01` with a valid JWT token
- **THEN** the API SHALL return only AlertEvents related to agent "web-01"

#### Scenario: Paginated alert history
- **WHEN** a GET request includes `&limit=50&offset=100` with a valid JWT token
- **THEN** the API SHALL return at most 50 AlertEvents starting from the 101st result

#### Scenario: Query alert history without token
- **WHEN** a GET request is made to `/v1/alerts/history` without an Authorization header
- **THEN** the API SHALL return HTTP 401

### Requirement: API SHALL return server health status
The REST API SHALL provide a health check endpoint. This endpoint SHALL remain publicly accessible without authentication.

#### Scenario: Health check when healthy
- **WHEN** a GET request is made to `/v1/health` without any Authorization header
- **THEN** the API SHALL return HTTP 200 with a JSON body containing server version, uptime, number of connected agents, and storage status

#### Scenario: Health check with storage error
- **WHEN** the storage engine is in an error state
- **THEN** the API SHALL return HTTP 503 with a JSON body describing the storage issue

### Requirement: API SHALL use JSON response format
All REST API endpoints SHALL return responses in JSON format with appropriate HTTP status codes, including authentication error responses.

#### Scenario: Successful response
- **WHEN** an API request succeeds
- **THEN** the response SHALL have Content-Type "application/json" and HTTP status 200

#### Scenario: Error response format
- **WHEN** an API request fails
- **THEN** the response SHALL have Content-Type "application/json" with a body containing "error" (string) and "code" (string) fields, and an appropriate HTTP status code (400/401/404/500/503)

#### Scenario: Authentication error response format
- **WHEN** a request to a protected endpoint fails authentication
- **THEN** the response SHALL have Content-Type "application/json" with HTTP status 401 and a body containing "error" and "code" fields
