## ADDED Requirements

### Requirement: Serve OpenAPI spec in JSON format
The system SHALL expose a `GET /api/v1/openapi.json` endpoint that returns the complete OpenAPI 3.0.3 specification for all oxmon REST API endpoints. The response Content-Type SHALL be `application/json`.

#### Scenario: Fetch JSON spec
- **WHEN** a client sends `GET /api/v1/openapi.json`
- **THEN** the server returns HTTP 200 with a valid OpenAPI 3.0.3 JSON document containing all endpoint definitions

#### Scenario: JSON spec contains correct metadata
- **WHEN** the JSON spec is retrieved
- **THEN** the `info.title` field SHALL be "oxmon API", the `info.version` SHALL match the server version, and `openapi` field SHALL be "3.0.3"

### Requirement: Serve OpenAPI spec in YAML format
The system SHALL expose a `GET /api/v1/openapi.yaml` endpoint that returns the same OpenAPI specification in YAML format. The response Content-Type SHALL be `text/yaml`.

#### Scenario: Fetch YAML spec
- **WHEN** a client sends `GET /api/v1/openapi.yaml`
- **THEN** the server returns HTTP 200 with a valid OpenAPI 3.0.3 YAML document containing all endpoint definitions

#### Scenario: YAML and JSON specs are equivalent
- **WHEN** both `/api/v1/openapi.json` and `/api/v1/openapi.yaml` are fetched
- **THEN** both documents SHALL describe the same set of endpoints, schemas, and parameters

### Requirement: Cover all existing API endpoints
The OpenAPI spec SHALL include definitions for all REST API endpoints currently served by oxmon-server. This includes:

- Health: `GET /api/v1/health`
- Agents: `GET /api/v1/agents`, `GET /api/v1/agents/{id}/latest`
- Metrics: `GET /api/v1/metrics`
- Alerts: `GET /api/v1/alerts/rules`, `GET /api/v1/alerts/history`
- Certificate domains: `POST/GET /api/v1/certs/domains`, `POST /api/v1/certs/domains/batch`, `GET/PUT/DELETE /api/v1/certs/domains/{id}`, `POST /api/v1/certs/domains/{id}/check`
- Certificate check: `POST /api/v1/certs/check`
- Certificate status: `GET /api/v1/certs/status`, `GET /api/v1/certs/status/{domain}`
- OpenAPI: `GET /api/v1/openapi.json`, `GET /api/v1/openapi.yaml`

Each endpoint definition SHALL include method, path, summary, parameters (path/query), request body schema (if applicable), and response schemas with status codes.

#### Scenario: All endpoints present in spec
- **WHEN** the OpenAPI spec is loaded into an API tool (e.g., Apifox)
- **THEN** all 18 endpoints (16 existing + 2 openapi) SHALL be listed with correct HTTP methods and paths

#### Scenario: Request and response schemas defined
- **WHEN** an endpoint has a request body (e.g., `POST /api/v1/certs/domains`)
- **THEN** the spec SHALL define the request body schema with all required and optional fields

#### Scenario: Error responses documented
- **WHEN** an endpoint can return error responses (400, 404, 409, 500)
- **THEN** the spec SHALL include the error response schema with `error` and `code` fields

### Requirement: Spec constructed once and cached
The OpenAPI JSON document SHALL be constructed once (on first request or at startup) and cached in memory. Subsequent requests SHALL return the cached document without reconstruction.

#### Scenario: No repeated construction
- **WHEN** multiple requests are made to `/api/v1/openapi.json`
- **THEN** the underlying JSON value SHALL be constructed only once and reused for all responses

### Requirement: Compatible with Apifox import
The generated OpenAPI spec SHALL be importable into Apifox via its "Import" → "OpenAPI/Swagger" feature, both as `.json` file and via URL.

#### Scenario: Import via URL in Apifox
- **WHEN** a user enters `http://<server>/api/v1/openapi.json` in Apifox's import dialog
- **THEN** Apifox SHALL successfully parse and display all endpoints with their parameters and schemas
