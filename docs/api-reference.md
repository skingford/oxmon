# API Reference

> This file is extracted from README and maintained as the dedicated API guide.

## REST API

### `GET /v1/health`

Health check, returns server status.

```bash
curl http://localhost:8080/v1/health
```

### Auth Endpoints

#### `POST /v1/auth/login`

Login and get a JWT token (public endpoint, no auth required).

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme"}'
```

#### `POST /v1/auth/password`

Change the current logged-in user's password (requires Bearer token).

> Security behavior: once password change succeeds, existing JWTs are revoked immediately. Login again to get a new token.

```bash
curl -X POST http://localhost:8080/v1/auth/password \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"changeme","new_password":"new-strong-password"}'
```

### `GET /v1/agents`

List all registered agents.

Default sort: `last_seen` descending. Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl http://localhost:8080/v1/agents
```

Response example:

```json
[
  {
    "agent_id": "web-server-01",
    "last_seen": "2026-02-06T10:30:00Z",
    "active": true
  }
]
```

### `GET /v1/agents/:id/latest`

Get latest metric values for a specific agent.

```bash
curl http://localhost:8080/v1/agents/web-server-01/latest
```

### `GET /v1/metrics`

Paginated query for metric data points (supports filtering by `agent_id__eq` and `metric_name__eq`).

Default sort: `created_at` descending. Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `agent_id__eq` | Agent ID exact match | No |
| `metric_name__eq` | Metric name exact match | No |
| `timestamp__gte` | Timestamp lower bound (ISO 8601) | No |
| `timestamp__lte` | Timestamp upper bound (ISO 8601) | No |
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
# Defaults to 20 results when pagination params are omitted
curl "http://localhost:8080/v1/metrics"

# Explicit pagination
curl "http://localhost:8080/v1/metrics?limit=50&offset=100"
```

Response example:

```json
[
  {
    "id": "m_01JABCDEF1234567890",
    "timestamp": "2026-02-09T10:00:00Z",
    "agent_id": "web-server-01",
    "metric_name": "cpu.usage",
    "value": 37.5,
    "labels": {
      "core": "0"
    },
    "created_at": "2026-02-09T10:00:01Z"
  }
]
```

### `GET /v1/alerts/rules`

List all configured alert rules.

Default sort: `id` ascending. Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl http://localhost:8080/v1/alerts/rules
```

### `GET /v1/alerts/history`

Query alert history.

Default sort: `timestamp` descending. Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `agent_id__eq` | Agent ID exact match | No |
| `severity__eq` | Severity exact match (info/warning/critical) | No |
| `timestamp__gte` | Timestamp lower bound | No |
| `timestamp__lte` | Timestamp upper bound | No |
| `limit` | Result count limit (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl "http://localhost:8080/v1/alerts/history?severity__eq=critical&limit=50"
```

### Agent Whitelist Management

The agent whitelist controls which agents can report data via gRPC. Agents must be **manually** added via the API — there is no auto-registration. `agent_id` has a uniqueness constraint; duplicate additions return 409.

#### `POST /v1/agents/whitelist`

Add an agent to the whitelist. Returns an authentication token (shown only once at creation — save it).

```bash
curl -X POST http://localhost:8080/v1/agents/whitelist \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "web-server-01", "description": "Production web server"}'
```

Response example:

```json
{
  "agent_id": "web-server-01",
  "token": "AbCdEf1234567890...",
  "created_at": "2026-02-08T10:00:00Z"
}
```

#### `GET /v1/agents/whitelist`

List all whitelisted agents with online status (tokens are not included).

Default sort: `created_at` descending. Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl http://localhost:8080/v1/agents/whitelist
```

Response example:

```json
[
  {
    "agent_id": "web-server-01",
    "created_at": "2026-02-08T10:00:00Z",
    "description": "Production web server",
    "last_seen": "2026-02-08T12:30:00Z",
    "status": "active"
  }
]
```

`status` values: `active` (online), `inactive` (offline), `unknown` (never reported).

#### `PUT /v1/agents/whitelist/{agent_id}`

Update agent whitelist information (e.g., description).

```bash
curl -X PUT http://localhost:8080/v1/agents/whitelist/web-server-01 \
  -H "Content-Type: application/json" \
  -d '{"description": "Production web server - migrated"}'
```

#### `POST /v1/agents/whitelist/{agent_id}/token`

Regenerate the authentication token for an agent. The old token is immediately invalidated. Update the `auth_token` in the agent config and restart the agent.

```bash
curl -X POST http://localhost:8080/v1/agents/whitelist/web-server-01/token
```

Response example:

```json
{
  "agent_id": "web-server-01",
  "token": "NewToken1234567890..."
}
```

#### `DELETE /v1/agents/whitelist/{agent_id}`

Remove an agent from the whitelist.

```bash
curl -X DELETE http://localhost:8080/v1/agents/whitelist/web-server-01
```

### Certificate Details

The server periodically collects detailed certificate information (issuer, SANs, chain validation, resolved IPs, etc.), queryable via the following endpoints.

#### `GET /v1/certificates`

List all certificate details with filtering and pagination.

Default sort: `not_after` ascending. Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `not_after__lte` | Certificate expiry upper bound (Unix timestamp) | No |
| `ip_address__contains` | IP contains match | No |
| `issuer__contains` | Issuer contains match | No |
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
# List all certificates
curl http://localhost:8080/v1/certificates

# Filter by expiry upper bound (example timestamp)
curl "http://localhost:8080/v1/certificates?not_after__lte=1767225600"

# Filter by issuer
curl "http://localhost:8080/v1/certificates?issuer__contains=Let%27s%20Encrypt"
```

#### `GET /v1/certificates/{domain}`

Get certificate details for a specific domain.

```bash
curl http://localhost:8080/v1/certificates/example.com
```

Response example:

```json
{
  "domain": "example.com",
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2026-01-01T00:00:00Z",
  "ip_addresses": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
  "issuer_cn": "R3",
  "issuer_o": "Let's Encrypt",
  "subject_alt_names": ["example.com", "www.example.com"],
  "chain_valid": true,
  "last_checked": "2026-02-08T10:00:00Z"
}
```

#### `GET /v1/certificates/{domain}/chain`

Get certificate chain validation details for a specific domain.

```bash
curl http://localhost:8080/v1/certificates/example.com/chain
```

### Certificate Domain Management

#### `POST /v1/certs/domains`

Add a domain for monitoring.

```bash
curl -X POST http://localhost:8080/v1/certs/domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "port": 443, "note": "Main site"}'
```

#### `POST /v1/certs/domains/batch`

Batch add domains.

```bash
curl -X POST http://localhost:8080/v1/certs/domains/batch \
  -H "Content-Type: application/json" \
  -d '{"domains": [{"domain": "a.com"}, {"domain": "b.com", "port": 8443}]}'
```

#### `GET /v1/certs/domains`

List domains (supports `?enabled__eq=true&domain__contains=example&limit=20&offset=0`).

Default sort: `created_at` descending. Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `enabled__eq` | Enabled status exact match | No |
| `domain__contains` | Domain contains match | No |
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl http://localhost:8080/v1/certs/domains
```

#### `PUT /v1/certs/domains/:id`

Update domain configuration (port, enabled status, check interval).

```bash
curl -X PUT http://localhost:8080/v1/certs/domains/<id> \
  -H "Content-Type: application/json" \
  -d '{"check_interval_secs": 3600, "enabled": true}'
```

#### `DELETE /v1/certs/domains/:id`

Delete a domain and its check results.

```bash
curl -X DELETE http://localhost:8080/v1/certs/domains/<id>
```

#### `GET /v1/certs/status`

Get the latest certificate check results for all domains.

Default sort: `checked_at` descending. Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl http://localhost:8080/v1/certs/status
```

#### `GET /v1/certs/status/:domain`

Get the latest certificate check result for a specific domain.

```bash
curl http://localhost:8080/v1/certs/status/example.com
```

#### `POST /v1/certs/domains/:id/check`

Manually trigger a certificate check for a specific domain.

```bash
curl -X POST http://localhost:8080/v1/certs/domains/<id>/check
```

#### `POST /v1/certs/check`

Manually trigger certificate checks for all enabled domains.

```bash
curl -X POST http://localhost:8080/v1/certs/check
```

### API Documentation (OpenAPI)

The server provides OpenAPI 3.0.3 API documentation, which can be imported directly into Apifox, Postman, Swagger UI, and similar tools.

| Endpoint | Format |
|----------|--------|
| `GET /v1/openapi.json` | JSON format |
| `GET /v1/openapi.yaml` | YAML format |

```bash
# Get JSON format API documentation
curl http://localhost:8080/v1/openapi.json

# Get YAML format API documentation
curl http://localhost:8080/v1/openapi.yaml
```

**Apifox Import:**
1. Open Apifox -> Project Settings -> Import Data
2. Select "OpenAPI/Swagger" -> "URL Import"
3. Enter `http://<server-ip>:8080/v1/openapi.json`
4. Click Import to get all API definitions

### Query Parameter Naming Convention

To keep filtering semantics consistent across endpoints, query parameters use the `field__operator` pattern:

- `__eq`: exact match (example: `agent_id__eq=web-server-01`)
- `__contains`: contains match (example: `issuer__contains=Let%27s%20Encrypt`)
- `__gte`: lower bound, greater than or equal (example: `timestamp__gte=2026-02-09T00:00:00Z`)
- `__lte`: upper bound, less than or equal (example: `timestamp__lte=2026-02-09T23:59:59Z`)

Pagination parameters are unified across list endpoints:

- `limit`: page size (default: `20`)
- `offset`: offset (default: `0`)


## Unified Response Format

All REST APIs return a unified JSON envelope:

```json
{
  "err_code": 0,
  "err_msg": "success",
  "trace_id": "",
  "data": {}
}
```

- `err_code`: integer code (`0` = success, non-zero = custom failure code)
- `err_msg`: error/success message
- `trace_id`: trace identifier (currently empty string by default)
- `data`: business payload (`null` when no payload)

Failure responses use custom business error codes (not HTTP status code values).

## Error Code Table

| err_code | Symbolic Name | Description |
|----------|---------------|-------------|
| 0 | OK | Success |
| 1001 | BAD_REQUEST | Invalid request parameters |
| 1002 | UNAUTHORIZED | Authentication failed / unauthorized |
| 1003 | TOKEN_EXPIRED | JWT token expired |
| 1004 | NOT_FOUND | Resource not found |
| 1005 | CONFLICT | Resource conflict |
| 1101 | duplicate_domain | Domain already exists |
| 1102 | invalid_domain | Invalid domain value |
| 1103 | invalid_port | Invalid port value |
| 1104 | empty_batch | Batch request payload is empty |
| 1105 | no_results | No check result available |
| 1500 | INTERNAL_ERROR | Internal server error |
| 1501 | storage_error | Storage layer error |
| 1999 | unknown | Unknown custom error |
