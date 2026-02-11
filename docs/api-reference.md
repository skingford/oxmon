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

### Metrics Discovery

#### `GET /v1/metrics/names`

Get all distinct metric names in a time range.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `timestamp__gte` | Time lower bound (default: 24h ago) | No |
| `timestamp__lte` | Time upper bound (default: now) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/metrics/names
```

Response example:

```json
["cpu.usage", "cpu.core_usage", "memory.used_percent", "disk.used_percent"]
```

#### `GET /v1/metrics/agents`

Get all distinct agent IDs reporting in a time range.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `timestamp__gte` | Time lower bound (default: 24h ago) | No |
| `timestamp__lte` | Time upper bound (default: now) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/metrics/agents
```

#### `GET /v1/metrics/summary`

Get aggregated metric statistics (min/max/avg/count).

| Parameter | Description | Required |
|-----------|-------------|----------|
| `agent_id` | Agent ID | Yes |
| `metric_name` | Metric name | Yes |
| `timestamp__gte` | Time lower bound (default: 1h ago) | No |
| `timestamp__lte` | Time upper bound (default: now) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/v1/metrics/summary?agent_id=web-01&metric_name=cpu.usage"
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

### Alert Rules Management

#### `GET /v1/alerts/rules`

List all active alert rules in the engine.

Default pagination: `limit=20&offset=0`.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/rules
```

#### `GET /v1/alerts/rules/config`

List persisted alert rule configurations from the database.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/rules/config
```

#### `GET /v1/alerts/rules/{id}`

Get details of a single alert rule.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/rules/<id>
```

#### `POST /v1/alerts/rules`

Create a new alert rule.

```bash
curl -X POST http://localhost:8080/v1/alerts/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "high-cpu",
    "rule_type": "threshold",
    "metric": "cpu.usage",
    "agent_pattern": "*",
    "severity": "critical",
    "config_json": "{\"operator\":\"greater_than\",\"value\":90.0,\"duration_secs\":300}",
    "silence_secs": 600
  }'
```

#### `PUT /v1/alerts/rules/{id}`

Update an existing alert rule (partial update).

```bash
curl -X PUT http://localhost:8080/v1/alerts/rules/<id> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"severity": "warning", "silence_secs": 1200}'
```

#### `DELETE /v1/alerts/rules/{id}`

Delete an alert rule.

```bash
curl -X DELETE http://localhost:8080/v1/alerts/rules/<id> \
  -H "Authorization: Bearer $TOKEN"
```

#### `PUT /v1/alerts/rules/{id}/enable`

Enable or disable an alert rule.

```bash
curl -X PUT http://localhost:8080/v1/alerts/rules/<id>/enable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### Alert History & Lifecycle

#### `GET /v1/alerts/history`

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
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/v1/alerts/history?severity__eq=critical&limit=50"
```

#### `POST /v1/alerts/history/{id}/acknowledge`

Mark an alert as acknowledged.

```bash
curl -X POST http://localhost:8080/v1/alerts/history/<id>/acknowledge \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /v1/alerts/history/{id}/resolve`

Mark an alert as resolved.

```bash
curl -X POST http://localhost:8080/v1/alerts/history/<id>/resolve \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /v1/alerts/active`

Get all active (unresolved) alerts.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/active
```

#### `GET /v1/alerts/summary`

Get alert statistics summary for the last 24 hours.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/summary
```

Response example:

```json
{
  "total": 42,
  "by_severity": {
    "critical": 3,
    "warning": 15,
    "info": 24
  }
}
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

#### `GET /v1/certs/domains/{id}/history`

Get certificate check history for a domain.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/certs/domains/<id>/history
```

#### `GET /v1/certs/summary`

Get certificate health summary (total domains, valid/invalid/expiring counts).

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/certs/summary
```

### Notification Channel Management

Notification channels are stored in the database and managed dynamically via REST API. Each channel type (email, webhook, sms, dingtalk, weixin) supports multiple instances. Recipients are managed separately per channel.

#### `GET /v1/notifications/channels`

List all notification channels with their recipients and recipient type.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/notifications/channels
```

Response example:

```json
[
  {
    "id": "ch_01JABCDEF",
    "name": "ops-email",
    "channel_type": "email",
    "description": "Ops team email channel",
    "min_severity": "warning",
    "enabled": true,
    "recipient_type": "email",
    "recipients": ["ops@example.com", "admin@example.com"],
    "created_at": "2026-02-10T10:00:00Z",
    "updated_at": "2026-02-10T10:00:00Z"
  }
]
```

#### `GET /v1/notifications/channels/config`

List persisted notification channel configurations (raw DB rows).

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/notifications/channels/config
```

#### `POST /v1/notifications/channels/config`

Create a new notification channel. The `config_json` field contains channel-type-specific configuration (SMTP settings for email, gateway URL for SMS, etc.). Recipients can be provided during creation.

```bash
curl -X POST http://localhost:8080/v1/notifications/channels/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ops-email",
    "channel_type": "email",
    "description": "Ops team email alerts",
    "min_severity": "warning",
    "config_json": "{\"smtp_host\":\"smtp.example.com\",\"smtp_port\":587,\"from\":\"alerts@example.com\"}",
    "recipients": ["ops@example.com"]
  }'
```

Channel types and their `config_json` fields:

| Type | Required Config | Optional Config |
|------|----------------|-----------------|
| `email` | `smtp_host`, `smtp_port`, `from` | `smtp_username`, `smtp_password` |
| `webhook` | (none) | `body_template` |
| `sms` | `gateway_url`, `api_key` | — |
| `dingtalk` | `webhook_url` | `secret` |
| `weixin` | `webhook_url` | — |

Recipient types per channel:

| Channel | Recipient Type | Example |
|---------|---------------|---------|
| `email` | email address | `admin@example.com` |
| `sms` | phone number | `+8613800138000` |
| `webhook` | URL | `https://hooks.slack.com/services/xxx` |
| `dingtalk` | webhook URL | `https://oapi.dingtalk.com/robot/send?access_token=...` |
| `weixin` | webhook URL | `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...` |

#### `PUT /v1/notifications/channels/config/{id}`

Update a notification channel configuration (partial update). Changes take effect immediately via hot-reload.

```bash
curl -X PUT http://localhost:8080/v1/notifications/channels/config/<id> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"min_severity": "critical", "enabled": false}'
```

#### `DELETE /v1/notifications/channels/config/{id}`

Delete a notification channel and its recipients.

```bash
curl -X DELETE http://localhost:8080/v1/notifications/channels/config/<id> \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /v1/notifications/channels/{id}/test`

Send a test notification through a channel to verify configuration. Uses the channel's current recipients.

```bash
curl -X POST http://localhost:8080/v1/notifications/channels/<id>/test \
  -H "Authorization: Bearer $TOKEN"
```

#### `PUT /v1/notifications/channels/{id}/recipients`

Set (replace) the recipient list for a channel.

```bash
curl -X PUT http://localhost:8080/v1/notifications/channels/<id>/recipients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"recipients": ["admin@example.com", "ops@example.com"]}'
```

#### `GET /v1/notifications/channels/{id}/recipients`

Get the current recipient list for a channel.

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/notifications/channels/<id>/recipients
```

### Silence Windows

Silence windows suppress notifications during maintenance periods. Managed via REST API and stored in the database.

#### `GET /v1/notifications/silence-windows`

List all silence windows.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `limit` | Page size (default: 20) | No |
| `offset` | Offset (default: 0) | No |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/notifications/silence-windows
```

#### `POST /v1/notifications/silence-windows`

Create a silence window.

```bash
curl -X POST http://localhost:8080/v1/notifications/silence-windows \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"start_time": "02:00", "end_time": "04:00", "recurrence": "daily"}'
```

#### `DELETE /v1/notifications/silence-windows/{id}`

Delete a silence window.

```bash
curl -X DELETE http://localhost:8080/v1/notifications/silence-windows/<id> \
  -H "Authorization: Bearer $TOKEN"
```

### Dashboard

#### `GET /v1/dashboard/overview`

Get a comprehensive dashboard overview including agent status, alert summary, certificate health, and storage info.

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/dashboard/overview
```

Response example:

```json
{
  "active_agents": 5,
  "total_agents": 8,
  "alerts_24h": 42,
  "alerts_by_severity": {"critical": 3, "warning": 15, "info": 24},
  "cert_summary": {"total_domains": 10, "valid": 8, "invalid": 1, "expiring_soon": 1},
  "partition_count": 7,
  "storage_total_bytes": 52428800,
  "uptime_secs": 86400
}
```

### System Management

#### `GET /v1/system/config`

Get runtime server configuration (sensitive fields are masked).

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/system/config
```

#### `GET /v1/system/storage`

Get storage partition information (file list, sizes).

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/system/storage
```

Response example:

```json
{
  "partitions": [
    {"date": "2026-02-10", "size_bytes": 8388608},
    {"date": "2026-02-09", "size_bytes": 7340032}
  ],
  "total_partitions": 2,
  "total_size_bytes": 15728640
}
```

#### `POST /v1/system/storage/cleanup`

Manually trigger storage cleanup based on the retention policy.

```bash
curl -X POST http://localhost:8080/v1/system/storage/cleanup \
  -H "Authorization: Bearer $TOKEN"
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

## Test Coverage Strategy

- Endpoint matrix tests: each API is covered for success + auth failure + validation/business error branches.
- Real agent simulation: gRPC `ReportMetrics` is tested with real metadata and payload paths.
- OpenAPI contract guard: if a new endpoint appears in OpenAPI but not in test matrix, CI fails.

See also: [`docs/api-improvement-plan.md`](api-improvement-plan.md)
