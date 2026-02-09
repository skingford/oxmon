English | [中文](README.zh-CN.md)

# oxmon

Lightweight server monitoring system built with Rust. Collects system metrics (CPU, memory, disk, network, load), stores time-series data, evaluates alert rules, and sends notifications through multiple channels.

## Architecture

```
┌──────────────────┐      gRPC      ┌──────────────────────────────────────┐
│   oxmon-agent    │───────────────→│           oxmon-server                │
│                  │                │                                      │
│ ┌──────────────┐ │                │ ┌────────┐  ┌─────────┐  ┌────────┐ │
│ │  Collectors  │ │                │ │ gRPC   │→ │ Storage │  │  REST  │ │
│ │ CPU/Mem/Disk │ │                │ │ Ingest │  │ SQLite  │  │  API   │ │
│ │ Net/Load     │ │                │ └────┬───┘  └────┬────┘  └────────┘ │
│ └──────────────┘ │                │      │           │                   │
│ ┌──────────────┐ │                │      ▼           │                   │
│ │ Local Buffer │ │                │ ┌────────┐       │  ┌────────────┐  │
│ │ (VecDeque)   │ │                │ │ Alert  │───────┘  │ Notify     │  │
│ └──────────────┘ │                │ │ Engine │─────────→│ Notify     │  │
└──────────────────┘                │ └────────┘          │ Plugin     │  │
                                    │                     │ Registry   │  │
                                    └─────────────────────┴────────────┴──┘
```

**Agent** is deployed on monitored servers. It collects metrics every N seconds and reports them via gRPC. When the connection fails, data is buffered locally.

**Server** receives metrics, stores them in time-partitioned SQLite, evaluates alert rules (threshold / rate of change / trend prediction), and sends notifications.

## Crate Structure

| Crate | Description |
|-------|-------------|
| `oxmon-common` | Shared types, protobuf definitions |
| `oxmon-collector` | System metric collectors (CPU, memory, disk, network, load) |
| `oxmon-agent` | Agent binary - collection loop + gRPC client |
| `oxmon-storage` | Time-partitioned SQLite storage engine |
| `oxmon-alert` | Alert rule engine (threshold, rate of change, trend prediction) |
| `oxmon-notify` | Notification channel plugin system (email, webhook, SMS, DingTalk, WeChat Work) |
| `oxmon-server` | Server binary - gRPC + REST API + alerting + notifications |

## Quick Start

### 1. Build

```bash
cargo build --release
```

This produces two binaries: `target/release/oxmon-agent` and `target/release/oxmon-server`.

### 2. Configure

```bash
cp config/server.example.toml config/server.toml
cp config/agent.example.toml config/agent.toml
```

Edit the configuration files for your environment. See [Configuration](#configuration) below.

### 3. Start the Server

```bash
# Start manually
oxmon-server /etc/oxmon/server.toml

# Or start with PM2 for process management (Beijing timezone)
TZ=Asia/Shanghai pm2 start oxmon-server --name oxmon-server \
  --log-date-format="YYYY-MM-DD HH:mm:ss Z" \
  -- /etc/oxmon/server.toml
pm2 save && pm2 startup
```

The server listens on gRPC port 9090 and REST API port 8080 (configurable).

### 4. Start the Agent

```bash
# Start manually
oxmon-agent /etc/oxmon/agent.toml

# Or start with PM2 for process management (Beijing timezone)
TZ=Asia/Shanghai pm2 start oxmon-agent --name oxmon-agent \
  --log-date-format="YYYY-MM-DD HH:mm:ss Z" \
  -- /etc/oxmon/agent.toml
pm2 save && pm2 startup
```

The agent collects system metrics every 10 seconds (configurable) and reports them to the server via gRPC.

## Configuration

### Agent Configuration (`agent.toml`)

| Field | Description | Default |
|-------|-------------|---------|
| `agent_id` | Unique identifier for this node | `"web-server-01"` |
| `server_endpoint` | Server gRPC address | `"http://127.0.0.1:9090"` |
| `auth_token` | Authentication token (optional, required when server auth is enabled) | none |
| `collection_interval_secs` | Metric collection interval (seconds) | `10` |
| `buffer_max_size` | Max buffered batches when server is unreachable | `1000` |

Example:

```toml
agent_id = "web-server-01"
server_endpoint = "http://10.0.1.100:9090"
# auth_token = "your-token-here"  # Required when server has require_agent_auth enabled
collection_interval_secs = 10
buffer_max_size = 1000
```

### Server Configuration (`server.toml`)

#### Basic Settings

| Field | Description | Default |
|-------|-------------|---------|
| `grpc_port` | gRPC port for receiving agent reports | `9090` |
| `http_port` | REST API port | `8080` |
| `data_dir` | SQLite data file storage directory | `"data"` |
| `retention_days` | Data retention in days, auto-cleanup when expired | `7` |
| `require_agent_auth` | Require agent authentication | `false` |

#### Alert Rules (`[[alert.rules]]`)

Four rule types are supported:

**Threshold Alert** — triggers when a metric exceeds a threshold for a sustained duration:

```toml
[[alert.rules]]
name = "high-cpu"
type = "threshold"
metric = "cpu.usage"          # Metric name to monitor
agent_pattern = "*"           # Agent match pattern, supports glob (e.g., "web-*")
operator = "greater_than"     # Comparison operator: greater_than / less_than
value = 90.0                  # Threshold value
duration_secs = 300           # Duration (seconds) the metric must exceed threshold to trigger
severity = "critical"         # Severity level: info / warning / critical
silence_secs = 600            # Silence period (seconds), same alert won't re-trigger within this window
```

**Rate of Change Alert** — triggers when a metric changes beyond a percentage within a time window:

```toml
[[alert.rules]]
name = "memory-spike"
type = "rate_of_change"
metric = "memory.used_percent"
agent_pattern = "*"
rate_threshold = 20.0         # Rate threshold (percentage)
window_secs = 300             # Calculation window (seconds)
severity = "warning"
silence_secs = 600
```

**Trend Prediction Alert** — uses linear regression to predict when a metric will breach a threshold:

```toml
[[alert.rules]]
name = "disk-full-prediction"
type = "trend_prediction"
metric = "disk.used_percent"
agent_pattern = "*"
predict_threshold = 95.0      # Target threshold for prediction
horizon_secs = 86400          # Prediction horizon (seconds), e.g., 86400 = 24 hours
min_data_points = 10          # Minimum data points required for prediction
severity = "info"
silence_secs = 3600
```

**Certificate Expiration Alert** — triggers tiered alerts based on days until certificate expiry:

```toml
[[alert.rules]]
name = "cert-expiry"
type = "cert_expiration"
metric = "certificate.days_until_expiry"
agent_pattern = "cert-checker"
severity = "critical"             # Default severity level
warning_days = 30                 # Trigger warning at 30 days before expiry
critical_days = 7                 # Trigger critical at 7 days before expiry
silence_secs = 86400
```

#### Notification Channels (`[[notification.channels]]`)

**Email:**

```toml
[[notification.channels]]
type = "email"
min_severity = "warning"          # Minimum severity to trigger
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "alerts@example.com"
smtp_password = "your-password"
from = "alerts@example.com"
recipients = ["admin@example.com", "ops@example.com"]
```

**Webhook (for Slack / DingTalk / Feishu, etc.):**

```toml
[[notification.channels]]
type = "webhook"
min_severity = "info"
url = "https://hooks.slack.com/services/xxx/yyy/zzz"
# Optional: custom body template with {{agent_id}} {{metric}} {{value}} {{severity}} {{message}} variables
# body_template = '{"text": "[{{severity}}] {{agent_id}}: {{message}}"}'
```

**SMS:**

```toml
[[notification.channels]]
type = "sms"
min_severity = "critical"
gateway_url = "https://sms-api.example.com/send"
api_key = "your-api-key"
phone_numbers = ["+8613800138000"]
```

**DingTalk Robot:**

```toml
[[notification.channels]]
type = "dingtalk"
min_severity = "warning"
webhook_url = "https://oapi.dingtalk.com/robot/send?access_token=YOUR_TOKEN"
secret = "SEC_YOUR_SECRET"   # Optional: HMAC-SHA256 signing secret
```

DingTalk notifications send Markdown-formatted messages containing alert severity, agent, metric, value, threshold, and timestamp. When `secret` is configured, requests are signed with HMAC-SHA256.

**WeChat Work Robot:**

```toml
[[notification.channels]]
type = "weixin"
min_severity = "warning"
webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY"
```

WeChat Work notifications send Markdown-formatted messages.

> **Plugin System**: Notification channels are implemented as a plugin architecture. Each channel is an independent `ChannelPlugin`. The server uses `ChannelRegistry` to dynamically look up and instantiate channels — the `type` field in the config maps to the plugin name, and remaining fields are passed directly to the plugin for parsing. Built-in plugins: `email`, `webhook`, `sms`, `dingtalk`, `weixin`.

#### Silence Windows (`[[notification.silence_windows]]`)

Suppress notifications during maintenance windows:

```toml
[[notification.silence_windows]]
start_time = "02:00"
end_time = "04:00"
recurrence = "daily"
```

#### Alert Aggregation

```toml
aggregation_window_secs = 60   # Aggregation window (seconds) for batching similar alerts into one notification
```

## Collected Metrics

| Metric | Description |
|--------|-------------|
| `cpu.usage` | Overall CPU usage (%) |
| `cpu.core_usage` | Per-core CPU usage (%) |
| `memory.total` | Total memory (bytes) |
| `memory.used` | Used memory (bytes) |
| `memory.available` | Available memory (bytes) |
| `memory.used_percent` | Memory usage (%) |
| `memory.swap_total` | Swap total (bytes) |
| `memory.swap_used` | Swap used (bytes) |
| `disk.total` | Disk total capacity (bytes), per mount point |
| `disk.used` | Disk used (bytes), per mount point |
| `disk.available` | Disk available (bytes), per mount point |
| `disk.used_percent` | Disk usage (%), per mount point |
| `network.bytes_sent` | Network bytes sent/sec, per interface |
| `network.bytes_recv` | Network bytes received/sec, per interface |
| `network.packets_sent` | Network packets sent/sec, per interface |
| `network.packets_recv` | Network packets received/sec, per interface |
| `load.load_1` | 1-minute load average |
| `load.load_5` | 5-minute load average |
| `load.load_15` | 15-minute load average |
| `load.uptime` | System uptime (seconds) |
| `certificate.days_until_expiry` | Days until certificate expiry, per domain (collected by server) |
| `certificate.is_valid` | Whether certificate is valid (1=valid, 0=invalid/expired/error), per domain |

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

Query time-series data.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `agent` | Agent ID | Yes |
| `metric` | Metric name | Yes |
| `from` | Start time (ISO 8601) | Yes |
| `to` | End time (ISO 8601) | Yes |

```bash
curl "http://localhost:8080/v1/metrics?agent=web-server-01&metric=cpu.usage&from=2026-02-06T00:00:00Z&to=2026-02-06T23:59:59Z"
```

### `GET /v1/alerts/rules`

List all configured alert rules.

```bash
curl http://localhost:8080/v1/alerts/rules
```

### `GET /v1/alerts/history`

Query alert history.

| Parameter | Description | Required |
|-----------|-------------|----------|
| `severity` | Filter by severity (info/warning/critical) | No |
| `agent` | Filter by agent ID | No |
| `from` | Start time | No |
| `to` | End time | No |
| `limit` | Result count limit | No |
| `offset` | Pagination offset | No |

```bash
curl "http://localhost:8080/v1/alerts/history?severity=critical&limit=50"
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

| Parameter | Description | Required |
|-----------|-------------|----------|
| `expiring_within_days` | Filter certificates expiring within N days | No |
| `ip_address` | Filter by IP address | No |
| `issuer` | Filter by issuer | No |
| `limit` | Page size (default 100) | No |
| `offset` | Pagination offset | No |

```bash
# List all certificates
curl http://localhost:8080/v1/certificates

# Filter certificates expiring within 30 days
curl "http://localhost:8080/v1/certificates?expiring_within_days=30"

# Filter by issuer
curl "http://localhost:8080/v1/certificates?issuer=Let%27s%20Encrypt"
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

List domains (supports `?enabled=true&search=example&limit=20&offset=0`).

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

### Common SQLite Commands

oxmon stores data in SQLite:

- `data/cert.db`: users, whitelist, certificate domains, certificate details
- `data/YYYY-MM-DD.db`: daily partitioned metric & alert data (`metrics`, `alert_events`)

```bash
# List database files in the data directory
ls -lh data/*.db

# Open main database
sqlite3 data/cert.db

# Open one daily partition database
sqlite3 data/2026-02-09.db
```

Useful commands inside `sqlite3`:

```sql
.headers on
.mode column
.tables
.schema
.schema users
PRAGMA table_info(users);
.quit
```

Basic queries (SELECT):

```sql
SELECT id, username, created_at FROM users LIMIT 20;

SELECT id, domain, port, enabled
FROM cert_domains
ORDER BY updated_at DESC
LIMIT 20;

SELECT id, rule_id, agent_id, severity, metric_name, timestamp
FROM alert_events
ORDER BY timestamp DESC
LIMIT 20;
```

Basic CRUD examples:

```sql
-- Create (INSERT)
INSERT INTO cert_domains (id, domain, port, enabled, created_at, updated_at)
VALUES ('manual-001', 'example.com', 443, 1, strftime('%s','now'), strftime('%s','now'));

-- Read (SELECT)
SELECT id, domain, enabled FROM cert_domains WHERE id = 'manual-001';

-- Update (UPDATE)
UPDATE cert_domains
SET enabled = 0, updated_at = strftime('%s','now')
WHERE id = 'manual-001';

-- Delete (DELETE)
DELETE FROM cert_domains WHERE id = 'manual-001';
```

> Prefer using REST APIs for production data writes. Manual changes to auth-related tables such as `users` and `agent_whitelist` can break login/authentication.

### Certificate Check Configuration

Configure certificate checking in `server.toml`:

```toml
[cert_check]
enabled = true
default_interval_secs = 86400   # Default check interval (24 hours)
tick_secs = 60                  # Scheduler tick interval
connect_timeout_secs = 10       # TLS connection timeout
max_concurrent = 10              # Max concurrent checks
```

Domains are managed dynamically via the REST API. Each domain can have its own `check_interval_secs` to override the global default.

## Linux Quick Deploy

One-liner install using `curl | bash`, similar to [nvm](https://github.com/nvm-sh/nvm). Downloads pre-built binaries from GitHub Releases, generates config files, and optionally sets up PM2 for process management.

> Server and agent are deployed separately — use `server` on the central machine, `agent` on each monitored host.

### Install Server (central machine)

```bash
# Basic install
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- server

# Install with PM2 process daemon
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- server --setup-pm2
```

### Install Agent (monitored hosts)

```bash
# Point to the server's gRPC address
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- agent \
  --server-endpoint http://10.0.1.100:9090

# Custom agent ID + PM2
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- agent \
  --server-endpoint http://10.0.1.100:9090 \
  --agent-id web-server-01 \
  --setup-pm2
```

### Add PM2 to Existing Installation

If you already installed oxmon manually and want to add PM2 management:

```bash
# For server
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- server --pm2-only

# For agent
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- agent --pm2-only
```

### PM2 Common Commands

```bash
pm2 status                    # View process status
pm2 logs oxmon-server         # View server logs (real-time)
pm2 logs oxmon-agent          # View agent logs
pm2 restart oxmon-server      # Restart server
pm2 restart oxmon-agent       # Restart agent
pm2 stop oxmon-server         # Stop service
pm2 startup                   # Enable auto-start on boot
pm2 save                      # Save current process list
```

### Troubleshooting

If PM2 fails with `EACCES: permission denied` on log or data directories, fix ownership:

```bash
sudo chown $(id -u):$(id -g) /var/log/oxmon /var/lib/oxmon
pm2 restart oxmon-server   # or: pm2 reload oxmon-server
```

### Install Script Options

| Option | Description | Default |
|--------|-------------|---------|
| `server` / `agent` | Component to install (required, first argument) | — |
| `--version` | Release version tag | `latest` |
| `--install-dir` | Binary install path | `/usr/local/bin` |
| `--config-dir` | Config file path | `/etc/oxmon` |
| `--data-dir` | Server data storage (server only) | `/var/lib/oxmon` |
| `--agent-id` | Agent identifier (agent only) | `$(hostname)` |
| `--server-endpoint` | gRPC server address (agent only) | `http://127.0.0.1:9090` |
| `--setup-pm2` | Generate PM2 config and start service | off |
| `--pm2-only` | Only generate PM2 config (skip download) | off |

## Cross-Compilation / Multi-Platform Build

Supported target platforms:

| Target | Description |
|--------|-------------|
| `x86_64-unknown-linux-gnu` | Linux AMD64 |
| `aarch64-unknown-linux-gnu` | Linux ARM64 |
| `x86_64-apple-darwin` | macOS Intel |
| `aarch64-apple-darwin` | macOS Apple Silicon |

### Prerequisites

- [cross](https://github.com/cross-rs/cross) (Docker required for Linux cross-compilation)
- Rust toolchain with corresponding targets: `rustup target add <triple>`

### Using the Makefile

```bash
# Build a single Linux target (via cross)
make x86_64-unknown-linux-gnu
make aarch64-unknown-linux-gnu

# Build macOS target (native compilation)
make aarch64-apple-darwin

# Package artifacts for a target
make package TARGET=x86_64-unknown-linux-gnu

# Build and package all targets
make release
```

### Using cross Manually

```bash
cross build --release --target aarch64-unknown-linux-gnu
```

### Verify OpenSSL Removal

```bash
cargo tree -i openssl-sys
# Should output that "openssl-sys" does not exist
```

## Docker Deployment

### Build Images

```bash
# Single architecture
docker build -f Dockerfile.server -t oxmon-server .
docker build -f Dockerfile.agent -t oxmon-agent .

# Multi-architecture (requires docker buildx)
docker buildx build --platform linux/amd64,linux/arm64 \
  -f Dockerfile.agent -t oxmon-agent:latest --push .
docker buildx build --platform linux/amd64,linux/arm64 \
  -f Dockerfile.server -t oxmon-server:latest --push .
```

### Run the Server

```bash
docker run -d \
  -p 9090:9090 \
  -p 8080:8080 \
  -v $(pwd)/config/server.toml:/etc/oxmon/server.toml \
  -v $(pwd)/data:/data \
  --name oxmon-server \
  oxmon-server
```

### Run the Agent

```bash
docker run -d \
  -v $(pwd)/config/agent.toml:/etc/oxmon/agent.toml \
  --name oxmon-agent \
  oxmon-agent
```

## Alert Workflow

The system runs automatically with no manual intervention required:

1. **Collect** — Agent collects CPU, memory, disk, network, and load metrics at configured intervals
2. **Report** — Sent to server via gRPC; automatically buffered on connection failure, retransmitted on recovery
3. **Store** — Server writes to daily-partitioned SQLite, automatically cleans up expired data
4. **Evaluate** — Alert engine evaluates all matching alert rules against each data point
5. **Deduplicate** — Same alert won't re-trigger within the silence period
6. **Aggregate** — Similar alerts within the aggregation window are merged into a single notification
7. **Notify** — Routed to channels by severity (email / webhook / SMS / DingTalk / WeChat Work); suppressed during silence windows

## License

MIT
