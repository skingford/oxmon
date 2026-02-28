English | [中文](README.zh-CN.md)

# oxmon

Lightweight server monitoring system built with Rust. Collects system metrics (CPU, memory, disk, network, load), stores time-series data, evaluates alert rules, and sends notifications through multiple channels.

## Table of Contents

- [Architecture](#architecture)
- [Crate Structure](#crate-structure)
- [Quick Start](#quick-start)
- [Local Testing (Mock Ingest + API Checks)](#local-testing-mock-ingest--api-checks)
- [Configuration](#configuration)
- [Collected Metrics](#collected-metrics)
- [API Reference](#api-reference)
- [Linux Quick Deploy](#linux-quick-deploy)
- [Docker Deployment](#docker-deployment)
- [License](#license)

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

## Local Testing (Mock Ingest + API Checks)

The repository includes three scripts for local integration testing:

- `scripts/mock-report-all.sh`: ingest all mock scenarios (baseline + alert-triggering data)
- `scripts/mock-query-check.sh`: validate core read APIs and print a summary table
- `scripts/mock-e2e.sh`: one-command workflow that runs ingest + API checks

### 1) One-command E2E (recommended)

```bash
# Runs all mock scenarios, then validates API endpoints
scripts/mock-e2e.sh

# When server has require_agent_auth=true
scripts/mock-e2e.sh --auto-auth --username admin --password changeme
```

### 2) Run ingest and checks separately

```bash
# Step 1: ingest all scenarios
scripts/mock-report-all.sh --scenario all --agent-count 5

# Step 2: validate metrics / alerts / dashboard endpoints
scripts/mock-query-check.sh
```

### 3) Run a single scenario only

```bash
# Trigger rate_of_change scenario only
scripts/mock-report-all.sh --scenario rate

# Trigger trend_prediction scenario only
scripts/mock-report-all.sh --scenario trend
```

Supported scenarios: `all`, `baseline`, `threshold`, `rate`, `trend`, `cert`.

### 4) Common options

```bash
# Print batch summaries during ingest
scripts/mock-report-all.sh --print-payload

# Print raw API responses during validation
scripts/mock-query-check.sh --verbose

# Select target for /v1/metrics/summary
scripts/mock-query-check.sh --summary-agent mock-threshold --summary-metric cpu.usage
```

### 5) Token map file format (optional)

If you don't use `--auto-auth` but server auth is enabled, pass a token mapping file:

```ini
mock-normal-01=token_xxx
mock-normal-02=token_yyy
mock-threshold=token_zzz
mock-rate=token_aaa
mock-trend=token_bbb
cert-checker=token_ccc
```

Then run:

```bash
scripts/mock-report-all.sh --auth-token-file ./tokens.env
```

## Configuration

### Agent Configuration (`agent.toml`)

| Field | Description | Default |
|-------|-------------|---------|
| `agent_id` | Unique identifier for this node | `"web-server-01"` |
| `server_endpoint` | Server gRPC address (`host:port`) | `"127.0.0.1:9090"` |
| `tls` | Enable TLS for gRPC connection | `false` |
| `auth_token` | Authentication token (optional, required when server auth is enabled) | none |
| `collection_interval_secs` | Metric collection interval (seconds) | `10` |
| `buffer_max_size` | Max buffered batches when server is unreachable | `1000` |

Example:

```toml
agent_id = "web-server-01"
server_endpoint = "10.0.1.100:9090"
# tls = true  # Enable TLS for gRPC connection
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
| `database.data_dir` | SQLite data file storage directory | `"data"` |
| `retention_days` | Data retention in days, auto-cleanup when expired | `7` |
| `require_agent_auth` | Require agent authentication | `false` |
| `agent_collection_interval_secs` | Agent collection interval (seconds) for determining active status. Timeout threshold is 3x this value. Should match agents' `collection_interval_secs` | `10` |

#### Alert Rules (DB-backed, API-managed)

Alert rules are stored in the database and managed dynamically via REST API or CLI. Four rule types are supported: `threshold`, `rate_of_change`, `trend_prediction`, and `cert_expiration`.

**Initial setup** uses the `init-rules` CLI subcommand with a JSON seed file:

```bash
oxmon-server init-rules config/server.toml config/rules.seed.json
```

See `config/rules.seed.example.json` for rule configuration examples including:
- **Threshold Alert** — triggers when a metric exceeds a threshold for a sustained duration
- **Rate of Change Alert** — triggers when a metric changes beyond a percentage within a time window
- **Trend Prediction Alert** — uses linear regression to predict when a metric will breach a threshold
- **Certificate Expiration Alert** — triggers tiered alerts based on days until certificate expiry

Duplicate rule names are skipped on re-run. After initial setup, use the REST API (`/v1/alerts/rules`) to manage rules. CRUD operations trigger immediate hot-reload without server restart.

See [API Reference](#api-reference) for detailed endpoint documentation.

#### Notification Channels (DB-backed, API-managed)

Notification channels are stored in the database and managed dynamically via REST API. Each channel type supports **multiple instances** (e.g., separate email configs for ops and dev teams). Recipients (email addresses, phone numbers, webhook URLs) are managed independently per channel.

**Initial setup** uses the `init-channels` CLI subcommand with a JSON seed file:

```bash
oxmon-server init-channels config/server.toml config/channels.seed.json
```

See `config/channels.seed.example.json` for a template. Duplicate channel names are skipped on re-run. After initial setup, use the REST API (`/v1/notifications/channels`) to manage channels, recipients, and send test notifications.

Built-in channel types: `email`, `webhook`, `sms`, `dingtalk`, `weixin`.

**Channel config reference:**

| Type | Required Config | Recipient Type |
|------|----------------|----------------|
| `email` | `smtp_host`, `smtp_port`, `from_name`, `from_email` | Email address |
| `webhook` | (none) | URL |
| `sms` | `gateway_url`, `api_key` | Phone number |
| `dingtalk` | `webhook_url` | Webhook URL |
| `weixin` | `webhook_url` | Webhook URL |

DingTalk supports optional `secret` for HMAC-SHA256 signing. Webhook supports optional `body_template` with `{{agent_id}}`, `{{metric}}`, `{{value}}`, `{{severity}}`, `{{message}}` variables.

> **Plugin System**: Each channel is an independent `ChannelPlugin` with `ChannelRegistry` for dynamic lookup and instantiation. Configuration changes trigger hot-reload — no server restart required.

#### Silence Windows (DB-backed, API-managed)

Suppress notifications during maintenance windows. Managed via REST API (`/v1/notifications/silence-windows`).

#### Runtime Settings (DB-backed)

Runtime parameters such as alert aggregation and log retention are stored in the database (`system_configs` table) and managed via REST API (`/v1/system/configs`). Default values are auto-initialized on first server startup:
- `aggregation_window_secs`: 60 (seconds for batching similar alerts into one notification)
- `log_retention_days`: 30 (notification log retention period)

#### System Dictionaries (DB-backed)

Centralized enum management for system constants (channel types, severity levels, rule types, alert statuses, etc.). Stored in the database (`system_dictionaries` table) and managed via REST API (`/v1/dictionaries`) or CLI.

**Initial setup** uses the `init-dictionaries` CLI subcommand with a JSON seed file:

```bash
oxmon-server init-dictionaries config/server.toml config/dictionaries.seed.json
```

See `config/dictionaries.seed.example.json` for the default seed data (~50 items). Default dictionaries are auto-initialized on first server startup when the table is empty.

Available dictionary types: `channel_type`, `severity`, `rule_type`, `alert_status`, `agent_status`, `compare_operator`, `metric_name`, `rule_source`, `recipient_type`. System built-in items are protected from deletion.

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

<a id="api-reference"></a>

## API Reference

REST API documentation has been moved to a standalone guide:

- English: [`docs/api-reference.md`](docs/api-reference.md)
- 中文: [`docs/api-reference.zh-CN.md`](docs/api-reference.zh-CN.md)

OpenAPI endpoints remain available:

| Endpoint | Format |
|----------|--------|
| `GET /v1/openapi.json` | JSON format |
| `GET /v1/openapi.yaml` | YAML format |

Quick import URL (Apifox/Postman/Swagger): `http://<server-ip>:8080/v1/openapi.json`

### Common SQLite Commands

oxmon stores data in SQLite:

- `data/oxmon.db`: users, whitelist, certificate domains, certificate details
- `data/YYYY-MM-DD.db`: daily partitioned metric & alert data (`metrics`, `alert_events`)

```bash
# List database files in the data directory
ls -lh data/*.db

# Open main database
sqlite3 data/oxmon.db

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
  --server-endpoint 10.0.1.100:9090

# Custom agent ID + PM2
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- agent \
  --server-endpoint 10.0.1.100:9090 \
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
| `--server-endpoint` | gRPC server address (agent only) | `127.0.0.1:9090` |
| `--setup-pm2` | Generate PM2 config and start service | off |
| `--pm2-only` | Only generate PM2 config (skip download) | off |

## Cross-Compilation / Multi-Platform Build

Supported target platforms:

| Platform | Description |
|----------|-------------|
| `x86_64-linux` | Linux AMD64 |
| `aarch64-linux` | Linux ARM64 |
| `x86_64-macos` | macOS Intel |
| `aarch64-macos` | macOS Apple Silicon |

> Release artifacts use simplified platform names (e.g., `x86_64-linux`). Internal Rust builds use standard target triples (e.g., `x86_64-unknown-linux-gnu`).

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

### GitHub Release Publishing

```bash
# 1) Sync main branch and verify tests
git checkout main
git pull --ff-only
cargo test --workspace

# 2) Bump version
# Edit Cargo.toml: [workspace.package].version = "0.1.2"
cargo check --workspace

# 3) Commit release version files
git add Cargo.toml Cargo.lock
git commit -m "chore(release): bump version to 0.1.2"

# 4) Create and push tag
git tag -a v0.1.2 -m "v0.1.2"
git push origin main
git push origin v0.1.2
```

Or use the helper script (auto patch bump if version is omitted):

```bash
# Auto bump patch (e.g. 0.1.1 -> 0.1.2), then commit + tag + push main/tag
./scripts/release.sh

# Specify a version explicitly (also auto push by default)
./scripts/release.sh --version 0.1.2

# Only create local commit/tag, do not push
./scripts/release.sh --version 0.1.2 --no-push
```

- `scripts/release.sh` now pushes `main` and `v*` tag by default (use `--no-push` to only create local commit/tag).
- Pushing a `v*` tag triggers `.github/workflows/release.yml` automatically.
- After workflow success, verify assets in GitHub Releases (`oxmon-agent-*` / `oxmon-server-*` tarballs and `SHA256SUMS`).
- Linux upgrades can be done by rerunning the install command (defaults to `latest`).

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
