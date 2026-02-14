# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
cargo build --release          # Build both binaries (oxmon-agent, oxmon-server)
cargo test --workspace         # Run all tests
cargo clippy --workspace -- -D warnings  # Lint (CI treats all warnings as errors)
cargo test -p oxmon-storage    # Run tests for a single crate
cargo test -p oxmon-alert      # Run tests for alert crate
cargo test -p oxmon-notify     # Run tests for notify crate
```

**Cross-compilation** requires `cross` installed (`cargo install cross`):
```bash
make x86_64-unknown-linux-gnu  # Linux AMD64 via cross
make aarch64-unknown-linux-gnu # Linux ARM64 via cross
make aarch64-apple-darwin      # macOS Apple Silicon (native cargo)
```

**Protobuf**: CI installs `protoc` v25.1. The proto file `proto/metrics.proto` is compiled by `tonic-build` in `crates/oxmon-common/build.rs`.

## Architecture

**Agent-Server model** for server monitoring:

```
Agent (per monitored host)          Server (central)
├── Collectors (CPU/Mem/Disk/       ├── gRPC ingestion (tonic)
│   Network/Load via sysinfo)       ├── Time-partitioned SQLite storage
├── Local VecDeque buffer           ├── Alert rule engine (sliding window)
│   (offline resilience)            ├── Notification manager (plugin system)
└── gRPC client ──MetricBatch──►    ├── REST API (axum)
                                    ├── Certificate monitoring scheduler
                                    └── OpenAPI doc endpoint
```

## Workspace Crates

| Crate | Role |
|-------|------|
| `oxmon-common` | Shared types, protobuf codegen (build.rs), `MetricDataPoint` |
| `oxmon-collector` | Trait `Collector` + implementations for each metric type |
| `oxmon-agent` | Agent binary: collection loop, gRPC client, offline buffering |
| `oxmon-storage` | `StorageEngine` trait, time-partitioned SQLite (daily), cert storage, agent whitelist, token auth (`auth` module) |
| `oxmon-alert` | `AlertRule` trait, rule types (threshold, rate-of-change, trend, cert-expiration), sliding window engine |
| `oxmon-notify` | `ChannelPlugin` trait, plugin registry, DB-backed multi-instance channels, recipient management, routing by severity, silence windows. Plugins: email, webhook, sms (generic/aliyun/tencent), dingtalk, weixin |
| `oxmon-server` | Server binary: gRPC handler, REST API, `AppState`, cert scheduler |

## Key Patterns

- **Trait-based extensibility**: `Collector`, `AlertRule`, `ChannelPlugin`, `StorageEngine` are all traits. New implementations register through their respective registries/engines.
- **Shared state**: `AppState` (in `oxmon-server/src/state.rs`) wraps components in `Arc` and is cloned into axum/gRPC handlers.
- **DB-backed alert rules**: Alert rules are stored in the `alert_rules` table and loaded into `AlertEngine` at startup via `rule_builder::reload_alert_engine()`. CRUD operations via REST API (`/v1/alerts/rules`) trigger immediate hot-reload. Initial setup via `init-rules` CLI subcommand or REST API. Conversion from DB rows to trait objects is in `oxmon-server/src/rule_builder.rs`.
- **Alert deduplication**: The alert engine uses per-(rule_id, agent_id) sliding windows with configurable silence periods.
- **Agent glob matching**: Alert rules use `glob-match` patterns to target specific agents.
- **No OpenSSL**: All TLS uses `rustls`/`tokio-rustls`. The `reqwest` dependency uses `rustls-tls` feature. SQLite is bundled.
- **Agent authentication**: Optional bearer-token auth for gRPC ingestion. Tokens are bcrypt-hashed and stored in the `agent_whitelist` table. Managed via REST API (`/v1/agents/whitelist`). Controlled by `require_agent_auth` config flag.
- **Certificate details collection**: The cert scheduler uses `CertificateCollector` (DNS resolution + TLS + x509 parsing) to gather detailed cert info (issuer, SANs, chain validation, IPs) stored in `certificate_details` table.
- **DB-backed notification channels**: Channels are stored in `notification_channels` table with a separate `notification_recipients` table. Each channel type supports multiple instances. Channel configuration (SMTP, SMS API credentials, webhook URLs, etc.) is stored directly in each channel's `config_json` field. `NotificationManager` uses `RwLock<HashMap<String, ChannelInstance>>` with build-then-swap hot-reload via `reload()`. Initial setup via `init-channels` CLI subcommand or REST API (no TOML migration).
- **Recipient separation**: Recipients (email addresses, phone numbers, webhook URLs) are stored in `notification_recipients` and managed independently per channel via REST API (`/v1/notifications/channels/{id}/recipients`).
- **Silence windows from DB**: Silence windows are read from DB at notification time rather than loaded into memory at startup.
- **Runtime settings**: Notification runtime parameters (`aggregation_window_secs`, `log_retention_days`) are stored in `system_configs` table with `config_type="runtime"`. Auto-initialized with default values on first startup via `runtime_seed::init_default_runtime_settings()`. Retrieved via `CertStore::get_runtime_setting_u64()` and `get_runtime_setting_u32()` methods. Note: `system_configs` table is ONLY for runtime parameters; sender configs (email/sms) are stored in each notification channel's `config_json`.
- **System dictionaries**: Centralized enum management for system constants (channel types, severity levels, rule types, alert statuses, agent statuses, compare operators, metric names, rule sources, recipient types). Stored in `system_dictionaries` table with `dict_type` + `dict_key` unique constraint. System built-in items (`is_system = true`) are protected from deletion. Default seed data (~50 items) is auto-initialized on first startup when the table is empty. Managed via REST API (`/v1/dictionaries`) or `init-dictionaries` CLI subcommand. Seed data defined in `oxmon-server/src/dictionary_seed.rs`.

## REST API Routes

Core metrics API is in `oxmon-server/src/api.rs`. Certificate management API is in `oxmon-server/src/cert/api.rs`. Certificate details API is in `oxmon-server/src/api/certificates.rs`. Agent whitelist API is in `oxmon-server/src/api/whitelist.rs`. Alert rules & lifecycle API is in `oxmon-server/src/api/alerts.rs`. Notification channels & silence windows API is in `oxmon-server/src/api/notifications.rs`. Dashboard API is in `oxmon-server/src/api/dashboard.rs`. System management API is in `oxmon-server/src/api/system.rs`. Dictionary management API is in `oxmon-server/src/api/dictionaries.rs`. OpenAPI spec is served from `oxmon-server/src/openapi.rs`. All routes are prefixed with `/v1/`.

## CLI Subcommands

```
oxmon-server [config.toml]                                    # Start server (default)
oxmon-server init-channels <config.toml> <seed.json>          # Initialize channels from seed file
oxmon-server init-rules <config.toml> <seed.json>             # Initialize alert rules from seed file
oxmon-server init-dictionaries <config.toml> <seed.json>      # Initialize dictionaries from seed file
```

The `init-channels` subcommand reads a JSON seed file (see `config/channels.seed.example.json`) and inserts notification channels and silence windows into the database. Duplicate channel names are skipped.

The `init-rules` subcommand reads a JSON seed file (see `config/rules.seed.example.json`) and inserts alert rules into the database. Duplicate rule names are skipped.

The `init-dictionaries` subcommand reads a JSON seed file (see `config/dictionaries.seed.example.json`) and inserts dictionary items into the database. Duplicate `dict_type` + `dict_key` pairs are skipped.

## Configuration

Example configs are in `config/agent.example.toml` and `config/server.example.toml`. Parsed via `toml` crate in each binary's `config.rs`. Notification channels are **not** configured in TOML — use `init-channels` CLI or REST API. Alert rules are **not** configured in TOML — use `init-rules` CLI or REST API. Runtime settings (aggregation window, log retention) are **not** configured in TOML — they are stored in the database as `system_configs` with `config_type="runtime"` and can be managed via REST API.
