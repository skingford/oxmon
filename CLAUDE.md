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
| `oxmon-notify` | `ChannelPlugin` trait, plugin registry, DB-backed multi-instance channels, recipient management, routing by severity, silence windows. Plugins: email, webhook, sms, dingtalk, weixin |
| `oxmon-server` | Server binary: gRPC handler, REST API, `AppState`, cert scheduler |

## Key Patterns

- **Trait-based extensibility**: `Collector`, `AlertRule`, `ChannelPlugin`, `StorageEngine` are all traits. New implementations register through their respective registries/engines.
- **Shared state**: `AppState` (in `oxmon-server/src/state.rs`) wraps components in `Arc` and is cloned into axum/gRPC handlers.
- **Alert deduplication**: The alert engine uses per-(rule_id, agent_id) sliding windows with configurable silence periods.
- **Agent glob matching**: Alert rules use `glob-match` patterns to target specific agents.
- **No OpenSSL**: All TLS uses `rustls`/`tokio-rustls`. The `reqwest` dependency uses `rustls-tls` feature. SQLite is bundled.
- **Agent authentication**: Optional bearer-token auth for gRPC ingestion. Tokens are bcrypt-hashed and stored in the `agent_whitelist` table. Managed via REST API (`/v1/agents/whitelist`). Controlled by `require_agent_auth` config flag.
- **Certificate details collection**: The cert scheduler uses `CertificateCollector` (DNS resolution + TLS + x509 parsing) to gather detailed cert info (issuer, SANs, chain validation, IPs) stored in `certificate_details` table.
- **DB-backed notification channels**: Channels are stored in `notification_channels` table with a separate `notification_recipients` table. Each channel type supports multiple instances. `NotificationManager` uses `RwLock<HashMap<String, ChannelInstance>>` with build-then-swap hot-reload via `reload()`. TOML config is only used for first-time migration to DB.
- **Recipient separation**: Recipients (email addresses, phone numbers, webhook URLs) are stored in `notification_recipients` and managed independently per channel via REST API (`/v1/notifications/channels/{id}/recipients`).
- **Silence windows from DB**: Silence windows are read from DB at notification time rather than loaded into memory at startup.

## REST API Routes

Core metrics API is in `oxmon-server/src/api.rs`. Certificate management API is in `oxmon-server/src/cert/api.rs`. Certificate details API is in `oxmon-server/src/api/certificates.rs`. Agent whitelist API is in `oxmon-server/src/api/whitelist.rs`. Alert rules & lifecycle API is in `oxmon-server/src/api/alerts.rs`. Notification channels & silence windows API is in `oxmon-server/src/api/notifications.rs`. Dashboard API is in `oxmon-server/src/api/dashboard.rs`. System management API is in `oxmon-server/src/api/system.rs`. OpenAPI spec is served from `oxmon-server/src/openapi.rs`. All routes are prefixed with `/v1/`.

## Configuration

Example configs are in `config/agent.example.toml` and `config/server.example.toml`. Parsed via `toml` crate in each binary's `config.rs`.
