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
| `oxmon-storage` | `StorageEngine` trait, time-partitioned SQLite (daily), cert storage |
| `oxmon-alert` | `AlertRule` trait, rule types (threshold, rate-of-change, trend), sliding window engine |
| `oxmon-notify` | `ChannelPlugin` trait, plugin registry, routing by severity, silence windows. Plugins: email, webhook, sms, dingtalk, weixin |
| `oxmon-server` | Server binary: gRPC handler, REST API, `AppState`, cert scheduler |

## Key Patterns

- **Trait-based extensibility**: `Collector`, `AlertRule`, `ChannelPlugin`, `StorageEngine` are all traits. New implementations register through their respective registries/engines.
- **Shared state**: `AppState` (in `oxmon-server/src/state.rs`) wraps components in `Arc` and is cloned into axum/gRPC handlers.
- **Alert deduplication**: The alert engine uses per-(rule_id, agent_id) sliding windows with configurable silence periods.
- **Agent glob matching**: Alert rules use `glob-match` patterns to target specific agents.
- **No OpenSSL**: All TLS uses `rustls`/`tokio-rustls`. The `reqwest` dependency uses `rustls-tls` feature. SQLite is bundled.

## REST API Routes

Core metrics API is in `oxmon-server/src/api.rs`. Certificate management API is in `oxmon-server/src/cert/api.rs`. OpenAPI spec is served from `oxmon-server/src/openapi.rs`. All routes are prefixed with `/api/v1/`.

## Configuration

Example configs are in `config/agent.example.toml` and `config/server.example.toml`. Parsed via `toml` crate in each binary's `config.rs`.
