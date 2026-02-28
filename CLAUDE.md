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

**Agent-Server model** for server monitoring with cloud integration:

```
Agent (per monitored host)          Server (central)
├── Collectors (CPU/Mem/Disk/       ├── gRPC ingestion (tonic)
│   Network/Load via sysinfo)       ├── Time-partitioned SQLite storage
├── Local VecDeque buffer           ├── Alert rule engine (sliding window)
│   (offline resilience)            ├── Notification manager (plugin system)
└── gRPC client ──MetricBatch──►    ├── REST API (axum)
                                    ├── Certificate monitoring scheduler
                                    ├── Cloud monitoring scheduler
                                    │   ├── Tencent Cloud API (TC3-HMAC-SHA256)
                                    │   └── Alibaba Cloud API (ACS v1 HMAC-SHA1)
                                    └── OpenAPI doc endpoint
```

## Workspace Crates

| Crate | Role |
|-------|------|
| `oxmon-common` | Shared types, protobuf codegen (build.rs), `MetricDataPoint` |
| `oxmon-collector` | Trait `Collector` + implementations for each metric type |
| `oxmon-agent` | Agent binary: collection loop, gRPC client, offline buffering |
| `oxmon-storage` | `StorageEngine` trait, time-partitioned SQLite (daily), cert storage, agent whitelist, token auth (`auth` module), cloud collection state & instances |
| `oxmon-alert` | `AlertRule` trait, rule types (threshold, rate-of-change, trend, cert-expiration), sliding window engine |
| `oxmon-notify` | `ChannelPlugin` trait, plugin registry, DB-backed multi-instance channels, recipient management, routing by severity, silence windows. Plugins: email, webhook, sms (generic/aliyun/tencent), dingtalk, weixin |
| `oxmon-cloud` | Cloud provider integrations: `CloudProvider` trait, Tencent/Alibaba implementations with API signing, `CloudCollector` for concurrent metrics collection, rate limiting, retry logic |
| `oxmon-server` | Server binary: gRPC handler, REST API, `AppState`, cert scheduler, cloud scheduler |

## Key Patterns

- **Trait-based extensibility**: `Collector`, `AlertRule`, `ChannelPlugin`, `StorageEngine` are all traits. New implementations register through their respective registries/engines.
- **Shared state**: `AppState` (in `oxmon-server/src/state.rs`) wraps components in `Arc` and is cloned into axum/gRPC handlers.
- **DB-backed alert rules**: Alert rules are stored in the `alert_rules` table and loaded into `AlertEngine` at startup via `rule_builder::reload_alert_engine()`. CRUD operations via REST API (`/v1/alerts/rules`) trigger immediate hot-reload. Initial setup via `init-rules` CLI subcommand or REST API. Conversion from DB rows to trait objects is in `oxmon-server/src/rule_builder.rs`.
- **Alert deduplication**: The alert engine uses per-(rule_id, agent_id) sliding windows with configurable silence periods.
- **Agent glob matching**: Alert rules use `glob-match` patterns to target specific agents.
- **No OpenSSL**: All TLS uses `rustls`/`tokio-rustls`. The `reqwest` dependency uses `rustls-tls` feature. SQLite is bundled.
- **Agent authentication**: Optional bearer-token auth for gRPC ingestion. Tokens are bcrypt-hashed and stored in the `agent_whitelist` table. Managed via REST API (`/v1/agents/whitelist`). Controlled by `require_agent_auth` config flag.
- **Application ID validation**: Optional `ox-app-id` header validation for public/auth endpoints (health check, login). Controlled by `require_app_id` config flag (default: false for backward compatibility). When enabled, requests without valid `ox-app-id` are rejected with 403 Forbidden. Supports whitelist validation via `allowed_app_ids` configuration. Does not affect JWT-protected routes. Middleware is in `oxmon-server/src/middleware.rs`.
- **Certificate details collection**: The cert scheduler uses `CertificateCollector` (DNS resolution + TLS + x509 parsing) to gather detailed cert info (issuer, SANs, chain validation, IPs) stored in `certificate_details` table.
- **DB-backed notification channels**: Channels are stored in `notification_channels` table with a separate `notification_recipients` table. Each channel type supports multiple instances. Channel configuration (SMTP, SMS API credentials, webhook URLs, etc.) is stored directly in each channel's `config_json` field. `NotificationManager` uses `RwLock<HashMap<String, ChannelInstance>>` with build-then-swap hot-reload via `reload()`. Initial setup via `init-channels` CLI subcommand or REST API (no TOML migration).
- **Recipient separation**: Recipients (email addresses, phone numbers, webhook URLs) are stored in `notification_recipients` and managed independently per channel via REST API (`/v1/notifications/channels/{id}/recipients`).
- **Silence windows from DB**: Silence windows are read from DB at notification time rather than loaded into memory at startup.
- **Runtime settings**: Notification runtime parameters (`aggregation_window_secs`, `log_retention_days`) are stored in `system_configs` table with `config_type="runtime"`. Auto-initialized with default values on first startup via `runtime_seed::init_default_runtime_settings()`. Retrieved via `CertStore::get_runtime_setting_u64()` and `get_runtime_setting_u32()` methods. Note: `system_configs` table is ONLY for runtime parameters; sender configs (email/sms) are stored in each notification channel's `config_json`.
- **System dictionaries**: Centralized enum management for system constants (channel types, severity levels, rule types, alert statuses, agent statuses, compare operators, metric names, rule sources, recipient types). Stored in `system_dictionaries` table with `dict_type` + `dict_key` unique constraint. System built-in items (`is_system = true`) are protected from deletion. Default seed data (~50 items) is auto-initialized on first startup when the table is empty. Managed via REST API (`/v1/dictionaries`) or `init-dictionaries` CLI subcommand. Seed data defined in `oxmon-server/src/dictionary_seed.rs`.

- **Multi-language (i18n)**: The `oxmon-common::i18n` module provides a lightweight translation registry (`TRANSLATIONS` singleton) keyed by `(locale, message_key)`. Supported locales: `zh-CN` (default), `en`. The global language is stored as a `language` runtime setting in `system_configs`. Alert rules receive `locale` via `evaluate(window, now, locale)` and notification channels via `send(alert, recipients, locale)`. Adding a new locale requires: (1) add translations in `i18n.rs`, (2) add a dictionary entry in `dictionary_seed.rs`, (3) add the locale to `SUPPORTED_LOCALES`.

- **Cloud monitoring**: Server-side scheduler collects metrics from cloud providers (Tencent Cloud, Alibaba Cloud) via their native APIs. Cloud accounts are stored in a dedicated `cloud_accounts` table (NOT in `system_configs`). Table schema includes fields: `id`, `config_key` (unique), `provider`, `display_name`, `description`, `account_name`（云账号名称如"主账号"）, `secret_id` (AccessKey ID), `secret_key` (AccessKey Secret), `regions` (JSON array of region strings, e.g. `["ap-shanghai","ap-guangzhou"]`), `collection_interval_secs`, `enabled`, `created_at`, `updated_at`. Managed exclusively via REST API (`/v1/cloud/accounts`). Batch import supported via `POST /v1/cloud/accounts/batch` with pipe-delimited text format: `账号名:SecretId:SecretKey:region1,region2|...`. Supported providers: `tencent` (腾讯云), `alibaba` (阿里云). Cloud instances are discovered via provider APIs and stored in `cloud_instances` table. Collected metrics are written to the same time-partitioned storage as agent metrics. Virtual agent IDs follow format `cloud:{provider}:{instance_id}` (e.g., `cloud:tencent:ins-abc123`), enabling alert rules to target cloud instances using glob patterns. Metrics include `cloud.cpu.usage`, `cloud.memory.usage`, `cloud.disk.usage`. API signing implemented without OpenSSL: TC3-HMAC-SHA256 for Tencent, ACS v1 HMAC-SHA1 for Alibaba. Rate limiting and exponential backoff retry for Alibaba Cloud (10 req/s with token bucket). Scheduler is in `oxmon-server/src/cloud/scheduler.rs`, API routes in `oxmon-server/src/cloud/api.rs`. Table is auto-created on first startup. If migrating from old `system_configs` storage, data is automatically migrated and old entries are deleted.

- **AI account management**: AI accounts (for AI-powered report generation) are stored in a dedicated `ai_accounts` table (NOT in `system_configs`). Table schema includes fields: `id`, `config_key` (unique), `provider`, `display_name`, `description`, `api_key`, `api_secret`, `model`, `extra_config` (JSON string for additional settings like `base_url`, `timeout_secs`, `max_tokens`, `temperature`, `collection_interval_secs`), `enabled`, `created_at`, `updated_at`. Managed exclusively via REST API (`/v1/ai/accounts`). Supported providers: `zhipu` (智谱 GLM-4/GLM-5), `kimi`, `minimax`, `claude`, `codex`, `custom`. The AI scheduler (`oxmon-server/src/ai/scheduler.rs`) uses `CertStore::list_ai_accounts()` to load accounts and `build_analyzer()` to create provider-specific analyzers. API keys and secrets are always redacted in API responses. For data migration from old `system_configs` storage, use `scripts/migrate_ai_accounts.sh`. For verification, use `scripts/verify_ai_accounts.sh`.

- **Pagination convention**: All list endpoints use `PaginationParams` (defined in `oxmon-server/src/api/pagination.rs`) with `Option<u64>` for `limit` and `offset`. Default limit is **20**, maximum is **1000**. All filter parameters in query structs are `Option<T>` (non-required). All list endpoints return `success_paginated_response` with standardized envelope: `{ err_code, err_msg, trace_id, data: { items, total, limit, offset } }`. Storage layer methods that support pagination should also provide a corresponding `count_*` method with matching filter parameters for total count calculation.

## REST API Routes

Core metrics API is in `oxmon-server/src/api.rs`. Certificate management API is in `oxmon-server/src/cert/api.rs`. Certificate details API is in `oxmon-server/src/api/certificates.rs`. Agent whitelist API is in `oxmon-server/src/api/whitelist.rs`. Alert rules & lifecycle API is in `oxmon-server/src/api/alerts.rs`. Notification channels & silence windows API is in `oxmon-server/src/api/notifications.rs`. Dashboard API is in `oxmon-server/src/api/dashboard.rs`. System management API is in `oxmon-server/src/api/system.rs`. Dictionary management API is in `oxmon-server/src/api/dictionaries.rs`. Cloud accounts & instances API is in `oxmon-server/src/cloud/api.rs` (includes cloud instance detail endpoint `GET /v1/cloud/instances/{id}` with real-time metrics). AI accounts & reports API is in `oxmon-server/src/ai/api.rs` (includes endpoints for managing AI accounts and viewing generated reports). OpenAPI spec is served from `oxmon-server/src/openapi.rs`. All routes are prefixed with `/v1/`.

## CLI Subcommands

```
oxmon-server [config.toml]                                    # Start server (default)
oxmon-server init-channels <config.toml> <seed.json>          # Initialize channels from seed file
oxmon-server init-rules <config.toml> <seed.json>             # Initialize alert rules from seed file
oxmon-server init-dictionaries <config.toml> <seed.json>      # Initialize dictionaries from seed file
oxmon-server init-configs <config.toml> <seed.json>           # Initialize/update system configs (runtime settings, etc.)
```

The `init-channels` subcommand reads a JSON seed file (see `config/channels.seed.example.json`) and inserts notification channels and silence windows into the database. Duplicate channel names are skipped.

The `init-rules` subcommand reads a JSON seed file (see `config/rules.seed.example.json`) and inserts alert rules into the database. Duplicate rule names are skipped.

The `init-dictionaries` subcommand reads a JSON seed file (see `config/dictionaries.seed.example.json`) and inserts dictionary items into the database. Duplicate `dict_type` + `dict_key` pairs are skipped.

The `init-configs` subcommand reads a JSON seed file (see `config/runtime.seed.example.json`) and inserts or updates system configs in the database. If a config with the same `config_key` already exists, it will be updated with the seed data. This is useful for managing runtime settings (notification aggregation window, AI report schedule, language, etc.) via configuration files. Changes take effect on next scheduler tick or service restart.

The `init-cloud-accounts` subcommand reads a JSON seed file (see `config/cloud-accounts.seed.example.json`) and inserts cloud accounts into the database as `system_configs` with `config_type="cloud_account"`. Duplicate `config_key` values are skipped.

## Configuration

Example configs are in `config/agent.example.toml` and `config/server.example.toml`. Parsed via `toml` crate in each binary's `config.rs`. Notification channels are **not** configured in TOML — use `init-channels` CLI or REST API. Alert rules are **not** configured in TOML — use `init-rules` CLI or REST API. Cloud accounts are **not** configured in TOML — use `init-cloud-accounts` CLI or REST API. AI accounts are **not** configured in TOML — use `/v1/ai/accounts` REST API exclusively. Runtime settings (aggregation window, log retention, language) are **not** configured in TOML — they are stored in the database as `system_configs` with `config_type="runtime"` and can be managed via REST API.

**Cloud monitoring** is configured in `server.example.toml` under `[cloud_check]` section:
```toml
[cloud_check]
enabled = true          # Enable cloud monitoring scheduler (default: true)
tick_secs = 60          # Scheduler tick interval (default: 60)
max_concurrent = 5      # Max concurrent cloud API calls (default: 5)
```
Cloud accounts are **not** configured in TOML — use `/v1/cloud/accounts` REST API exclusively. Cloud accounts are stored in the `cloud_accounts` table with credentials and per-account `collection_interval_secs`. Supported providers: `tencent` (腾讯云), `alibaba` (阿里云). Cloud instances are represented as virtual agents with ID format `cloud:{provider}:{instance_id}`.

**Application ID validation** is configured in `server.example.toml` under `[app_id]` section:
```toml
[app_id]
require_app_id = false  # Default: false for backward compatibility
allowed_app_ids = ["web-console", "mobile-app"]  # Whitelist of allowed app IDs
```
When `require_app_id = true`, requests to public endpoints (health, login) without valid `ox-app-id` header are rejected with 403. If `allowed_app_ids` is empty, any non-empty value is accepted. If `allowed_app_ids` has entries, the header value must match one of them.

**AI report scheduling** is configured via runtime settings in the `system_configs` table (auto-initialized on first startup):
- `ai_report_schedule_enabled` (bool, default: true): Enable/disable daily AI report generation
- `ai_report_schedule_time` (string, default: "08:00"): Daily send time in HH:MM format (24-hour)
- `ai_report_send_notification` (bool, default: true): Whether to send notifications after generating reports

The scheduler checks every tick (default 60s) if the current time has reached the configured time and today's report hasn't been generated yet. Reports are generated once per day per AI account. To receive notifications, configure a notification channel with `channel_type="ai_report"`. See `AI_REPORT_SCHEDULE_GUIDE.md` for detailed configuration instructions.

## requirements

- 默认返回中文
- python 默认使用 uv 管理环境
