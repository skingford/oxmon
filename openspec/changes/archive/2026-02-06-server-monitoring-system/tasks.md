## 1. Project Scaffolding

- [x] 1.1 Initialize Cargo workspace with root Cargo.toml and crates/ directory
- [x] 1.2 Create oxmon-common crate with shared types (MetricType, MetricDataPoint, MetricBatch, AlertEvent, Severity enums)
- [x] 1.3 Define Protocol Buffers schema (proto/metrics.proto) for MetricBatch and ReportResponse
- [x] 1.4 Create oxmon-agent crate skeleton (binary, TOML config parsing with serde)
- [x] 1.5 Create oxmon-server crate skeleton (binary, TOML config parsing with serde)
- [x] 1.6 Create config/agent.example.toml and config/server.example.toml with documented fields
- [x] 1.7 Set up workspace-level dependencies (tokio, tonic, prost, serde, toml, tracing)

## 2. Metric Collection (oxmon-collector)

- [x] 2.1 Create oxmon-collector crate with Collector trait defining the collect() interface
- [x] 2.2 Implement CpuCollector: overall usage % and per-core usage % using sysinfo crate
- [x] 2.3 Implement MemoryCollector: total, used, available memory and swap metrics
- [x] 2.4 Implement DiskCollector: per-mount space usage and per-device I/O (read/write bytes/sec)
- [x] 2.5 Implement NetworkCollector: per-interface bytes/packets sent/received per second
- [x] 2.6 Implement LoadCollector: 1/5/15-min load averages and system uptime
- [x] 2.7 Write unit tests for each collector with mocked system data
- [x] 2.8 Verify cross-platform support (Linux /proc and macOS sysctl via sysinfo abstraction)

## 3. Agent Core (oxmon-agent)

- [x] 3.1 Implement periodic collection loop with configurable interval using tokio timer
- [x] 3.2 Implement gRPC client for metric reporting using tonic (generated from proto)
- [x] 3.3 Implement local metric buffer (VecDeque) with configurable max size and overflow eviction
- [x] 3.4 Implement retry logic: buffer on connection failure, drain buffer on reconnect
- [x] 3.5 Wire TOML config: agent_id, server_endpoint, collection_interval, buffer_max_size
- [x] 3.6 Add graceful shutdown handling (SIGINT/SIGTERM)
- [x] 3.7 Write integration test: Agent collects and serializes a metric batch end-to-end

## 4. Metric Storage (oxmon-storage)

- [x] 4.1 Create oxmon-storage crate with StorageEngine trait (write_batch, query, cleanup)
- [x] 4.2 Implement SQLite partition manager: create/open partition files by time period (daily)
- [x] 4.3 Implement partition schema: metrics table with (timestamp, agent_id, metric_name, value, labels)
- [x] 4.4 Enable WAL mode (PRAGMA journal_mode=WAL) on partition creation
- [x] 4.5 Implement batch write: insert metric batch within a single transaction
- [x] 4.6 Implement time-range query: query by agent_id, metric_name, time range across partitions
- [x] 4.7 Implement data retention cleanup: delete partition files older than configured retention_days
- [x] 4.8 Write unit tests for partition CRUD, cross-partition queries, and retention cleanup

## 5. Server gRPC Ingestion (oxmon-server)

- [x] 5.1 Implement gRPC MetricService using tonic (ReportMetrics RPC from proto definition)
- [x] 5.2 Validate incoming MetricBatch (non-empty, valid agent_id, valid timestamps)
- [x] 5.3 Wire gRPC service to StorageEngine for persisting received batches
- [x] 5.4 Register agent on first metric report (track agent_id and last_seen timestamp)
- [x] 5.5 Write integration test: gRPC client sends batch → Server persists → query returns data

## 6. Alert Engine (oxmon-alert)

- [x] 6.1 Create oxmon-alert crate with AlertRule trait and AlertEvent struct
- [x] 6.2 Implement SlidingWindow data structure (time-bounded ring buffer per rule per agent)
- [x] 6.3 Implement ThresholdRule: evaluate metric > threshold sustained for duration
- [x] 6.4 Implement RateOfChangeRule: evaluate percentage change within time window
- [x] 6.5 Implement TrendPredictionRule: linear regression on sliding window, predict time-to-breach
- [x] 6.6 Implement alert deduplication: suppress duplicate AlertEvents within silence period per rule+agent
- [x] 6.7 Implement severity levels (info/warning/critical) on AlertEvent
- [x] 6.8 Implement agent glob pattern matching for rules (e.g., "web-*")
- [x] 6.9 Wire alert engine to storage: feed new metric data into sliding windows and trigger evaluation
- [x] 6.10 Parse alert rules from Server TOML config ([[alert.rules]] sections)
- [x] 6.11 Write unit tests for each rule type, deduplication, and glob matching

## 7. Notification System (oxmon-notify)

- [x] 7.1 Create oxmon-notify crate with NotificationChannel trait (async send, channel_type)
- [x] 7.2 Implement EmailChannel: SMTP send via lettre crate with retry (3x exponential backoff)
- [x] 7.3 Implement WebhookChannel: HTTP POST via reqwest with custom body template rendering and retry
- [x] 7.4 Implement SmsChannel: configurable SMS gateway HTTP API call with retry
- [x] 7.5 Implement severity-based routing: route AlertEvents to channels by min_severity filter
- [x] 7.6 Implement silence windows: suppress notifications during configured time periods (with recurrence)
- [x] 7.7 Implement alert aggregation: batch similar AlertEvents within aggregation window into single notification
- [x] 7.8 Parse notification config from Server TOML ([[notification.channels]], [[notification.silence_windows]])
- [x] 7.9 Write unit tests for routing, silence window evaluation, and aggregation logic

## 8. Dashboard REST API (oxmon-server)

- [x] 8.1 Set up axum router with /api/v1 prefix, sharing tokio runtime with tonic gRPC
- [x] 8.2 Implement GET /api/v1/health (version, uptime, agent count, storage status)
- [x] 8.3 Implement GET /api/v1/agents (list agents with id, last_seen, active/inactive status)
- [x] 8.4 Implement GET /api/v1/agents/:id/latest (latest metric values for a specific agent)
- [x] 8.5 Implement GET /api/v1/metrics (query time-series with agent, metric, from, to, step params)
- [x] 8.6 Implement GET /api/v1/alerts/rules (list all configured alert rules)
- [x] 8.7 Implement GET /api/v1/alerts/history (query alert history with severity, agent, time, pagination filters)
- [x] 8.8 Implement unified JSON error response format (error + code fields, proper HTTP status codes)
- [x] 8.9 Write integration tests for each API endpoint with test fixtures

## 9. Server Wiring & Configuration

- [x] 9.1 Wire all components in oxmon-server main: storage + gRPC + alert engine + notification + axum API
- [x] 9.2 Implement shared application state (Arc-wrapped storage, alert engine, notification manager)
- [x] 9.3 Start gRPC server and axum HTTP server on configurable ports (single tokio runtime)
- [x] 9.4 Implement periodic tasks: data retention cleanup cycle, alert engine evaluation tick
- [x] 9.5 Add graceful shutdown for Server (drain connections on SIGINT/SIGTERM)
- [x] 9.6 Write end-to-end test: Agent reports → Server stores → alert fires → notification sent

## 10. Documentation & Packaging

- [x] 10.1 Write README.md with project overview, architecture diagram, quick start guide
- [x] 10.2 Document TOML config format for Agent and Server with all fields explained
- [x] 10.3 Add Dockerfile for Agent and Server binaries
- [x] 10.4 Add CI workflow (cargo build, cargo test, cargo clippy) for GitHub Actions
