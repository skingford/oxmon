## ADDED Requirements

### Requirement: Server SHALL receive metrics via gRPC
Server SHALL expose a gRPC endpoint to receive metric batches from Agents.

#### Scenario: Receive metric batch
- **WHEN** an Agent sends a metric batch via gRPC
- **THEN** Server SHALL validate the batch format and return a success acknowledgment

#### Scenario: Reject malformed batch
- **WHEN** an Agent sends an invalid or incomplete metric batch
- **THEN** Server SHALL return an error response with a descriptive error code

### Requirement: Server SHALL persist metrics in time-partitioned SQLite storage
Server SHALL store received metrics in SQLite databases partitioned by time.

#### Scenario: Write metrics to current partition
- **WHEN** Server receives a valid metric batch
- **THEN** Server SHALL insert all metric data points into the SQLite partition file corresponding to the metric timestamps

#### Scenario: Batch insert for performance
- **WHEN** Server receives multiple metric batches within a short time window
- **THEN** Server SHALL batch inserts into a single transaction to maximize write throughput

#### Scenario: Automatic partition creation
- **WHEN** a metric arrives for a time period with no existing partition file
- **THEN** Server SHALL create a new SQLite partition file with the appropriate schema

### Requirement: Server SHALL support time-range metric queries
Server SHALL provide the ability to query metrics by agent, metric name, and time range.

#### Scenario: Query metrics by time range
- **WHEN** a query requests metrics for agent "web-01", metric "cpu.usage", from T1 to T2
- **THEN** Server SHALL return all matching data points ordered by timestamp ascending

#### Scenario: Query spans multiple partitions
- **WHEN** a query time range spans multiple partition files
- **THEN** Server SHALL transparently query across all relevant partitions and merge results

#### Scenario: Query with no matching data
- **WHEN** a query matches no data points
- **THEN** Server SHALL return an empty result set (not an error)

### Requirement: Server SHALL enforce data retention policy
Server SHALL automatically remove metric data older than the configured retention period.

#### Scenario: Expire old partitions
- **WHEN** a partition file contains only data older than the retention period (default 7 days)
- **THEN** Server SHALL delete the partition file during the next cleanup cycle

#### Scenario: Configurable retention period
- **WHEN** Server starts with `retention_days = 30` in the config file
- **THEN** Server SHALL retain metric data for 30 days and delete older partitions

### Requirement: Server SHALL use WAL mode for SQLite
Server SHALL enable SQLite WAL (Write-Ahead Logging) mode for all partition databases.

#### Scenario: Enable WAL on partition creation
- **WHEN** Server creates a new SQLite partition file
- **THEN** Server SHALL set `PRAGMA journal_mode=WAL` before any writes

#### Scenario: Concurrent read during write
- **WHEN** a read query executes while a write transaction is in progress
- **THEN** the read query SHALL succeed without blocking
