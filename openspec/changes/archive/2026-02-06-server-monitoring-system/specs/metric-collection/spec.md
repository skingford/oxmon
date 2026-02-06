## ADDED Requirements

### Requirement: Agent SHALL collect CPU metrics
Agent SHALL periodically collect CPU usage metrics including overall CPU utilization percentage and per-core utilization.

#### Scenario: Collect overall CPU usage
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL sample current CPU utilization percentage (0-100%) and record it with a UTC timestamp

#### Scenario: Collect per-core CPU usage
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL sample each logical core's utilization percentage and record them with a shared UTC timestamp

### Requirement: Agent SHALL collect memory metrics
Agent SHALL periodically collect memory usage metrics including total memory, used memory, available memory, and swap usage.

#### Scenario: Collect memory usage
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL record total memory (bytes), used memory (bytes), available memory (bytes), and usage percentage

#### Scenario: Collect swap usage
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL record total swap (bytes), used swap (bytes), and swap usage percentage

### Requirement: Agent SHALL collect disk metrics
Agent SHALL periodically collect disk usage and I/O metrics for all mounted filesystems.

#### Scenario: Collect disk space usage
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL record total capacity (bytes), used space (bytes), available space (bytes), and usage percentage for each mounted filesystem

#### Scenario: Collect disk I/O metrics
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL record read bytes/sec and write bytes/sec for each disk device

### Requirement: Agent SHALL collect network metrics
Agent SHALL periodically collect network I/O metrics for each network interface.

#### Scenario: Collect network throughput
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL record bytes sent/sec, bytes received/sec, packets sent/sec, and packets received/sec for each network interface

### Requirement: Agent SHALL collect system load metrics
Agent SHALL periodically collect system load averages and uptime.

#### Scenario: Collect load averages
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL record 1-minute, 5-minute, and 15-minute load averages

#### Scenario: Collect uptime
- **WHEN** the collection interval timer fires
- **THEN** Agent SHALL record system uptime in seconds

### Requirement: Agent SHALL report metrics to Server via gRPC
Agent SHALL batch collected metrics and report them to the Server endpoint at configurable intervals.

#### Scenario: Successful metric report
- **WHEN** Agent has collected metrics for the current reporting interval
- **THEN** Agent SHALL serialize the metric batch using Protocol Buffers and send it to the configured Server gRPC endpoint

#### Scenario: Report includes agent identity
- **WHEN** Agent sends a metric batch
- **THEN** the batch SHALL include the agent_id (configurable hostname or custom identifier) and a batch timestamp

### Requirement: Agent SHALL buffer metrics on connection failure
Agent SHALL cache unreported metrics locally when the Server is unreachable and retry on reconnection.

#### Scenario: Server unreachable during report
- **WHEN** Agent fails to send a metric batch due to network error or Server unavailability
- **THEN** Agent SHALL store the batch in a local buffer and retry sending on the next reporting interval

#### Scenario: Buffer overflow protection
- **WHEN** the local buffer exceeds the configured maximum size (default 1000 batches)
- **THEN** Agent SHALL discard the oldest batches to make room for new ones

### Requirement: Agent SHALL be configurable via TOML file
Agent SHALL read its configuration from a TOML file at startup.

#### Scenario: Configure collection interval
- **WHEN** Agent starts with `collection_interval = 10` in the config file
- **THEN** Agent SHALL collect metrics every 10 seconds

#### Scenario: Configure server endpoint
- **WHEN** Agent starts with `server_endpoint = "http://10.0.0.1:9090"` in the config file
- **THEN** Agent SHALL report metrics to that gRPC endpoint

#### Scenario: Configure agent identity
- **WHEN** Agent starts with `agent_id = "web-server-01"` in the config file
- **THEN** Agent SHALL use "web-server-01" as its identity in all metric reports

### Requirement: Agent SHALL support cross-platform metric collection
Agent SHALL collect metrics on both Linux and macOS using platform-appropriate system APIs.

#### Scenario: Collect metrics on Linux
- **WHEN** Agent runs on a Linux system
- **THEN** Agent SHALL collect all supported metrics using /proc filesystem or equivalent APIs

#### Scenario: Collect metrics on macOS
- **WHEN** Agent runs on a macOS system
- **THEN** Agent SHALL collect all supported metrics using sysctl or equivalent APIs
