## ADDED Requirements

### Requirement: Cert checker SHALL connect to domains via TLS and extract certificate info
The cert checker SHALL establish a TLS connection to each monitored domain and parse the presented certificate.

#### Scenario: Successful certificate extraction
- **WHEN** the cert checker connects to a domain with a valid TLS certificate
- **THEN** it SHALL extract and record: issuer, subject, SAN list, not_before, not_after, days_until_expiry, is_valid=true, chain_valid=true

#### Scenario: Expired certificate
- **WHEN** the cert checker connects to a domain whose certificate has passed its not_after date
- **THEN** it SHALL record is_valid=false, days_until_expiry as a negative number, and include the expiry details

#### Scenario: Invalid certificate chain
- **WHEN** the TLS handshake fails due to an untrusted or incomplete certificate chain
- **THEN** it SHALL record chain_valid=false with the error description, and still attempt to extract certificate details if possible

#### Scenario: Custom port
- **WHEN** a domain is configured with a non-default port (e.g., 8443)
- **THEN** the cert checker SHALL connect to that specific port instead of 443

#### Scenario: Connection timeout
- **WHEN** the target domain is unreachable within connect_timeout_secs (default 10s)
- **THEN** it SHALL record the check as failed with an error message describing the timeout, and proceed to the next domain

#### Scenario: DNS resolution failure
- **WHEN** the domain name cannot be resolved
- **THEN** it SHALL record the check as failed with an error message describing the DNS failure

### Requirement: Cert checker SHALL run on a configurable schedule
The cert checker SHALL periodically check all enabled domains based on their configured intervals.

#### Scenario: Global default interval
- **WHEN** a domain has check_interval_secs=null
- **THEN** the cert checker SHALL use the global default_interval_secs from server.toml (default 86400 seconds / 24 hours)

#### Scenario: Per-domain custom interval
- **WHEN** a domain has check_interval_secs=3600
- **THEN** the cert checker SHALL check that domain every 3600 seconds, independent of the global default

#### Scenario: Scheduler tick evaluates domain readiness
- **WHEN** the scheduler tick fires (every tick_secs, default 60s)
- **THEN** it SHALL iterate all enabled domains and check each domain whose elapsed time since last_checked_at exceeds its effective interval

#### Scenario: Newly added domain checked promptly
- **WHEN** a new domain is added via API with last_checked_at=null
- **THEN** the cert checker SHALL check it on the next scheduler tick

#### Scenario: Disabled domain skipped
- **WHEN** a domain has enabled=false
- **THEN** the cert checker SHALL skip it during scheduling

### Requirement: Cert checker SHALL control concurrency
The cert checker SHALL limit the number of concurrent TLS connections to prevent resource exhaustion.

#### Scenario: Concurrent connection limit
- **WHEN** multiple domains are due for checking in the same tick
- **THEN** the cert checker SHALL limit concurrent TLS connections to max_concurrent (default 10) using a semaphore

#### Scenario: Remaining domains queued
- **WHEN** more domains are due than max_concurrent allows
- **THEN** the cert checker SHALL process them in batches, waiting for a permit before starting each new connection

### Requirement: Cert checker SHALL write results to storage
The cert checker SHALL persist check results and emit standard metrics for the alert engine.

#### Scenario: Write detailed result to cert_check_results
- **WHEN** a certificate check completes (success or failure)
- **THEN** the cert checker SHALL insert a record into cert_check_results with all extracted fields (domain, is_valid, chain_valid, not_before, not_after, days_until_expiry, issuer, subject, san_list, error, checked_at)

#### Scenario: Emit certificate.days_until_expiry metric
- **WHEN** a certificate check successfully extracts expiry information
- **THEN** the cert checker SHALL write a MetricDataPoint with metric_name="certificate.days_until_expiry", value=days remaining, and label domain=<domain> to the partitioned metric storage

#### Scenario: Emit certificate.is_valid metric
- **WHEN** a certificate check completes
- **THEN** the cert checker SHALL write a MetricDataPoint with metric_name="certificate.is_valid", value=1.0 (valid) or 0.0 (invalid/expired/error), and label domain=<domain>

#### Scenario: Update domain last_checked_at
- **WHEN** a certificate check completes for a domain
- **THEN** the cert checker SHALL update cert_domains.last_checked_at to the current timestamp

### Requirement: Cert checker SHALL be configurable via server.toml
The cert checker SHALL read its configuration from a `[cert_check]` section in server.toml.

#### Scenario: Default configuration
- **WHEN** server.toml does not contain a `[cert_check]` section
- **THEN** the cert checker SHALL use defaults: enabled=true, default_interval_secs=86400, tick_secs=60, connect_timeout_secs=10, max_concurrent=10

#### Scenario: Disabled cert checker
- **WHEN** server.toml contains `[cert_check]` with `enabled = false`
- **THEN** the Server SHALL not start the cert checker scheduler task
