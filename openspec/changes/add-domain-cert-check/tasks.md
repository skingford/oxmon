## 1. Dependencies and Configuration

- [x] 1.1 Add `tokio-rustls`, `rustls`, `webpki-roots`, `x509-parser`, `uuid` dependencies to workspace Cargo.toml
- [x] 1.2 Add `[cert_check]` config section to `ServerConfig` in `oxmon-server/src/config.rs` (enabled, default_interval_secs, tick_secs, connect_timeout_secs, max_concurrent) with defaults
- [x] 1.3 Add `[cert_check]` example section to `config/server.example.toml`

## 2. Storage Layer (oxmon-storage)

- [x] 2.1 Create `oxmon-storage/src/cert_store.rs` with `CertStore` struct managing cert.db SQLite connection
- [x] 2.2 Implement cert.db initialization: create `cert_domains` table (id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, updated_at) with UNIQUE index on domain
- [x] 2.3 Implement cert.db initialization: create `cert_check_results` table (id, domain_id, domain, is_valid, chain_valid, not_before, not_after, days_until_expiry, issuer, subject, san_list, error, checked_at) with indexes
- [x] 2.4 Implement `CertStore` CRUD methods for cert_domains: insert_domain, insert_domains_batch, query_domains (with enabled/search/limit/offset filters), get_domain_by_id, update_domain, delete_domain
- [x] 2.5 Implement `CertStore` method: query_domains_due_for_check(default_interval_secs) — returns enabled domains where last_checked_at is null or elapsed time exceeds effective interval
- [x] 2.6 Implement `CertStore` methods for cert_check_results: insert_check_result, query_latest_results, query_result_by_domain
- [x] 2.7 Implement `CertStore` method: update_last_checked_at(domain_id, timestamp)
- [x] 2.8 Export `CertStore` from `oxmon-storage/src/lib.rs`

## 3. Common Types (oxmon-common)

- [x] 3.1 Add `CertDomain` struct (id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, updated_at) with Serialize/Deserialize
- [x] 3.2 Add `CertCheckResult` struct (id, domain_id, domain, is_valid, chain_valid, not_before, not_after, days_until_expiry, issuer, subject, san_list, error, checked_at) with Serialize/Deserialize
- [x] 3.3 Add API request/response types: `CreateDomainRequest`, `UpdateDomainRequest`, `BatchCreateDomainsRequest`

## 4. Certificate Checker (oxmon-server/src/cert/)

- [x] 4.1 Create `oxmon-server/src/cert/mod.rs` module structure (mod checker, scheduler, api)
- [x] 4.2 Implement `checker.rs`: async fn `check_certificate(domain, port, timeout)` — TLS connect via tokio-rustls, extract certificate with x509-parser, return CertCheckResult
- [x] 4.3 Handle checker edge cases: connection timeout, DNS failure, expired cert, invalid chain — all recorded as CertCheckResult with error field
- [x] 4.4 Implement `scheduler.rs`: `CertCheckScheduler` struct with `run()` method — tick loop, query due domains, check with Semaphore concurrency limit, write results to CertStore, emit MetricDataPoints to StorageEngine
- [x] 4.5 Emit `certificate.days_until_expiry` and `certificate.is_valid` MetricDataPoints with domain label after each check

## 5. REST API (oxmon-server/src/cert/api.rs)

- [x] 5.1 Implement POST `/v1/certs/domains` handler — create single domain
- [x] 5.2 Implement POST `/v1/certs/domains/batch` handler — batch create domains
- [x] 5.3 Implement GET `/v1/certs/domains` handler — list domains with enabled/search/limit/offset query params
- [x] 5.4 Implement GET `/v1/certs/domains/:id` handler — get single domain
- [x] 5.5 Implement PUT `/v1/certs/domains/:id` handler — update domain (port, enabled, check_interval_secs, note)
- [x] 5.6 Implement DELETE `/v1/certs/domains/:id` handler — delete domain and its check results
- [x] 5.7 Implement GET `/v1/certs/status` handler — latest check result for all enabled domains
- [x] 5.8 Implement GET `/v1/certs/status/:domain` handler — latest check result for specific domain
- [x] 5.9 Add input validation: reject empty/invalid domain, reject duplicate domain (409), validate port range
- [x] 5.10 Fix route path parameter syntax: `{id}`/`{domain}` → `:id`/`:domain` (axum 0.7 uses colon syntax, not brace syntax)

## 6. Server Integration (oxmon-server/src/main.rs)

- [x] 6.1 Add `CertStore` to `AppState` struct (Arc wrapped)
- [x] 6.2 Initialize `CertStore` in main() after storage engine init
- [x] 6.3 Register cert API routes in the axum router
- [x] 6.4 Spawn `CertCheckScheduler` task in main() (guarded by cert_check.enabled config)

## 7. Configuration and Documentation

- [x] 7.1 Add certificate alert rule examples to `config/server.example.toml` (threshold on certificate.days_until_expiry < 30 warning, < 7 critical; threshold on certificate.is_valid == 0 critical)
- [x] 7.2 Update README.md: add cert check feature description, API docs for /v1/certs/*, cert_check config section, certificate metrics to metrics table

## 8. Testing

- [x] 8.1 Unit tests for `CertStore`: CRUD operations, query_domains_due_for_check logic, delete cascading results
- [x] 8.2 Unit tests for `check_certificate`: mock or use known public domains (e.g., valid cert, expired cert scenarios)
- [x] 8.3 Unit tests for scheduler: verify tick-based scheduling logic, concurrency limit, metric emission
- [x] 8.4 Integration tests for cert API endpoints: create, list, update, delete, batch, status queries, error cases (409/404/400)
- [x] 8.5 E2E smoke test: start server with all 5 notification plugins + cert config, verify all HTTP endpoints return correct status codes and payloads, verify gRPC port listening, verify OpenAPI spec serves 15 endpoints
