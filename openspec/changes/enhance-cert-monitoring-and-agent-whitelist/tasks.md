# Implementation Tasks

## 1. Database Schema

- [x] 1.1 Create migration for `agent_whitelist` table with agent_id, token_hash, created_at, description fields
- [x] 1.2 Create migration for `certificate_details` table with domain, timestamps, IP addresses, issuer details, SANs, chain validation fields
- [x] 1.3 Add database migration runner to apply new schema on server startup
- [x] 1.4 Add StorageEngine trait methods for agent whitelist operations (add, get, delete, list)
- [x] 1.5 Add StorageEngine trait methods for certificate details operations (upsert, get, list with filters)

## 2. Agent Whitelist - Storage Layer

- [x] 2.1 Implement agent whitelist storage in SQLite StorageEngine (crates/oxmon-storage)
- [x] 2.2 Add bcrypt dependency for token hashing
- [x] 2.3 Implement token generation function (32-byte cryptographically secure random)
- [x] 2.4 Implement token hashing and validation functions using bcrypt
- [x] 2.5 Add unit tests for whitelist storage operations
- [x] 2.6 Add unit tests for token generation and validation

## 3. Agent Whitelist - gRPC Authentication

- [x] 3.1 Create auth interceptor module in oxmon-server/src/grpc/auth.rs
- [x] 3.2 Implement AuthInterceptor that extracts bearer token from gRPC metadata
- [x] 3.3 Implement token validation logic in interceptor using StorageEngine
- [x] 3.4 Inject authenticated agent_id into request extensions for handler access
- [x] 3.5 Add config flag `require_agent_auth` (default: false) to server config
- [x] 3.6 Wire up interceptor to gRPC server with conditional activation based on config
- [x] 3.7 Update gRPC ReportMetrics handler to log agent_id from extensions
- [x] 3.8 Add integration tests for authenticated and unauthenticated requests

## 4. Agent Whitelist - REST API

- [x] 4.1 Create whitelist API module in oxmon-server/src/api/whitelist.rs
- [x] 4.2 Implement POST /v1/agents/whitelist endpoint (add agent, return token)
- [x] 4.3 Implement GET /v1/agents/whitelist endpoint (list agents without tokens)
- [x] 4.4 Implement DELETE /v1/agents/whitelist/{agent_id} endpoint (remove agent)
- [x] 4.5 Add request/response types for whitelist API
- [x] 4.6 Add validation for duplicate agent_id (return 409 Conflict)
- [x] 4.7 Wire up whitelist routes to axum router
- [x] 4.8 Add API tests for whitelist management endpoints

## 5. Certificate Details - Collection

- [x] 5.1 Add dependencies: trust-dns-resolver, x509-parser
- [x] 5.2 Create certificate collector module in oxmon-server/src/cert/collector.rs
- [x] 5.3 Implement DNS resolution to get IPv4 and IPv6 addresses for domain
- [x] 5.4 Implement TLS connection using rustls to retrieve certificate
- [x] 5.5 Implement certificate parsing to extract expiration, issuer, SANs
- [x] 5.6 Implement certificate chain validation using rustls verifier
- [x] 5.7 Add timeout handling for TLS connections (5s default)
- [x] 5.8 Add retry logic with exponential backoff for transient failures
- [x] 5.9 Add unit tests for certificate parsing and validation

## 6. Certificate Details - Storage and Scheduler

- [x] 6.1 Implement certificate details storage in SQLite StorageEngine
- [x] 6.2 Update certificate monitoring scheduler to call new collector
- [x] 6.3 Store collected certificate details in certificate_details table
- [x] 6.4 Handle and log collection failures with error status
- [x] 6.5 Add integration tests for certificate collection and storage

## 7. Certificate Details - REST API

- [x] 7.1 Create certificate API module in oxmon-server/src/api/certificates.rs
- [x] 7.2 Implement GET /v1/certificates/{domain} endpoint (get cert details)
- [x] 7.3 Implement GET /v1/certificates endpoint with filters (expiring_within, ip_address, issuer)
- [x] 7.4 Implement GET /v1/certificates/{domain}/chain endpoint (chain validation details)
- [x] 7.5 Add request/response types for certificate API
- [x] 7.6 Add pagination support for certificate list endpoint
- [x] 7.7 Wire up certificate routes to axum router
- [x] 7.8 Add API tests for certificate endpoints

## 8. Certificate Expiration Alerting

- [x] 8.1 Create CertificateExpirationRule in oxmon-alert crate
- [x] 8.2 Implement alert rule that checks certificate expiration thresholds
- [x] 8.3 Add configurable warning threshold (default: 30 days)
- [x] 8.4 Add configurable critical threshold (default: 7 days)
- [x] 8.5 Include certificate details in alert payload (domain, expiration, issuer, IPs)
- [x] 8.6 Integrate certificate expiration rule with alert engine
- [x] 8.7 Add tests for certificate expiration alerting

## 9. Agent Configuration

- [x] 9.1 Add `auth_token` field to agent config (optional)
- [x] 9.2 Update agent gRPC client to include token in metadata if configured
- [x] 9.3 Add example agent config with auth_token placeholder
- [x] 9.4 Update agent documentation with authentication setup instructions

## 10. Documentation and Testing

- [x] 10.1 Update server config example with require_agent_auth flag
- [x] 10.2 Add migration guide for enabling agent authentication
- [x] 10.3 Add API documentation for whitelist endpoints to OpenAPI spec
- [x] 10.4 Add API documentation for certificate endpoints to OpenAPI spec
- [x] 10.5 Run full integration test suite
- [x] 10.6 Run clippy and fix any warnings
- [x] 10.7 Update CLAUDE.md if new patterns or commands are introduced
