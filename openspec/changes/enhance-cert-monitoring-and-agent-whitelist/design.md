# Design Document: Enhanced Certificate Monitoring and Agent Whitelist

## Context

The oxmon monitoring system currently has two security and operational gaps:

1. **Certificate monitoring lacks detail**: The existing certificate monitoring only checks basic validity, without collecting comprehensive information like expiration dates, IP addresses, issuer details, SANs, or chain validation status. This makes proactive certificate management and troubleshooting difficult.

2. **No agent authentication**: The gRPC `ReportMetrics` endpoint accepts data from any client, creating a security vulnerability where unauthorized third parties could pollute monitoring data or overload the system.

**Current Architecture:**
- Agent-server model with gRPC for metric ingestion
- SQLite storage with time-partitioned tables
- Certificate monitoring scheduler in `oxmon-server/src/cert`
- No authentication layer on gRPC endpoints

**Constraints:**
- Must maintain backward compatibility with existing metric collection
- No OpenSSL dependency (use rustls only)
- SQLite storage (no external database)
- Minimal performance impact on metric ingestion

## Goals / Non-Goals

**Goals:**
- Implement agent whitelist authentication for gRPC metric ingestion
- Collect and store comprehensive certificate details (expiration, IPs, issuer, SANs, chain validation)
- Provide REST API for whitelist management
- Enable certificate expiration alerting with detailed context
- Maintain audit trail of which agent submitted which metrics

**Non-Goals:**
- Mutual TLS authentication (token-based auth is sufficient)
- Certificate auto-renewal or ACME protocol integration
- Real-time certificate change notifications (scheduled polling is sufficient)
- Agent-to-agent communication or distributed whitelist
- Web UI for whitelist management (API only)

## Decisions

### Decision 1: Token-based authentication over mTLS

**Choice**: Use bearer tokens in gRPC metadata for agent authentication

**Rationale**:
- Simpler deployment: no need to manage client certificates
- Easier token rotation and revocation
- Lower operational complexity for users
- Sufficient security for internal monitoring infrastructure

**Alternatives considered**:
- mTLS: More complex certificate management, overkill for this use case
- API keys in config: Less secure, harder to rotate
- No auth: Current state, unacceptable security posture

**Implementation**:
- Agents include token in gRPC metadata: `authorization: Bearer <token>`
- Server validates token on every `ReportMetrics` call
- Tokens stored as bcrypt hashes in SQLite

### Decision 2: SQLite schema for whitelist and certificate details

**Choice**: Add two new tables: `agent_whitelist` and `certificate_details`

**Schema**:
```sql
CREATE TABLE agent_whitelist (
    agent_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    description TEXT
);

CREATE TABLE certificate_details (
    domain TEXT PRIMARY KEY,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    ip_addresses TEXT NOT NULL,  -- JSON array
    issuer_cn TEXT,
    issuer_o TEXT,
    issuer_ou TEXT,
    issuer_c TEXT,
    subject_alt_names TEXT,  -- JSON array
    chain_valid INTEGER NOT NULL,  -- 0 or 1
    chain_error TEXT,
    last_checked INTEGER NOT NULL
);
```

**Rationale**:
- Keeps all data in SQLite (no new dependencies)
- JSON arrays for IPs and SANs (simple, queryable with json_extract)
- Separate table for cert details (not time-partitioned, always latest state)

**Alternatives considered**:
- Embedded database like sled: Adds dependency, SQLite is sufficient
- Time-partitioned cert storage: Unnecessary, we only need current state
- Separate database: Overcomplicates deployment

### Decision 3: gRPC interceptor for authentication

**Choice**: Implement a tonic interceptor that validates tokens before reaching the handler

**Rationale**:
- Clean separation of concerns
- Reusable for future gRPC endpoints
- Fails fast before processing metrics
- Standard pattern in tonic/gRPC

**Implementation**:
```rust
// In oxmon-server/src/grpc/auth.rs
pub struct AuthInterceptor {
    storage: Arc<dyn StorageEngine>,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        // Extract token from metadata
        // Validate against whitelist
        // Inject agent_id into request extensions
    }
}
```

### Decision 4: Certificate detail collection using rustls and trust-dns

**Choice**: Use `rustls` for TLS connection and `trust-dns-resolver` for DNS resolution

**Rationale**:
- Already using rustls (no OpenSSL constraint)
- trust-dns provides async DNS resolution with IPv4/IPv6 support
- Can extract full certificate chain and validation status

**Implementation flow**:
1. Resolve domain to IPs using trust-dns
2. Connect to each IP with rustls
3. Extract certificate from TLS handshake
4. Parse certificate details (x509-parser crate)
5. Validate chain using rustls verifier
6. Store all details in certificate_details table

**Alternatives considered**:
- OpenSSL: Violates project constraint
- reqwest with certificate inspection: Less control over chain validation
- External service: Adds dependency and latency

### Decision 5: REST API for whitelist management

**Choice**: Add endpoints under `/v1/agents/whitelist` using existing axum router

**Endpoints**:
- `POST /v1/agents/whitelist` - Add agent (returns token)
- `GET /v1/agents/whitelist` - List agents (no tokens)
- `DELETE /v1/agents/whitelist/{agent_id}` - Remove agent

**Rationale**:
- Consistent with existing API structure
- Simple CRUD operations
- No authentication on API (assumes internal network, can add later)

**Security consideration**: Token is only returned once on creation. Admins must save it securely.

### Decision 6: Certificate expiration alerting integration

**Choice**: Integrate with existing alert system using threshold rules

**Implementation**:
- Add new alert rule type: `CertificateExpirationRule`
- Scheduler checks cert expiration on each run
- Triggers alerts through existing notification system
- Alert payload includes full cert details (domain, expiration, issuer, IPs)

**Rationale**:
- Reuses existing alert infrastructure
- Consistent with other monitoring alerts
- Leverages existing notification channels

## Risks / Trade-offs

### Risk: Token compromise
**Mitigation**:
- Store tokens as bcrypt hashes (one-way)
- Provide easy token rotation via API
- Log all authentication failures for audit

### Risk: Certificate collection failures
**Mitigation**:
- Retry logic with exponential backoff
- Store failure status in database
- Alert on persistent failures
- Timeout on TLS connections (5s default)

### Risk: Performance impact of authentication
**Mitigation**:
- Hash comparison is fast (bcrypt with low cost factor)
- Consider in-memory token cache if needed (future optimization)
- Benchmark: <1ms overhead per request expected

### Trade-off: JSON arrays in SQLite
**Limitation**: Querying IPs/SANs requires json_extract, less efficient than normalized tables

**Justification**: Simplicity outweighs performance concern for certificate data (low volume, infrequent queries)

### Risk: Agent config migration
**Impact**: Existing agents need config update to include token

**Mitigation**:
- Backward compatibility: make auth optional initially (config flag)
- Clear migration guide in documentation
- Graceful degradation: log warning if no token provided

## Migration Plan

### Phase 1: Database schema (non-breaking)
1. Add `agent_whitelist` table via migration
2. Add `certificate_details` table via migration
3. Deploy server with new tables (no behavior change yet)

### Phase 2: Certificate detail collection
1. Update certificate monitoring scheduler
2. Add certificate detail API endpoints
3. Deploy and verify cert data collection
4. No agent changes needed

### Phase 3: Agent authentication (breaking)
1. Add whitelist management API
2. Implement gRPC auth interceptor
3. Add config flag: `require_agent_auth` (default: false)
4. Deploy server with auth disabled
5. Populate whitelist via API
6. Update agent configs with tokens
7. Enable `require_agent_auth` flag
8. Monitor for auth failures

### Rollback strategy
- Phase 2: Disable cert scheduler if issues arise
- Phase 3: Set `require_agent_auth=false` to disable auth
- Database migrations are additive (safe to keep tables)

## Open Questions

1. **Token rotation policy**: Should tokens expire? Auto-rotation?
   - **Decision needed**: Start with no expiration, add if needed

2. **Rate limiting**: Should we rate-limit metric ingestion per agent?
   - **Decision**: Out of scope for this change, can add later

3. **Certificate monitoring frequency**: How often to refresh cert details?
   - **Proposal**: Use existing scheduler interval (configurable, default 1 hour)

4. **Multi-IP certificate handling**: If domain resolves to multiple IPs with different certs?
   - **Decision**: Store all IPs, validate cert against each, store first successful result
