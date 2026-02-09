## Why

The current certificate monitoring system lacks detailed information after domain validation, making it difficult to proactively manage certificate renewals and troubleshoot issues. Additionally, the server accepts metrics from any agent without authentication, creating a security vulnerability where unauthorized third parties could pollute monitoring data or overload the system.

## What Changes

- Add detailed certificate information retrieval including expiration time, IP addresses, issuer details, subject alternative names (SANs), and certificate chain validation status
- Implement agent whitelist mechanism on the server side to authenticate and authorize agents before accepting metric data
- Extend certificate storage schema to persist detailed certificate metadata
- Add REST API endpoints to manage the agent whitelist (add, remove, list authorized agents)
- Enhance certificate monitoring scheduler to collect and store comprehensive certificate details

## Capabilities

### New Capabilities
- `agent-whitelist`: Server-side authentication and authorization system for agents, including whitelist management API and gRPC request validation
- `detailed-cert-info`: Enhanced certificate monitoring that retrieves and stores comprehensive certificate details (expiration, IP, issuer, SANs, chain validation)

### Modified Capabilities
<!-- No existing capabilities are being modified at the spec level -->

## Impact

**Affected Components:**
- `oxmon-server`: gRPC handler needs whitelist validation, new REST API endpoints for whitelist management
- `oxmon-storage`: New tables/schema for agent whitelist and extended certificate details storage
- `oxmon-agent`: May need to include agent identifier/token in gRPC requests
- `oxmon-server/src/cert`: Certificate monitoring scheduler and storage logic needs enhancement

**Database Changes:**
- New table for agent whitelist (agent_id, token/key, created_at, description)
- Extended certificate storage schema with additional fields (ip_addresses, issuer, subject_alt_names, chain_valid, etc.)

**API Changes:**
- New REST endpoints: `/v1/agents/whitelist` (GET, POST, DELETE)
- gRPC `ReportMetrics` requires authentication header/metadata
