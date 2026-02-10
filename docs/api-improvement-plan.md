# API Improvement Plan

This document tracks hardening and consistency improvements for oxmon HTTP APIs.

## Scope

- Standardized response envelope (`err_code`, `err_msg`, `trace_id`, `data`)
- Custom integer error codes (`0` success, non-zero failure)
- List endpoint pagination/sort consistency (`limit`, `offset`)
- Sensitive field governance for list/detail responses
- Coverage guard to ensure new endpoints get tests

## Sensitive Data Governance

### Rules

1. **List endpoints MUST NOT return secrets** (tokens, password hashes, private keys, credentials).
2. Detail endpoints should only return sensitive values when explicitly required by business flow.
3. One-time secrets (e.g., newly generated tokens) should be returned only on creation/rotation endpoints.

### Applied Changes

- `GET /v1/agents/whitelist`: token is always `null` in list response.
- `POST /v1/agents/whitelist`: returns token once (creation flow).
- `POST /v1/agents/whitelist/{id}/token`: returns new token once (rotation flow).

### Follow-up Hardening Checklist

- [ ] Review every `Vec<...>` response schema for secret-bearing fields.
- [ ] Add lint-like test assertions for known sensitive keys (`token`, `password_hash`, etc.) in list payloads.
- [ ] Document redaction behavior in API reference per endpoint.

## Error Code Policy

- `err_code = 0`: success
- `err_code != 0`: custom business error code
- HTTP status and `err_code` are both meaningful:
  - HTTP status: transport/protocol category
  - `err_code`: stable business semantics for clients

## Testing Policy

## 1. Endpoint Matrix

Each endpoint must include tests for:

- success path
- unauthorized/auth failure (when protected)
- parameter validation failure (where applicable)
- business branch errors (404/409/etc.)

## 2. Real Agent Reporting Chain

Integration tests must validate:

- gRPC metadata auth (`authorization`, `agent-id`)
- payload/metadata identity mismatch rejection
- successful report persistence and REST query visibility

## 3. Contract Guard

OpenAPI-based guard should fail test runs if any newly exposed endpoint is missing in the coverage matrix.

