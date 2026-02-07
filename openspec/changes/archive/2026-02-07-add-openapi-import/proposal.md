## Why

oxmon currently has 16 个 REST API endpoints (metrics, alerts, cert monitoring, etc.), but no machine-readable API documentation. When using API management tools like Apifox, Postman, or Swagger UI, users must manually create each endpoint definition. Adding an OpenAPI spec endpoint allows one-click import of the complete API definition, improving developer experience and team collaboration.

## What Changes

- Add a new REST endpoint that serves the complete oxmon API documentation in OpenAPI 3.0 format
- Support both JSON (`/api/v1/openapi.json`) and YAML (`/api/v1/openapi.yaml`) output formats
- The OpenAPI spec is generated at compile time from a static definition — no runtime overhead
- Covers all existing API endpoints:
  - Health & agents (GET /health, GET /agents, GET /agents/:id/latest)
  - Metrics query (GET /metrics)
  - Alert rules & history (GET /alerts/rules, GET /alerts/history)
  - Certificate domain management (CRUD /certs/domains, batch, check)
  - Certificate status (GET /certs/status)

## Capabilities

### New Capabilities
- `openapi-docs`: REST endpoints serving OpenAPI 3.0 specification in JSON and YAML formats, describing all oxmon API endpoints with request/response schemas

### Modified Capabilities

## Impact

- **New files**: `crates/oxmon-server/src/openapi.rs` — OpenAPI spec definition and route handlers
- **Modified files**: `crates/oxmon-server/src/main.rs` — register openapi routes
- **Dependencies**: `serde_yaml` for YAML output (serde_json already available)
- **No breaking changes** to existing APIs — purely additive
