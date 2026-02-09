## 1. Dependencies

- [x] 1.1 Add `serde_yaml` dependency to workspace `Cargo.toml`
- [x] 1.2 Add `serde_yaml` to `crates/oxmon-server/Cargo.toml`

## 2. OpenAPI Spec Definition

- [x] 2.1 Create `crates/oxmon-server/src/openapi.rs` module with `build_openapi_spec()` function returning `serde_json::Value`
- [x] 2.2 Define OpenAPI 3.0.3 info section (title: "oxmon API", version from CARGO_PKG_VERSION)
- [x] 2.3 Define shared component schemas: ApiError, HealthResponse, AgentResponse, LatestMetric, MetricPointResponse, AlertRuleResponse, AlertEventResponse
- [x] 2.4 Define shared component schemas: CertDomain, CertCheckResult, CreateDomainRequest, UpdateDomainRequest, BatchCreateDomainsRequest
- [x] 2.5 Define paths for health and agent endpoints (GET /health, GET /agents, GET /agents/{id}/latest)
- [x] 2.6 Define paths for metrics endpoint (GET /metrics with query params: agent, metric, from, to)
- [x] 2.7 Define paths for alert endpoints (GET /alerts/rules, GET /alerts/history with query params)
- [x] 2.8 Define paths for cert domain CRUD endpoints (POST/GET /certs/domains, POST /certs/domains/batch, GET/PUT/DELETE /certs/domains/{id})
- [x] 2.9 Define paths for cert check and status endpoints (POST /certs/domains/{id}/check, POST /certs/check, GET /certs/status, GET /certs/status/{domain})
- [x] 2.10 Define paths for OpenAPI endpoints themselves (GET /openapi.json, GET /openapi.yaml)

## 3. Route Handlers

- [x] 3.1 Implement `OnceLock`-based caching for the OpenAPI spec JSON value
- [x] 3.2 Implement GET `/v1/openapi.json` handler returning cached JSON with `application/json` Content-Type
- [x] 3.3 Implement GET `/v1/openapi.yaml` handler serializing cached value to YAML with `text/yaml` Content-Type
- [x] 3.4 Export `openapi_routes() -> Router<AppState>` function

## 4. Server Integration

- [x] 4.1 Add `mod openapi;` to `main.rs`
- [x] 4.2 Merge `openapi_routes()` into the axum router in `main.rs`

## 5. Documentation

- [x] 5.1 Update README.md: add OpenAPI documentation section with endpoint URLs and Apifox import instructions
- [x] 5.2 Update `config/server.example.toml` comments if needed
