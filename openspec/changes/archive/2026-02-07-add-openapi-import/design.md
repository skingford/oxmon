## Context

oxmon-server exposes 16 REST API endpoints across two modules (`api.rs` with 6 endpoints, `cert/api.rs` with 10 endpoints). These endpoints currently have no machine-readable documentation. Users of Apifox, Postman, Swagger UI etc. must manually create endpoint definitions, which is error-prone and hard to keep in sync.

The project uses axum 0.7 for HTTP routing, serde/serde_json for serialization, and all request/response types are already defined as Rust structs with `Serialize`/`Deserialize`.

## Goals / Non-Goals

**Goals:**
- Serve a complete OpenAPI 3.0.3 spec covering all 16 REST API endpoints
- Support both JSON and YAML output formats for tool compatibility
- Zero runtime overhead — the spec is a static document
- Easy to maintain as new endpoints are added

**Non-Goals:**
- Auto-generation from Rust types via proc macros (e.g., utoipa) — adds complexity and heavy compile-time deps for a relatively small API surface
- Swagger UI hosting — users can paste the spec URL into Apifox/Swagger UI themselves
- API versioning changes — the existing `/api/v1/` prefix remains unchanged

## Decisions

### 1. Hand-written OpenAPI spec as embedded JSON

**Decision**: Define the OpenAPI spec as a static `serde_json::Value` built at startup, rather than using code-generation libraries like `utoipa` or `paperclip`.

**Rationale**: The API surface is 16 endpoints with straightforward request/response types. A proc-macro approach (utoipa) would require annotating every handler, struct, and field across multiple modules — adding significant boilerplate for a small API. A hand-written spec in a single file is easier to review, diff, and maintain.

**Alternatives considered**:
- `utoipa` — powerful but adds ~10 proc-macro annotations per endpoint, increases compile time, and couples spec generation to handler code
- External YAML file loaded at runtime — adds file I/O at startup and deployment concern; embedding is simpler

### 2. Single module `openapi.rs` with `serde_json::json!` macro

**Decision**: Build the entire OpenAPI document using `serde_json::json!` in a dedicated `openapi.rs` module. Construct once via `lazy_static` or `std::sync::OnceLock`, serve from two GET handlers.

**Rationale**: `serde_json::json!` provides a clean, readable way to define the spec inline. Using `OnceLock` (stable since Rust 1.70) avoids external deps. The JSON value is constructed once on first request and reused.

### 3. YAML via `serde_yaml` crate

**Decision**: Add `serde_yaml` dependency for the YAML endpoint. Serialize the same `serde_json::Value` to YAML.

**Rationale**: Apifox and other tools accept both JSON and YAML. `serde_yaml` is lightweight (~30KB) and the only new dependency needed.

**Alternatives considered**:
- YAML-only via string template — fragile and hard to maintain
- JSON-only — some tools prefer YAML; supporting both is trivial with serde

### 4. Route placement

**Decision**: Mount at `/api/v1/openapi.json` and `/api/v1/openapi.yaml`, integrated into the existing axum router in `main.rs`.

**Rationale**: Follows the existing `/api/v1/` convention. The `.json`/`.yaml` suffix is a common pattern for OpenAPI spec endpoints (used by FastAPI, Spring, etc.).

## Risks / Trade-offs

- **Spec drift**: Hand-written spec can become stale when endpoints change → Mitigation: add a comment header in `openapi.rs` listing all covered endpoints; PR reviewers should check spec updates when API changes
- **Large single file**: The OpenAPI JSON will be ~400-500 lines → Acceptable for 16 endpoints; still far less code than annotating every handler with proc macros
- **New dependency** (`serde_yaml`): Adds a small compile-time and binary-size cost → Negligible; `serde_yaml` is widely used and well-maintained
