## ADDED Requirements

### Requirement: API router SHALL include certificate domain management routes
The REST API router SHALL register routes for certificate domain CRUD and status queries.

#### Scenario: Register cert domain routes
- **WHEN** the Server starts and initializes the axum router
- **THEN** the router SHALL include routes for POST/GET /v1/certs/domains, GET/PUT/DELETE /v1/certs/domains/:id, POST /v1/certs/domains/batch, GET /v1/certs/status, and GET /v1/certs/status/:domain

#### Scenario: Cert routes share AppState
- **WHEN** cert domain API handlers execute
- **THEN** they SHALL access the shared AppState containing the cert storage instance
