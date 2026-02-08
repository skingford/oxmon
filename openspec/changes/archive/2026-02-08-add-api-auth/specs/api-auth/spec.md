## ADDED Requirements

### Requirement: System SHALL provide a login endpoint
The system SHALL provide `POST /api/v1/auth/login` that accepts username and password, validates credentials against the `users` table, and returns a signed JWT access token upon success.

#### Scenario: Successful login with valid credentials
- **WHEN** a POST request is made to `/api/v1/auth/login` with body `{"username": "admin", "password": "changeme"}`
- **THEN** the API SHALL return HTTP 200 with a JSON body containing `token` (JWT string) and `expires_in` (seconds until expiration)

#### Scenario: Login with incorrect password
- **WHEN** a POST request is made to `/api/v1/auth/login` with a valid username but incorrect password
- **THEN** the API SHALL return HTTP 401 with a JSON error body `{"error": "invalid credentials", "code": "UNAUTHORIZED"}`

#### Scenario: Login with non-existent username
- **WHEN** a POST request is made to `/api/v1/auth/login` with a username that does not exist in the `users` table
- **THEN** the API SHALL return HTTP 401 with a JSON error body `{"error": "invalid credentials", "code": "UNAUTHORIZED"}`

#### Scenario: Login with missing fields
- **WHEN** a POST request is made to `/api/v1/auth/login` with missing `username` or `password` field
- **THEN** the API SHALL return HTTP 400 with a JSON error body describing the missing field

### Requirement: JWT token SHALL contain standard claims
The JWT token issued by the login endpoint SHALL contain `sub` (user id), `username`, `iat` (issued at), and `exp` (expiration) claims, signed with HS256 algorithm using the configured secret.

#### Scenario: Token contains required claims
- **WHEN** a valid JWT token is decoded
- **THEN** the payload SHALL contain `sub` (Snowflake ID string), `username` (string), `iat` (unix timestamp), and `exp` (unix timestamp)

#### Scenario: Token expiration matches configuration
- **WHEN** a JWT token is issued with `token_expire_secs` configured as 86400
- **THEN** the `exp` claim SHALL equal `iat` plus 86400

### Requirement: JWT middleware SHALL protect REST API endpoints
The system SHALL enforce JWT authentication on all REST API endpoints except health check (`GET /api/v1/health`), login (`POST /api/v1/auth/login`), OpenAPI spec (`GET /v1/openapi.yaml`), and Swagger UI (`/docs`).

#### Scenario: Request with valid token
- **WHEN** a request is made to a protected endpoint with header `Authorization: Bearer <valid_jwt_token>`
- **THEN** the request SHALL proceed normally and return the expected response

#### Scenario: Request without Authorization header
- **WHEN** a request is made to a protected endpoint without an `Authorization` header
- **THEN** the API SHALL return HTTP 401 with JSON body `{"error": "missing authorization header", "code": "UNAUTHORIZED"}`

#### Scenario: Request with malformed Authorization header
- **WHEN** a request is made with `Authorization: Basic abc123` or `Authorization: Bearer` (no token)
- **THEN** the API SHALL return HTTP 401 with JSON body `{"error": "invalid authorization header", "code": "UNAUTHORIZED"}`

#### Scenario: Request with expired token
- **WHEN** a request is made with a JWT token whose `exp` claim is in the past
- **THEN** the API SHALL return HTTP 401 with JSON body `{"error": "token expired", "code": "TOKEN_EXPIRED"}`

#### Scenario: Request with invalid signature
- **WHEN** a request is made with a JWT token signed by a different secret
- **THEN** the API SHALL return HTTP 401 with JSON body `{"error": "invalid token", "code": "UNAUTHORIZED"}`

#### Scenario: Health check remains public
- **WHEN** a GET request is made to `/api/v1/health` without any Authorization header
- **THEN** the API SHALL return HTTP 200 with the health status response

#### Scenario: Login endpoint remains public
- **WHEN** a POST request is made to `/api/v1/auth/login` without any Authorization header
- **THEN** the API SHALL process the login request normally

### Requirement: System SHALL store user accounts in users table
The system SHALL maintain a `users` table in cert.db with columns `id` (Snowflake ID, primary key), `username` (unique), `password_hash` (bcrypt), `created_at`, and `updated_at`.

#### Scenario: Users table created on startup
- **WHEN** the server starts and the `users` table does not exist in cert.db
- **THEN** the system SHALL create the table with the specified schema

#### Scenario: Password stored as bcrypt hash
- **WHEN** a user account is created with password "changeme"
- **THEN** the `password_hash` column SHALL contain a bcrypt hash, NOT the plaintext password

### Requirement: System SHALL create default admin on first startup
The system SHALL check the `users` table on startup and create a default administrator account if the table is empty, using credentials from the `[auth]` configuration section.

#### Scenario: First startup creates default admin
- **WHEN** the server starts with an empty `users` table and `[auth]` config has `default_username = "admin"` and `default_password = "changeme"`
- **THEN** the system SHALL create a user with username "admin" and bcrypt-hashed password for "changeme"

#### Scenario: Existing users prevent default creation
- **WHEN** the server starts and the `users` table already contains one or more users
- **THEN** the system SHALL NOT create or modify any user accounts

#### Scenario: Default admin config uses fallback values
- **WHEN** the server starts with an empty `users` table and `[auth]` config does not specify `default_username` or `default_password`
- **THEN** the system SHALL use "admin" as default username and "changeme" as default password

### Requirement: Server configuration SHALL include auth section
The `server.toml` configuration file SHALL support an `[auth]` section with `jwt_secret`, `token_expire_secs`, `default_username`, and `default_password` fields, all with sensible defaults.

#### Scenario: Full auth configuration
- **WHEN** server.toml contains `[auth]` with `jwt_secret = "my-secret"`, `token_expire_secs = 3600`, `default_username = "admin"`, `default_password = "secure123"`
- **THEN** the server SHALL use these values for JWT signing, token expiration, and default account creation

#### Scenario: Missing auth section uses defaults
- **WHEN** server.toml does not contain an `[auth]` section
- **THEN** the server SHALL use auto-generated jwt_secret, 86400 for token_expire_secs, "admin" for default_username, and "changeme" for default_password

#### Scenario: Auto-generated secret logged as warning
- **WHEN** the server starts without `jwt_secret` configured
- **THEN** the server SHALL log a warning message indicating that a random JWT secret was generated and will change on restart

### Requirement: OpenAPI spec SHALL document Bearer auth
The OpenAPI specification SHALL include a Bearer token security scheme and mark all protected endpoints with this security requirement.

#### Scenario: Security scheme in OpenAPI spec
- **WHEN** the OpenAPI spec is retrieved from `/v1/openapi.yaml`
- **THEN** the spec SHALL contain a `securitySchemes` definition with type "http", scheme "bearer", and bearerFormat "JWT"

#### Scenario: Protected endpoints marked in spec
- **WHEN** the OpenAPI spec is retrieved
- **THEN** all endpoints except `/api/v1/health` and `/api/v1/auth/login` SHALL have a security requirement referencing the Bearer auth scheme

#### Scenario: Login endpoint documented
- **WHEN** the OpenAPI spec is retrieved
- **THEN** the spec SHALL include documentation for `POST /api/v1/auth/login` with request body schema and response schema
