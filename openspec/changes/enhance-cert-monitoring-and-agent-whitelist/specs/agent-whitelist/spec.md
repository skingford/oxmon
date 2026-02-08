# Agent Whitelist Specification

## ADDED Requirements

### Requirement: Agent authentication on metric ingestion

The server SHALL validate agent identity before accepting any metric data through the gRPC `ReportMetrics` endpoint. Each agent MUST include a valid authentication token in the gRPC metadata.

#### Scenario: Valid agent submits metrics
- **WHEN** an agent with a valid token in the whitelist sends metrics via gRPC
- **THEN** the server accepts the metrics and stores them in the database

#### Scenario: Unauthorized agent attempts to submit metrics
- **WHEN** an agent without a valid token or with an invalid token sends metrics
- **THEN** the server rejects the request with UNAUTHENTICATED status and logs the attempt

#### Scenario: Agent token is missing
- **WHEN** an agent sends metrics without including an authentication token in metadata
- **THEN** the server rejects the request with UNAUTHENTICATED status

### Requirement: Whitelist management API

The server SHALL provide REST API endpoints to manage the agent whitelist, allowing administrators to add, list, and remove authorized agents.

#### Scenario: Add agent to whitelist
- **WHEN** an administrator sends POST request to `/api/v1/agents/whitelist` with agent_id and optional description
- **THEN** the system generates a unique authentication token, stores the agent entry, and returns the token

#### Scenario: List all whitelisted agents
- **WHEN** an administrator sends GET request to `/api/v1/agents/whitelist`
- **THEN** the system returns a list of all whitelisted agents with their agent_id, creation time, and description (tokens SHALL NOT be included in the response)

#### Scenario: Remove agent from whitelist
- **WHEN** an administrator sends DELETE request to `/api/v1/agents/whitelist/{agent_id}`
- **THEN** the system removes the agent from the whitelist and invalidates its token

#### Scenario: Attempt to add duplicate agent_id
- **WHEN** an administrator attempts to add an agent_id that already exists in the whitelist
- **THEN** the system returns a 409 Conflict error with a descriptive message

### Requirement: Token generation and storage

The system SHALL generate cryptographically secure tokens for each whitelisted agent and store them securely in the database.

#### Scenario: Token generation
- **WHEN** a new agent is added to the whitelist
- **THEN** the system generates a random token of at least 32 bytes (256 bits) using a cryptographically secure random number generator

#### Scenario: Token storage
- **WHEN** an agent token is stored in the database
- **THEN** the token SHALL be hashed using a secure one-way hash function before storage

#### Scenario: Token validation
- **WHEN** an agent presents a token for authentication
- **THEN** the system hashes the provided token and compares it with stored hashes to validate authenticity

### Requirement: Agent identification in metrics

The system SHALL associate all ingested metrics with the authenticated agent's identity for traceability and auditing.

#### Scenario: Metrics tagged with agent identity
- **WHEN** metrics are successfully ingested from an authenticated agent
- **THEN** the system records the agent_id alongside the metric data for audit purposes

#### Scenario: Query metrics by agent
- **WHEN** an administrator queries metrics filtered by agent_id
- **THEN** the system returns only metrics submitted by that specific agent
