## ADDED Requirements

### Requirement: API SHALL create monitored domains
The REST API SHALL provide an endpoint to add domains for certificate monitoring.

#### Scenario: Add a single domain
- **WHEN** a POST request is made to `/v1/certs/domains` with body `{"domain": "example.com"}`
- **THEN** the API SHALL create the domain record with default port 443, enabled=true, check_interval_secs=null, and return HTTP 201 with the created domain object including its generated id

#### Scenario: Add a domain with custom port and interval
- **WHEN** a POST request is made to `/v1/certs/domains` with body `{"domain": "api.example.com", "port": 8443, "check_interval_secs": 3600, "note": "API server"}`
- **THEN** the API SHALL create the domain record with port 8443, check_interval_secs=3600, and the provided note

#### Scenario: Add multiple domains in batch
- **WHEN** a POST request is made to `/v1/certs/domains/batch` with body `{"domains": [{"domain": "a.com"}, {"domain": "b.com", "port": 8443}]}`
- **THEN** the API SHALL create all domain records and return HTTP 201 with an array of created domain objects

#### Scenario: Reject duplicate domain
- **WHEN** a POST request attempts to add a domain that already exists
- **THEN** the API SHALL return HTTP 409 with an error message indicating the domain already exists

#### Scenario: Reject invalid domain format
- **WHEN** a POST request is made with an empty or invalid domain string
- **THEN** the API SHALL return HTTP 400 with a descriptive error message

### Requirement: API SHALL list monitored domains
The REST API SHALL provide an endpoint to query the monitored domain list with filtering and pagination.

#### Scenario: List all domains
- **WHEN** a GET request is made to `/v1/certs/domains`
- **THEN** the API SHALL return a JSON array of all domain records with id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, and updated_at fields

#### Scenario: Filter by enabled status
- **WHEN** a GET request is made to `/v1/certs/domains?enabled=true`
- **THEN** the API SHALL return only domains with enabled=true

#### Scenario: Paginated domain list
- **WHEN** a GET request includes `?limit=20&offset=40`
- **THEN** the API SHALL return at most 20 domains starting from the 41st result

#### Scenario: Search by domain name
- **WHEN** a GET request includes `?search=example`
- **THEN** the API SHALL return domains whose domain name contains "example"

### Requirement: API SHALL get a single domain
The REST API SHALL provide an endpoint to get a single monitored domain by id.

#### Scenario: Get existing domain
- **WHEN** a GET request is made to `/v1/certs/domains/:id` with a valid id
- **THEN** the API SHALL return the domain record with all fields

#### Scenario: Domain not found
- **WHEN** a GET request is made to `/v1/certs/domains/:id` with an unknown id
- **THEN** the API SHALL return HTTP 404 with a JSON error message

### Requirement: API SHALL update monitored domains
The REST API SHALL provide an endpoint to update domain configuration.

#### Scenario: Update port
- **WHEN** a PUT request is made to `/v1/certs/domains/:id` with body `{"port": 8443}`
- **THEN** the API SHALL update the port to 8443 and return the updated domain object

#### Scenario: Update check interval
- **WHEN** a PUT request is made to `/v1/certs/domains/:id` with body `{"check_interval_secs": 7200}`
- **THEN** the API SHALL update the check_interval_secs to 7200 and return the updated domain object

#### Scenario: Disable a domain
- **WHEN** a PUT request is made to `/v1/certs/domains/:id` with body `{"enabled": false}`
- **THEN** the API SHALL set enabled=false and the cert checker SHALL skip this domain in subsequent checks

#### Scenario: Reset interval to global default
- **WHEN** a PUT request is made to `/v1/certs/domains/:id` with body `{"check_interval_secs": null}`
- **THEN** the API SHALL clear the per-domain interval and the domain SHALL use the global default_interval_secs

### Requirement: API SHALL delete monitored domains
The REST API SHALL provide an endpoint to remove a domain from monitoring.

#### Scenario: Delete existing domain
- **WHEN** a DELETE request is made to `/v1/certs/domains/:id`
- **THEN** the API SHALL remove the domain record and its check results, and return HTTP 204

#### Scenario: Delete non-existent domain
- **WHEN** a DELETE request is made to `/v1/certs/domains/:id` with an unknown id
- **THEN** the API SHALL return HTTP 404

### Requirement: API SHALL query certificate check status
The REST API SHALL provide endpoints to query certificate check results.

#### Scenario: Get all domains' latest check status
- **WHEN** a GET request is made to `/v1/certs/status`
- **THEN** the API SHALL return a JSON array of the latest check result for each enabled domain, including domain, is_valid, chain_valid, days_until_expiry, issuer, subject, not_before, not_after, checked_at, and error fields

#### Scenario: Get single domain check status
- **WHEN** a GET request is made to `/v1/certs/status/:domain`
- **THEN** the API SHALL return the latest check result for the specified domain, including full certificate details (san_list, issuer, subject, not_before, not_after, days_until_expiry, is_valid, chain_valid)

#### Scenario: Filter status by validity
- **WHEN** a GET request includes `?valid=false`
- **THEN** the API SHALL return only domains whose latest check shows is_valid=false or days_until_expiry below a warning threshold

#### Scenario: Domain not monitored
- **WHEN** a GET request is made to `/v1/certs/status/:domain` for a domain that is not being monitored
- **THEN** the API SHALL return HTTP 404
