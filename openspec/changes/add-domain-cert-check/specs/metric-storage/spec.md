## ADDED Requirements

### Requirement: Storage SHALL maintain a cert_domains table
The storage engine SHALL provide a dedicated SQLite database (cert.db) with a cert_domains table for persisting monitored domain configuration.

#### Scenario: Create cert.db on startup
- **WHEN** the Server starts and cert.db does not exist in data_dir
- **THEN** the storage engine SHALL create cert.db and initialize the cert_domains and cert_check_results tables with appropriate schema and indexes

#### Scenario: cert_domains schema
- **WHEN** cert.db is initialized
- **THEN** the cert_domains table SHALL contain columns: id (TEXT PK), domain (TEXT UNIQUE NOT NULL), port (INTEGER DEFAULT 443), enabled (INTEGER DEFAULT 1), check_interval_secs (INTEGER NULL), note (TEXT), last_checked_at (INTEGER NULL), created_at (INTEGER NOT NULL), updated_at (INTEGER NOT NULL)

#### Scenario: cert_check_results schema
- **WHEN** cert.db is initialized
- **THEN** the cert_check_results table SHALL contain columns: id (TEXT PK), domain_id (TEXT FK), domain (TEXT), is_valid (INTEGER), chain_valid (INTEGER), not_before (INTEGER), not_after (INTEGER), days_until_expiry (INTEGER), issuer (TEXT), subject (TEXT), san_list (TEXT), error (TEXT), checked_at (INTEGER NOT NULL)

### Requirement: Storage SHALL support CRUD operations for cert_domains
The storage engine SHALL provide methods to create, read, update, and delete domain records.

#### Scenario: Insert domain
- **WHEN** a new domain record is inserted
- **THEN** the storage engine SHALL generate a UUID for id, set created_at and updated_at to the current timestamp, and persist the record

#### Scenario: Query all domains
- **WHEN** all domains are queried with optional filters (enabled, search, limit, offset)
- **THEN** the storage engine SHALL return matching domain records ordered by created_at descending

#### Scenario: Query enabled domains due for check
- **WHEN** the scheduler queries domains due for checking with a given default_interval_secs
- **THEN** the storage engine SHALL return all domains where enabled=true AND (last_checked_at IS NULL OR current_time - last_checked_at >= effective_interval), where effective_interval is check_interval_secs if set, otherwise default_interval_secs

#### Scenario: Update domain
- **WHEN** a domain record is updated
- **THEN** the storage engine SHALL update only the provided fields and set updated_at to the current timestamp

#### Scenario: Delete domain and its results
- **WHEN** a domain record is deleted
- **THEN** the storage engine SHALL remove the domain record and all associated cert_check_results rows

### Requirement: Storage SHALL support cert_check_results operations
The storage engine SHALL provide methods to write and query certificate check results.

#### Scenario: Insert check result
- **WHEN** a check result is written
- **THEN** the storage engine SHALL insert the record into cert_check_results with a generated UUID

#### Scenario: Query latest result per domain
- **WHEN** the latest check results are queried
- **THEN** the storage engine SHALL return the most recent cert_check_results row for each domain, joined with cert_domains for domain metadata

#### Scenario: Query result by domain
- **WHEN** a check result is queried for a specific domain name
- **THEN** the storage engine SHALL return the most recent cert_check_results row matching that domain
