# Detailed Certificate Information Specification

## ADDED Requirements

### Requirement: Comprehensive certificate data collection

The certificate monitoring system SHALL collect and store detailed certificate information including expiration time, IP addresses, issuer details, subject alternative names (SANs), and certificate chain validation status.

#### Scenario: Collect certificate expiration information
- **WHEN** the system monitors a domain's certificate
- **THEN** it SHALL retrieve and store the certificate's not-before and not-after timestamps with timezone information

#### Scenario: Collect certificate IP addresses
- **WHEN** the system monitors a domain
- **THEN** it SHALL resolve and store all IP addresses (IPv4 and IPv6) associated with the domain

#### Scenario: Collect certificate issuer details
- **WHEN** the system retrieves a certificate
- **THEN** it SHALL extract and store the issuer's common name (CN), organization (O), organizational unit (OU), and country (C)

#### Scenario: Collect subject alternative names
- **WHEN** the system retrieves a certificate
- **THEN** it SHALL extract and store all subject alternative names (SANs) including DNS names and IP addresses

#### Scenario: Validate certificate chain
- **WHEN** the system retrieves a certificate
- **THEN** it SHALL validate the complete certificate chain and store the validation result (valid/invalid) and any error messages

### Requirement: Certificate storage schema extension

The system SHALL extend the certificate storage schema to persist all collected certificate metadata in a queryable format.

#### Scenario: Store certificate with all details
- **WHEN** certificate information is collected
- **THEN** the system stores domain, expiration dates, IP addresses (as JSON array), issuer details, SANs (as JSON array), chain validation status, and collection timestamp

#### Scenario: Query certificates by expiration
- **WHEN** an administrator queries certificates expiring within a time range
- **THEN** the system returns all certificates with not-after dates within that range

#### Scenario: Query certificates by IP address
- **WHEN** an administrator queries certificates by IP address
- **THEN** the system returns all certificates associated with that IP address

### Requirement: Certificate detail API endpoints

The system SHALL provide REST API endpoints to retrieve detailed certificate information for monitoring and troubleshooting.

#### Scenario: Get certificate details by domain
- **WHEN** a user sends GET request to `/v1/certificates/{domain}`
- **THEN** the system returns the complete certificate details including expiration, IPs, issuer, SANs, and chain validation status

#### Scenario: List certificates with filters
- **WHEN** a user sends GET request to `/v1/certificates` with optional filters (expiring_within, ip_address, issuer)
- **THEN** the system returns a paginated list of certificates matching the filters

#### Scenario: Get certificate chain validation details
- **WHEN** a user sends GET request to `/v1/certificates/{domain}/chain`
- **THEN** the system returns the complete certificate chain with validation status for each certificate in the chain

### Requirement: Scheduled certificate detail updates

The certificate monitoring scheduler SHALL periodically update certificate details to ensure information remains current.

#### Scenario: Periodic certificate refresh
- **WHEN** the scheduler runs its periodic check
- **THEN** it SHALL re-collect certificate details for all monitored domains and update the database

#### Scenario: Detect certificate changes
- **WHEN** a certificate's details change (e.g., renewal, IP change)
- **THEN** the system SHALL detect the change and update the stored information with a new timestamp

#### Scenario: Handle certificate retrieval failures
- **WHEN** the system fails to retrieve certificate details for a domain
- **THEN** it SHALL log the error, store the failure status, and retry on the next scheduled run

### Requirement: Certificate expiration alerting

The system SHALL generate alerts when certificates are approaching expiration based on configurable thresholds.

#### Scenario: Alert on approaching expiration
- **WHEN** a certificate's expiration date is within the configured warning threshold (e.g., 30 days)
- **THEN** the system SHALL trigger an alert with certificate details including domain, expiration date, and days remaining

#### Scenario: Alert on expired certificate
- **WHEN** a certificate has passed its not-after date
- **THEN** the system SHALL trigger a critical alert with certificate details

#### Scenario: Alert includes certificate details
- **WHEN** a certificate expiration alert is triggered
- **THEN** the alert message SHALL include domain, expiration date, issuer, and IP addresses for troubleshooting
