## ADDED Requirements

### Requirement: Certificates page SHALL display domain list with management
The certificates page at `/certificates` SHALL display all monitored domains from `GET /api/v1/certs/domains` with CRUD operations.

#### Scenario: Domain list display
- **WHEN** user navigates to `/certificates`
- **THEN** the page SHALL display a table with columns: Domain, Port, Enabled (toggle), Check Interval, Note, Last Checked, and action buttons (Edit, Check Now, Delete)

#### Scenario: Add domain
- **WHEN** user clicks "添加域名" and fills in domain, port, and note
- **THEN** the frontend SHALL call `POST /api/v1/certs/domains` and refresh the domain list

#### Scenario: Batch add domains
- **WHEN** user clicks "批量添加" and enters multiple domains (one per line)
- **THEN** the frontend SHALL call `POST /api/v1/certs/domains/batch` with the parsed domain list

#### Scenario: Edit domain
- **WHEN** user clicks the edit button for a domain
- **THEN** the frontend SHALL open an edit modal with current values, and upon save call `PUT /api/v1/certs/domains/:id`

#### Scenario: Delete domain
- **WHEN** user clicks delete for a domain
- **THEN** the frontend SHALL show a confirmation dialog, and upon confirmation call `DELETE /api/v1/certs/domains/:id`

#### Scenario: Manual check single domain
- **WHEN** user clicks "立即检测" for a domain
- **THEN** the frontend SHALL call `POST /api/v1/certs/domains/:id/check` and display the result

#### Scenario: Manual check all domains
- **WHEN** user clicks "全部检测"
- **THEN** the frontend SHALL call `POST /api/v1/certs/check` and refresh the status view

### Requirement: Certificates page SHALL show certificate status overview
The certificates page SHALL provide a "证书状态" tab showing the latest check results from `GET /api/v1/certs/status`.

#### Scenario: Certificate status list
- **WHEN** user clicks the "证书状态" tab
- **THEN** the page SHALL display each domain with: Domain, Valid (green checkmark or red cross), Issuer, Days Until Expiry (color-coded: green >30d, yellow 7-30d, red <7d), Last Checked

### Requirement: Certificate detail page SHALL show full certificate information
The certificate detail view SHALL display comprehensive certificate information from `GET /api/v1/certificates/:id`.

#### Scenario: Certificate detail display
- **WHEN** user clicks a domain to view details
- **THEN** the page SHALL display: Domain, Not Before, Not After, Days Until Expiry, Issuer (CN + Organization), Subject Alternative Names list, IP Addresses, Chain Valid status

#### Scenario: Certificate chain view
- **WHEN** user clicks "查看证书链"
- **THEN** the frontend SHALL call `GET /api/v1/certificates/:id/chain` and display chain validation status, chain error message (if any)

### Requirement: Certificates page SHALL support filtering
The certificates page SHALL support filtering by expiry, issuer, and search.

#### Scenario: Filter by expiring soon
- **WHEN** user selects "30 天内过期"
- **THEN** the frontend SHALL call `GET /api/v1/certificates?expiring_within_days=30`

#### Scenario: Search by domain
- **WHEN** user enters text in the search box
- **THEN** the frontend SHALL call `GET /api/v1/certs/domains?search=<text>` and filter the domain list
