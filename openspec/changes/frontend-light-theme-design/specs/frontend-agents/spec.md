## ADDED Requirements

### Requirement: Agents page SHALL list all registered agents
The agents page at `/agents` SHALL display a table of all registered agents with their status, sourced from `GET /api/v1/agents`.

#### Scenario: Agent list display
- **WHEN** user navigates to `/agents`
- **THEN** the page SHALL display a table with columns: Agent ID, Status (active badge green / inactive badge gray), Last Seen (relative time)

#### Scenario: Click agent row to view details
- **WHEN** user clicks an agent row
- **THEN** the page SHALL navigate to `/agents/:id` showing latest metrics for that agent

### Requirement: Agent detail page SHALL show latest metrics
The agent detail page at `/agents/:id` SHALL display the latest metric values for the selected agent from `GET /api/v1/agents/:id/latest`.

#### Scenario: Latest metrics display
- **WHEN** user views agent detail for "web-server-01"
- **THEN** the page SHALL display metric cards for CPU usage (%), memory usage (%), disk usage (%), and load average, each with current value and metric name

#### Scenario: Agent not found
- **WHEN** user navigates to `/agents/nonexistent-agent`
- **THEN** the page SHALL display a "Agent 未找到" message with a back navigation link

### Requirement: Agents page SHALL include whitelist management tab
The agents page SHALL provide a "白名单" tab that lists all whitelisted agents from `GET /api/v1/agents/whitelist` with CRUD operations.

#### Scenario: Whitelist tab display
- **WHEN** user clicks the "白名单" tab
- **THEN** the page SHALL display a table with columns: Agent ID, Description, Status, Created At, and action buttons (Edit, Regenerate Token, Delete)

#### Scenario: Add agent to whitelist
- **WHEN** user clicks "添加 Agent" and fills in agent_id and description
- **THEN** the frontend SHALL call `POST /api/v1/agents/whitelist` and display the returned token in a modal with a copy button and warning "Token 仅显示一次，请妥善保存"

#### Scenario: Delete agent from whitelist
- **WHEN** user clicks the delete button for an agent
- **THEN** the frontend SHALL show a confirmation dialog, and upon confirmation call `DELETE /api/v1/agents/whitelist/:id`

#### Scenario: Regenerate token
- **WHEN** user clicks "重新生成 Token" for an agent
- **THEN** the frontend SHALL show a confirmation dialog warning that the old token will be invalidated, and upon confirmation call `POST /api/v1/agents/whitelist/:id/token` and display the new token
