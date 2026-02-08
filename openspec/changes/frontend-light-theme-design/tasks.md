## 1. Project Setup

- [ ] 1.1 Initialize Vite + React 19 + TypeScript project in `web/` directory with `npm create vite@latest`
- [ ] 1.2 Install dependencies: react-router-dom, recharts, tailwindcss v4, @tailwindcss/vite, Inter font
- [ ] 1.3 Configure Tailwind CSS v4 with Apple Light Theme custom colors (bg, bg-secondary, text, text-secondary, blue, green, orange, red, border, border-light) as CSS variables in `src/styles/globals.css`
- [ ] 1.4 Configure Vite proxy for development API requests (`/api/v1` → `http://localhost:3000`)
- [ ] 1.5 Set up project directory structure: `src/{api,components,pages,contexts,hooks,types,styles}`

## 2. API Client & Types

- [ ] 2.1 Create `src/api/client.ts` with fetch wrapper: baseURL configuration, JWT token injection from localStorage, 401 auto-redirect to `/login`, unified error handling
- [ ] 2.2 Create `src/types/index.ts` with TypeScript interfaces for all API entities: Agent, AgentWhitelistEntry, MetricDataPoint, AlertRule, AlertEvent, CertDomain, CertStatus, CertificateDetails, HealthInfo
- [ ] 2.3 Create `src/api/auth.ts` with `login(username, password)` function
- [ ] 2.4 Create `src/api/agents.ts` with `listAgents()`, `getLatestMetrics(id)`, whitelist CRUD functions (list, add, update, delete, regenerateToken)
- [ ] 2.5 Create `src/api/metrics.ts` with `queryMetrics(agent, metric, from, to)` function
- [ ] 2.6 Create `src/api/alerts.ts` with `listRules()`, `queryHistory(filters)` functions
- [ ] 2.7 Create `src/api/certificates.ts` with domain CRUD, batch add, manual check, cert status, cert details, cert chain functions

## 3. Auth & Routing

- [ ] 3.1 Create `src/contexts/AuthContext.tsx` with JWT token state management, login/logout methods, token persistence in localStorage
- [ ] 3.2 Create route guard component that redirects to `/login` when no valid token exists
- [ ] 3.3 Set up React Router v7 in `src/App.tsx` with all routes: `/login`, `/dashboard`, `/agents`, `/agents/:id`, `/agents/whitelist`, `/metrics`, `/alerts`, `/certificates`, `/certificates/:id`
- [ ] 3.4 Configure default redirect from `/` to `/dashboard`

## 4. Layout & Common Components

- [ ] 4.1 Create `src/components/Layout.tsx` with left sidebar (240px, white bg) + right content area (#F5F5F7 bg), logo at top of sidebar, user info + logout button in header
- [ ] 4.2 Add sidebar navigation items with icons: Dashboard, Agents, Metrics, Alerts, Certificates; active state highlighted with `#0071E3`
- [ ] 4.3 Create `src/components/Card.tsx` — Apple-style card with white bg, 12px border-radius, `0 2px 12px rgba(0,0,0,0.08)` shadow
- [ ] 4.4 Create `src/components/Badge.tsx` — severity badge component with color presets (critical=#FF3B30, warning=#FF9500, info=#0071E3) and white text
- [ ] 4.5 Create `src/components/Table.tsx` — reusable table with header, rows, optional pagination controls
- [ ] 4.6 Create `src/components/Modal.tsx` — confirmation/form dialog with backdrop overlay
- [ ] 4.7 Create `src/components/EmptyState.tsx` — centered empty state with icon and message text

## 5. Login Page

- [ ] 5.1 Create `src/pages/LoginPage.tsx` with centered white card (max-width 400px) on #F5F5F7 bg, logo, username/password inputs, #0071E3 login button
- [ ] 5.2 Implement form validation: show inline errors for empty username or password fields
- [ ] 5.3 Implement login flow: call `POST /api/v1/auth/login`, store JWT token, redirect to `/dashboard`; show error message "用户名或密码错误" on failure

## 6. Dashboard Page

- [ ] 6.1 Create `src/pages/DashboardPage.tsx` with card-based grid layout
- [ ] 6.2 Implement agent status summary card: total agents, active count, online rate percentage with green/red indicator
- [ ] 6.3 Implement server health cards: version, uptime (formatted as human-readable), storage info from `GET /api/v1/health`
- [ ] 6.4 Implement recent alerts list: 10 most recent alerts with severity badge, agent ID, metric, message, relative timestamp; empty state "暂无告警记录"

## 7. Agents Pages

- [ ] 7.1 Create `src/pages/AgentListPage.tsx` with table displaying Agent ID, Status (active=green badge, inactive=gray badge), Last Seen (relative time)
- [ ] 7.2 Implement click-to-navigate: clicking an agent row navigates to `/agents/:id`
- [ ] 7.3 Create `src/pages/AgentDetailPage.tsx` with metric cards for CPU, memory, disk, load average from `GET /api/v1/agents/:id/latest`; "Agent 未找到" state for nonexistent agent
- [ ] 7.4 Add whitelist tab on agents page with table: Agent ID, Description, Status, Created At, action buttons (Edit, Regenerate Token, Delete)
- [ ] 7.5 Implement "添加 Agent" modal: agent_id + description inputs, display returned token with copy button and warning "Token 仅显示一次，请妥善保存"
- [ ] 7.6 Implement whitelist delete with confirmation dialog calling `DELETE /api/v1/agents/whitelist/:id`
- [ ] 7.7 Implement "重新生成 Token" with confirmation warning, call `POST /api/v1/agents/whitelist/:id/token`, display new token

## 8. Metrics Page

- [ ] 8.1 Create `src/pages/MetricsPage.tsx` with agent dropdown (populated from `GET /api/v1/agents`), metric dropdown (static: cpu.usage, memory.used_percent, disk.used_percent, load.load_1/5/15, network.bytes_sent/recv), time range controls
- [ ] 8.2 Implement time range presets: 1 hour, 6 hours, 24 hours, 7 days buttons, plus custom date-time picker
- [ ] 8.3 Implement query execution: validate required fields (inline errors), call `GET /api/v1/metrics` with selected filters
- [ ] 8.4 Implement Recharts LineChart rendering: #0071E3 line color, light blue fill area, #F5F5F7 chart bg, #E5E5EA grid lines, tooltip with timestamp and value

## 9. Alerts Page

- [ ] 9.1 Create `src/pages/AlertsPage.tsx` with "告警规则" and "告警历史" tabs
- [ ] 9.2 Implement alert rules tab: table with Rule Name, Type, Metric, Agent Pattern, Severity (color-coded badge), Parameters
- [ ] 9.3 Implement alert history tab: table with Severity, Agent, Metric, Message, Value/Threshold, Timestamp; default 50 most recent, descending
- [ ] 9.4 Implement history filters: severity dropdown, agent text input, date range picker
- [ ] 9.5 Implement pagination controls: Previous/Next buttons, page number display, page size selector (10, 25, 50, 100)

## 10. Certificates Pages

- [ ] 10.1 Create `src/pages/CertificatesPage.tsx` with "域名管理" and "证书状态" tabs
- [ ] 10.2 Implement domain list table: Domain, Port, Enabled (toggle), Check Interval, Note, Last Checked, action buttons (Edit, Check Now, Delete)
- [ ] 10.3 Implement "添加域名" modal: domain, port, note inputs; call `POST /api/v1/certs/domains`
- [ ] 10.4 Implement "批量添加" modal: textarea for multiple domains (one per line); call `POST /api/v1/certs/domains/batch`
- [ ] 10.5 Implement domain edit modal and delete confirmation dialog
- [ ] 10.6 Implement "立即检测" per domain (`POST /api/v1/certs/domains/:id/check`) and "全部检测" (`POST /api/v1/certs/check`)
- [ ] 10.7 Implement certificate status tab: domain list with Valid (green checkmark/red cross), Issuer, Days Until Expiry (color-coded: green >30d, yellow 7-30d, red <7d), Last Checked
- [ ] 10.8 Create `src/pages/CertificateDetailPage.tsx` with full cert info: Domain, Not Before, Not After, Days Until Expiry, Issuer (CN + Org), SANs list, IP Addresses, Chain Valid status
- [ ] 10.9 Implement "查看证书链" section: call `GET /api/v1/certificates/:id/chain`, display chain validation status and error message
- [ ] 10.10 Implement domain search filter and "30 天内过期" expiry filter

## 11. Polish & Build

- [ ] 11.1 Add loading states (spinner/skeleton) for all data-fetching pages
- [ ] 11.2 Add error states with retry buttons for failed API calls
- [ ] 11.3 Configure Vite production build output to `web/dist/`
- [ ] 11.4 Verify all pages render correctly with consistent Apple Light Theme styling
