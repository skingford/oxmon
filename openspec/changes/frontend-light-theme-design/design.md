## Context

oxmon 后端已提供完整的 REST API（JWT 认证、Agent 管理、指标查询、告警、证书监控），但缺少 Web 管理界面。运维人员依赖 curl/Postman 操作，效率低。本设计定义前端管理后台的技术架构和实现方案，采用 Apple Light Theme 极简设计语言。

现有后端 API 基础：
- 认证：`POST /api/v1/auth/login` → JWT token
- Agent：`GET /api/v1/agents`、`GET /api/v1/agents/:id/latest`、白名单 CRUD
- 指标：`GET /api/v1/metrics?agent=&metric=&from=&to=`
- 告警：`GET /api/v1/alerts/rules`、`GET /api/v1/alerts/history`
- 证书：域名 CRUD、证书状态、证书详情

后端已配置 CORS（allow all origins/methods/headers），前端可直接跨域请求。

## Goals / Non-Goals

**Goals:**
- 提供完整的 Web 管理后台，覆盖所有现有 API 功能
- Apple Light Theme 设计风格，简洁专业
- 响应式布局，支持桌面端（>=1024px）为主
- 前端独立项目，可独立部署或嵌入 oxmon-server 静态托管
- 代码结构清晰，便于后续扩展 Dark 主题

**Non-Goals:**
- 不实现 Dark 主题（本期仅 Light）
- 不新增后端 API 接口
- 不实现实时 WebSocket 推送（使用轮询或手动刷新）
- 不支持移动端适配（桌面优先）
- 不实现用户管理页面（仅使用现有登录）

## Decisions

### Decision 1: 技术栈选择

**选择**：React 19 + TypeScript + Vite + Tailwind CSS v4

**理由**：
- React：生态成熟，团队熟悉
- TypeScript：类型安全，API 类型可复用
- Vite：启动快、HMR 快、构建产物小
- Tailwind CSS v4：原子化 CSS，与 Apple 设计系统的精确像素控制契合

**备选方案**：
- Vue 3 + Vite — 同样优秀，但考虑到 React 生态更大
- Next.js — SSR 对管理后台不必要，增加复杂度

### Decision 2: 路由方案

**选择**：React Router v7

**理由**：React 生态标准路由方案，支持嵌套路由和路由守卫。

**路由结构**：
```
/login                  → LoginPage
/dashboard              → DashboardPage（默认首页）
/agents                 → AgentListPage
/agents/:id             → AgentDetailPage
/agents/whitelist       → WhitelistPage（tab 切换）
/metrics                → MetricsPage
/alerts                 → AlertsPage（rules/history tab 切换）
/certificates           → CertificatesPage（domains/status tab 切换）
/certificates/:id       → CertificateDetailPage
```

### Decision 3: HTTP 客户端与 API 层

**选择**：fetch API + 自封装 apiClient

**理由**：
- 原生 fetch 足够管理后台场景，无需引入 axios
- 封装统一的请求/响应拦截：自动附加 JWT header、401 自动跳转登录、统一错误处理

**API 层设计**：
```
web/src/
  api/
    client.ts          → fetch 封装（baseURL、token 注入、错误拦截）
    auth.ts            → login()
    agents.ts          → listAgents(), getLatestMetrics(), whitelist CRUD
    metrics.ts         → queryMetrics()
    alerts.ts          → listRules(), queryHistory()
    certificates.ts    → domains CRUD, certStatus, certDetails
```

### Decision 4: 状态管理

**选择**：React Context + useState（无全局状态库）

**理由**：
- 管理后台页面间数据独立，无复杂共享状态
- AuthContext 管理 JWT token 和登录状态
- 各页面独立管理自身数据，使用 useState + useEffect
- 避免引入 Redux/Zustand 的额外复杂度

### Decision 5: 图表库

**选择**：Recharts

**理由**：
- 基于 React + D3 的声明式图表库
- 支持 LineChart、AreaChart，满足时序指标展示需求
- 轻量，API 简洁
- 样式可定制，适配 Apple 设计风格

**备选方案**：
- ECharts — 功能更强但体积大，管理后台不需要复杂图表
- Chart.js — 非 React 原生，需要 wrapper

### Decision 6: 项目目录结构

```
web/
  index.html
  package.json
  vite.config.ts
  tailwind.config.ts
  tsconfig.json
  src/
    main.tsx                → 入口
    App.tsx                 → 根组件（路由配置）
    api/                    → API 客户端层
    components/             → 通用 UI 组件
      Layout.tsx            → 侧边导航 + 顶栏 + 内容区
      Card.tsx              → Apple 风格卡片
      Badge.tsx             → 严重级别徽章
      Table.tsx             → 通用表格
      Modal.tsx             → 确认/表单对话框
      EmptyState.tsx        → 空数据状态
    pages/                  → 页面组件
      LoginPage.tsx
      DashboardPage.tsx
      AgentListPage.tsx
      AgentDetailPage.tsx
      MetricsPage.tsx
      AlertsPage.tsx
      CertificatesPage.tsx
      CertificateDetailPage.tsx
    contexts/
      AuthContext.tsx        → JWT 认证上下文
    hooks/
      useApi.ts             → 通用数据请求 hook
    types/                  → TypeScript 类型定义
      index.ts
    styles/
      globals.css           → Tailwind 入口 + 自定义变量
```

### Decision 7: Apple Light Theme 实现

**选择**：Tailwind CSS 自定义主题 + CSS 变量

通过 Tailwind 配置扩展自定义颜色：

```typescript
// tailwind.config.ts
colors: {
  apple: {
    bg: '#FFFFFF',
    'bg-secondary': '#F5F5F7',
    text: '#1D1D1F',
    'text-secondary': '#6E6E73',
    blue: '#0071E3',
    green: '#34C759',
    orange: '#FF9500',
    red: '#FF3B30',
    border: '#D2D2D7',
    'border-light': '#E5E5EA',
  }
}
```

CSS 变量方式定义，便于未来扩展 Dark 主题时切换。

### Decision 8: 布局方案

**选择**：左侧固定导航栏 + 右侧内容区

- 左侧导航栏：宽度 240px，白色背景，底部阴影分隔
- 导航项：图标 + 文字，选中态使用 `#0071E3` 高亮
- 顶栏：右侧显示用户名 + 登出按钮
- 内容区：`#F5F5F7` 背景，内容卡片白底 12px 圆角

### Decision 9: 构建产物部署

**选择**：Vite 构建为静态文件，支持两种部署方式

1. **嵌入 oxmon-server**：构建产物放入 `web/dist/`，oxmon-server 通过 axum 静态文件服务托管
2. **独立部署**：nginx 反代静态文件 + API 代理到 oxmon-server

本期不修改 oxmon-server 代码，采用独立部署方式。后续可添加嵌入支持。

## Risks / Trade-offs

- **[无实时推送]** → 使用手动刷新和页面切换时自动重新请求数据。Dashboard 可添加自动轮询（30s 间隔）作为妥协方案
- **[API 类型不同步]** → 前端 TypeScript 类型手动定义。后续可考虑从 OpenAPI spec 自动生成类型
- **[单主题]** → 仅 Light 主题。通过 CSS 变量设计，确保后续 Dark 主题扩展成本低
- **[桌面优先]** → 不适配移动端。管理后台的典型使用场景是桌面浏览器，可接受
- **[无离线支持]** → 管理后台依赖在线 API 访问，无 Service Worker 或 PWA 能力
