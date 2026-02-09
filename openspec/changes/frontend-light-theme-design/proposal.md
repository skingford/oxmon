## Why

oxmon 目前仅通过 REST API + CLI 进行操作，缺少可视化管理界面。运维人员需要通过 curl/Postman 查询告警、指标和证书状态，效率低且不直观。需要一个 Apple 风格的极简管理后台，提供一站式的监控可视化和配置管理能力。当前仅设计 Light 主题方案。

## What Changes

- 新增独立前端项目 `web/`，基于 React + TypeScript 构建
- 设计风格参考 Apple.com：纯白底色、大留白、无衬线字体、圆角卡片、极简导航
- 仅实现 Light 主题（后续可扩展 Dark 主题）
- 前端通过现有 REST API 交互，不新增后端接口
- 前端构建产物可由 oxmon-server 静态文件服务托管

### 页面规划

1. **Login** — JWT 登录页
2. **Dashboard** — 总览仪表盘（Agent 在线率、关键指标概览、最近告警）
3. **Agents** — Agent 列表与详情（实时指标、白名单管理）
4. **Metrics** — 时序指标查询与图表展示
5. **Alerts** — 告警规则列表 + 告警历史
6. **Certificates** — 证书域名管理 + 证书状态 + 证书详情

### 设计语言（Apple Light Theme）

| 属性 | 规范 |
|------|------|
| 主背景色 | `#FFFFFF` |
| 次要背景 | `#F5F5F7` |
| 主文字色 | `#1D1D1F` |
| 次要文字 | `#6E6E73` |
| 强调色 | `#0071E3`（Apple Blue） |
| 成功色 | `#34C759` |
| 警告色 | `#FF9500` |
| 危险色 | `#FF3B30` |
| 圆角 | 12px（卡片）/ 8px（按钮、输入框） |
| 字体 | SF Pro Display / Inter（fallback：system-ui） |
| 阴影 | `0 2px 12px rgba(0,0,0,0.08)` |
| 最大内容宽度 | 1280px 居中 |
| 间距基准 | 8px 网格系统 |

## Capabilities

### New Capabilities

- `frontend-auth`: 前端登录鉴权模块（JWT 登录、token 管理、路由守卫）
- `frontend-dashboard`: 总览仪表盘（Agent 在线率、关键指标卡片、最近告警列表）
- `frontend-agents`: Agent 管理页（Agent 列表、实时指标详情、白名单 CRUD）
- `frontend-metrics`: 指标查询页（时间范围选择、Agent/指标筛选、时序折线图）
- `frontend-alerts`: 告警管理页（告警规则列表、告警历史查询与过滤）
- `frontend-certificates`: 证书监控页（域名管理 CRUD、证书状态列表、证书详情与证书链）

### Modified Capabilities

（无需修改现有后端 spec）

## Impact

- **新增目录**：`web/` — 独立前端项目
- **技术栈**：React 19 + TypeScript + Vite + Tailwind CSS + Recharts
- **API 对接**：消费全部现有 REST API（`/api/v1/*`），不新增后端接口
- **部署方式**：构建产物可嵌入 oxmon-server 静态托管，或独立 nginx 部署
- **CI/CD**：需新增前端构建步骤
