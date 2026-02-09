[English](README.md) | 中文

# oxmon

轻量级服务器监控系统，使用 Rust 构建。采集系统指标（CPU、内存、磁盘、网络、负载），存储时序数据，评估告警规则，并通过多种渠道发送通知。

## 架构

```
┌──────────────────┐      gRPC      ┌──────────────────────────────────────┐
│   oxmon-agent    │───────────────→│           oxmon-server                │
│                  │                │                                      │
│ ┌──────────────┐ │                │ ┌────────┐  ┌─────────┐  ┌────────┐ │
│ │  Collectors  │ │                │ │ gRPC   │→ │ Storage │  │  REST  │ │
│ │ CPU/Mem/Disk │ │                │ │ Ingest │  │ SQLite  │  │  API   │ │
│ │ Net/Load     │ │                │ └────┬───┘  └────┬────┘  └────────┘ │
│ └──────────────┘ │                │      │           │                   │
│ ┌──────────────┐ │                │      ▼           │                   │
│ │ Local Buffer │ │                │ ┌────────┐       │  ┌────────────┐  │
│ │ (VecDeque)   │ │                │ │ Alert  │───────┘  │ Notify     │  │
│ └──────────────┘ │                │ │ Engine │─────────→│ Notify     │  │
└──────────────────┘                │ └────────┘          │ Plugin     │  │
                                    │                     │ Registry   │  │
                                    └─────────────────────┴────────────┴──┘
```

**Agent** 部署在被监控服务器上，每隔 N 秒采集指标，通过 gRPC 上报。连接失败时在本地缓冲。

**Server** 接收指标，存储到按时间分区的 SQLite，评估告警规则（阈值/变化率/趋势预测），并发送通知。

## Crate 结构

| Crate | 说明 |
|-------|------|
| `oxmon-common` | 共享类型、protobuf 定义 |
| `oxmon-collector` | 系统指标采集器（CPU、内存、磁盘、网络、负载） |
| `oxmon-agent` | Agent 二进制 - 采集循环 + gRPC 客户端 |
| `oxmon-storage` | 按时间分区的 SQLite 存储引擎 |
| `oxmon-alert` | 告警规则引擎（阈值、变化率、趋势预测） |
| `oxmon-notify` | 通知渠道插件系统（邮件、Webhook、短信、钉钉、企业微信） |
| `oxmon-server` | Server 二进制 - gRPC + REST API + 告警 + 通知 |

## 快速开始

### 1. 构建

```bash
cargo build --release
```

生成两个二进制文件：`target/release/oxmon-agent` 和 `target/release/oxmon-server`。

### 2. 配置

```bash
cp config/server.example.toml config/server.toml
cp config/agent.example.toml config/agent.toml
```

根据实际环境编辑配置文件，详见下方 [配置说明](#配置说明)。

### 3. 启动服务端

```bash
# 手动启动
oxmon-server /etc/oxmon/server.toml

# 或使用 PM2 进程守护（默认北京时间）
TZ=Asia/Shanghai pm2 start oxmon-server --name oxmon-server \
  --log-date-format="YYYY-MM-DD HH:mm:ss Z" \
  -- /etc/oxmon/server.toml
pm2 save && pm2 startup
```

Server 启动后监听 gRPC 端口 9090 和 REST API 端口 8080（可配置）。

### 4. 启动采集端

```bash
# 手动启动
oxmon-agent /etc/oxmon/agent.toml

# 或使用 PM2 进程守护（默认北京时间）
TZ=Asia/Shanghai pm2 start oxmon-agent --name oxmon-agent \
  --log-date-format="YYYY-MM-DD HH:mm:ss Z" \
  -- /etc/oxmon/agent.toml
pm2 save && pm2 startup
```

Agent 每 10 秒（可配置）采集一次系统指标，通过 gRPC 上报给 Server。

## 配置说明

### Agent 配置 (`agent.toml`)

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `agent_id` | 该节点唯一标识，用于区分不同服务器 | `"web-server-01"` |
| `server_endpoint` | Server 的 gRPC 地址（`host:port`） | `"127.0.0.1:9090"` |
| `tls` | 启用 gRPC TLS 加密连接 | `false` |
| `auth_token` | 认证 token（可选，Server 启用认证时必填） | 无 |
| `collection_interval_secs` | 指标采集间隔（秒） | `10` |
| `buffer_max_size` | Server 不可达时本地缓冲的最大批次数 | `1000` |

示例：

```toml
agent_id = "web-server-01"
server_endpoint = "10.0.1.100:9090"
# tls = true  # 启用 gRPC TLS 加密连接
# auth_token = "your-token-here"  # Server 启用认证时填写
collection_interval_secs = 10
buffer_max_size = 1000
```

### Server 配置 (`server.toml`)

#### 基础配置

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `grpc_port` | gRPC 端口，接收 Agent 上报 | `9090` |
| `http_port` | REST API 端口 | `8080` |
| `data_dir` | SQLite 数据文件存储目录 | `"data"` |
| `retention_days` | 数据保留天数，超期自动清理 | `7` |
| `require_agent_auth` | 是否要求 Agent 认证 | `false` |

#### 告警规则 (`[[alert.rules]]`)

支持四种规则类型：

**阈值告警 (threshold)** — 指标持续超过阈值时触发：

```toml
[[alert.rules]]
name = "high-cpu"
type = "threshold"
metric = "cpu.usage"          # 监控的指标名
agent_pattern = "*"           # Agent 匹配模式，支持 glob（如 "web-*"）
operator = "greater_than"     # 比较运算符：greater_than / less_than
value = 90.0                  # 阈值
duration_secs = 300           # 持续时间（秒），超过阈值持续这么久才触发
severity = "critical"         # 严重级别：info / warning / critical
silence_secs = 600            # 静默期（秒），同一告警在此期间不重复触发
```

**变化率告警 (rate_of_change)** — 指标在时间窗口内变化超过百分比时触发：

```toml
[[alert.rules]]
name = "memory-spike"
type = "rate_of_change"
metric = "memory.used_percent"
agent_pattern = "*"
rate_threshold = 20.0         # 变化率阈值（百分比）
window_secs = 300             # 计算窗口（秒）
severity = "warning"
silence_secs = 600
```

**趋势预测告警 (trend_prediction)** — 通过线性回归预测指标何时突破阈值：

```toml
[[alert.rules]]
name = "disk-full-prediction"
type = "trend_prediction"
metric = "disk.used_percent"
agent_pattern = "*"
predict_threshold = 95.0      # 预测突破的目标阈值
horizon_secs = 86400          # 预测时间范围（秒），如 86400 = 24 小时
min_data_points = 10          # 最少数据点数，不够则不预测
severity = "info"
silence_secs = 3600
```

**证书过期告警 (cert_expiration)** — 根据证书剩余有效天数触发分级告警：

```toml
[[alert.rules]]
name = "cert-expiry"
type = "cert_expiration"
metric = "certificate.days_until_expiry"
agent_pattern = "cert-checker"
severity = "critical"           # 默认严重级别
warning_days = 30               # 距过期 30 天触发 warning
critical_days = 7               # 距过期 7 天触发 critical
silence_secs = 86400
```

#### 通知渠道 (`[[notification.channels]]`)

**邮件通知：**

```toml
[[notification.channels]]
type = "email"
min_severity = "warning"          # 最低触发级别
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "alerts@example.com"
smtp_password = "your-password"
from = "alerts@example.com"
recipients = ["admin@example.com", "ops@example.com"]
```

**Webhook 通知（适用于 Slack / 钉钉 / 飞书等）：**

```toml
[[notification.channels]]
type = "webhook"
min_severity = "info"
url = "https://hooks.slack.com/services/xxx/yyy/zzz"
# 可选：自定义 body 模板，支持 {{agent_id}} {{metric}} {{value}} {{severity}} {{message}} 变量
# body_template = '{"text": "[{{severity}}] {{agent_id}}: {{message}}"}'
```

**短信通知：**

```toml
[[notification.channels]]
type = "sms"
min_severity = "critical"
gateway_url = "https://sms-api.example.com/send"
api_key = "your-api-key"
phone_numbers = ["+8613800138000"]
```

**钉钉机器人通知：**

```toml
[[notification.channels]]
type = "dingtalk"
min_severity = "warning"
webhook_url = "https://oapi.dingtalk.com/robot/send?access_token=YOUR_TOKEN"
secret = "SEC_YOUR_SECRET"   # 可选：HMAC-SHA256 加签密钥
```

钉钉通知发送 Markdown 格式消息，包含告警级别、Agent、指标、值、阈值和时间信息。当配置了 `secret` 时，使用 HMAC-SHA256 对请求签名。

**企业微信机器人通知：**

```toml
[[notification.channels]]
type = "weixin"
min_severity = "warning"
webhook_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY"
```

企业微信通知发送 Markdown 格式消息。

> **插件系统**：通知渠道基于插件架构实现，每种渠道是一个独立的 `ChannelPlugin`。Server 通过 `ChannelRegistry` 动态查找并实例化渠道，配置文件中的 `type` 字段对应插件名称，其余字段直接传给插件解析。内置插件：`email`、`webhook`、`sms`、`dingtalk`、`weixin`。

#### 静默窗口 (`[[notification.silence_windows]]`)

在维护时段抑制通知：

```toml
[[notification.silence_windows]]
start_time = "02:00"
end_time = "04:00"
recurrence = "daily"
```

#### 告警聚合

```toml
aggregation_window_secs = 60   # 相似告警的聚合窗口（秒），窗口内的同类告警合并为一条通知
```

## 采集指标列表

| 指标名 | 说明 |
|--------|------|
| `cpu.usage` | CPU 总体使用率 (%) |
| `cpu.core_usage` | 每核 CPU 使用率 (%) |
| `memory.total` | 内存总量 (bytes) |
| `memory.used` | 已用内存 (bytes) |
| `memory.available` | 可用内存 (bytes) |
| `memory.used_percent` | 内存使用率 (%) |
| `memory.swap_total` | Swap 总量 (bytes) |
| `memory.swap_used` | Swap 已用 (bytes) |
| `disk.total` | 磁盘总容量 (bytes)，按挂载点 |
| `disk.used` | 磁盘已用 (bytes)，按挂载点 |
| `disk.available` | 磁盘可用 (bytes)，按挂载点 |
| `disk.used_percent` | 磁盘使用率 (%)，按挂载点 |
| `network.bytes_sent` | 网络发送字节数/秒，按网卡 |
| `network.bytes_recv` | 网络接收字节数/秒，按网卡 |
| `network.packets_sent` | 网络发送包数/秒，按网卡 |
| `network.packets_recv` | 网络接收包数/秒，按网卡 |
| `load.load_1` | 1 分钟负载 |
| `load.load_5` | 5 分钟负载 |
| `load.load_15` | 15 分钟负载 |
| `load.uptime` | 系统运行时间 (秒) |
| `certificate.days_until_expiry` | 证书剩余有效天数，按域名（Server 端采集） |
| `certificate.is_valid` | 证书是否有效 (1=有效, 0=无效/过期/错误)，按域名 |

## REST API

### `GET /v1/health`

健康检查，返回服务端状态。

```bash
curl http://localhost:8080/v1/health
```

### 认证接口

#### `POST /v1/auth/login`

登录获取 JWT Token（公开接口，无需鉴权）。

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"changeme"}'
```

#### `POST /v1/auth/password`

修改当前登录用户密码（需携带 Bearer Token）。

> 安全行为：密码修改成功后，旧 JWT 会立即失效，需要重新登录获取新 token。

```bash
curl -X POST http://localhost:8080/v1/auth/password \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"changeme","new_password":"new-strong-password"}'
```

### `GET /v1/agents`

列出所有已注册的 Agent。

```bash
curl http://localhost:8080/v1/agents
```

响应示例：

```json
[
  {
    "agent_id": "web-server-01",
    "last_seen": "2026-02-06T10:30:00Z",
    "active": true
  }
]
```

### `GET /v1/agents/:id/latest`

获取指定 Agent 的最新指标值。

```bash
curl http://localhost:8080/v1/agents/web-server-01/latest
```

### `GET /v1/metrics`

查询时序数据。

| 参数 | 说明 | 必填 |
|------|------|------|
| `agent` | Agent ID | 是 |
| `metric` | 指标名 | 是 |
| `from` | 起始时间 (ISO 8601) | 是 |
| `to` | 结束时间 (ISO 8601) | 是 |

```bash
curl "http://localhost:8080/v1/metrics?agent=web-server-01&metric=cpu.usage&from=2026-02-06T00:00:00Z&to=2026-02-06T23:59:59Z"
```

### `GET /v1/alerts/rules`

列出所有已配置的告警规则。

```bash
curl http://localhost:8080/v1/alerts/rules
```

### `GET /v1/alerts/history`

查询告警历史。

| 参数 | 说明 | 必填 |
|------|------|------|
| `severity` | 按严重级别过滤 (info/warning/critical) | 否 |
| `agent` | 按 Agent ID 过滤 | 否 |
| `from` | 起始时间 | 否 |
| `to` | 结束时间 | 否 |
| `limit` | 返回条数限制 | 否 |
| `offset` | 分页偏移 | 否 |

```bash
curl "http://localhost:8080/v1/alerts/history?severity=critical&limit=50"
```

### Agent 白名单管理

Agent 白名单用于控制哪些 Agent 可以通过 gRPC 上报数据。Agent 需要**手动**通过 API 添加到白名单，不会自动注册。`agent_id` 具有唯一性约束，重复添加返回 409。

#### `POST /v1/agents/whitelist`

添加 Agent 到白名单，返回认证 token（仅在创建时返回一次，请妥善保存）。

```bash
curl -X POST http://localhost:8080/v1/agents/whitelist \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "web-server-01", "description": "生产环境 Web 服务器"}'
```

响应示例：

```json
{
  "agent_id": "web-server-01",
  "token": "AbCdEf1234567890...",
  "created_at": "2026-02-08T10:00:00Z"
}
```

#### `GET /v1/agents/whitelist`

列出所有白名单中的 Agent（包含在线状态，不包含 token）。

```bash
curl http://localhost:8080/v1/agents/whitelist
```

响应示例：

```json
[
  {
    "agent_id": "web-server-01",
    "created_at": "2026-02-08T10:00:00Z",
    "description": "生产环境 Web 服务器",
    "last_seen": "2026-02-08T12:30:00Z",
    "status": "active"
  }
]
```

`status` 字段取值：`active`（在线）、`inactive`（离线）、`unknown`（从未上报）。

#### `PUT /v1/agents/whitelist/{agent_id}`

更新 Agent 白名单信息（如描述）。

```bash
curl -X PUT http://localhost:8080/v1/agents/whitelist/web-server-01 \
  -H "Content-Type: application/json" \
  -d '{"description": "生产环境 Web 服务器 - 已迁移"}'
```

#### `POST /v1/agents/whitelist/{agent_id}/token`

重新生成 Agent 的认证 Token。生成后旧 Token 立即失效，请更新 Agent 配置中的 `auth_token` 并重启 Agent。

```bash
curl -X POST http://localhost:8080/v1/agents/whitelist/web-server-01/token
```

响应示例：

```json
{
  "agent_id": "web-server-01",
  "token": "NewToken1234567890..."
}
```

#### `DELETE /v1/agents/whitelist/{agent_id}`

从白名单中删除 Agent。

```bash
curl -X DELETE http://localhost:8080/v1/agents/whitelist/web-server-01
```

### 证书详情查询

Server 定期采集证书详细信息（颁发者、SAN、证书链验证、解析 IP 等），可通过以下接口查询。

#### `GET /v1/certificates`

列出所有证书详情，支持过滤和分页。

| 参数 | 说明 | 必填 |
|------|------|------|
| `expiring_within_days` | 过滤即将过期的证书（N 天内） | 否 |
| `ip_address` | 按 IP 地址过滤 | 否 |
| `issuer` | 按颁发者过滤 | 否 |
| `limit` | 每页数量（默认 100） | 否 |
| `offset` | 分页偏移 | 否 |

```bash
# 查询所有证书
curl http://localhost:8080/v1/certificates

# 查询 30 天内即将过期的证书
curl "http://localhost:8080/v1/certificates?expiring_within_days=30"

# 按颁发者过滤
curl "http://localhost:8080/v1/certificates?issuer=Let%27s%20Encrypt"
```

#### `GET /v1/certificates/{domain}`

获取指定域名的证书详情。

```bash
curl http://localhost:8080/v1/certificates/example.com
```

响应示例：

```json
{
  "domain": "example.com",
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2026-01-01T00:00:00Z",
  "ip_addresses": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
  "issuer_cn": "R3",
  "issuer_o": "Let's Encrypt",
  "subject_alt_names": ["example.com", "www.example.com"],
  "chain_valid": true,
  "last_checked": "2026-02-08T10:00:00Z"
}
```

#### `GET /v1/certificates/{domain}/chain`

获取指定域名的证书链验证信息。

```bash
curl http://localhost:8080/v1/certificates/example.com/chain
```

### 证书域名管理

#### `POST /v1/certs/domains`

添加监控域名。

```bash
curl -X POST http://localhost:8080/v1/certs/domains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "port": 443, "note": "主站"}'
```

#### `POST /v1/certs/domains/batch`

批量添加域名。

```bash
curl -X POST http://localhost:8080/v1/certs/domains/batch \
  -H "Content-Type: application/json" \
  -d '{"domains": [{"domain": "a.com"}, {"domain": "b.com", "port": 8443}]}'
```

#### `GET /v1/certs/domains`

查询域名列表（支持 `?enabled=true&search=example&limit=20&offset=0`）。

```bash
curl http://localhost:8080/v1/certs/domains
```

#### `PUT /v1/certs/domains/:id`

更新域名配置（端口、启用状态、检测间隔）。

```bash
curl -X PUT http://localhost:8080/v1/certs/domains/<id> \
  -H "Content-Type: application/json" \
  -d '{"check_interval_secs": 3600, "enabled": true}'
```

#### `DELETE /v1/certs/domains/:id`

删除域名及其检测记录。

```bash
curl -X DELETE http://localhost:8080/v1/certs/domains/<id>
```

#### `GET /v1/certs/status`

查询所有域名最新证书检测结果。

```bash
curl http://localhost:8080/v1/certs/status
```

#### `GET /v1/certs/status/:domain`

查询指定域名的最新证书检测结果。

```bash
curl http://localhost:8080/v1/certs/status/example.com
```

#### `POST /v1/certs/domains/:id/check`

手动触发指定域名的证书检测。

```bash
curl -X POST http://localhost:8080/v1/certs/domains/<id>/check
```

#### `POST /v1/certs/check`

手动触发所有已启用域名的证书检测。

```bash
curl -X POST http://localhost:8080/v1/certs/check
```

### API 文档（OpenAPI）

Server 提供 OpenAPI 3.0.3 格式的接口文档，可直接导入 Apifox、Postman、Swagger UI 等工具。

| 端点 | 格式 |
|------|------|
| `GET /v1/openapi.json` | JSON 格式 |
| `GET /v1/openapi.yaml` | YAML 格式 |

```bash
# 获取 JSON 格式的 API 文档
curl http://localhost:8080/v1/openapi.json

# 获取 YAML 格式的 API 文档
curl http://localhost:8080/v1/openapi.yaml
```

**Apifox 导入方式：**
1. 打开 Apifox → 项目设置 → 导入数据
2. 选择 "OpenAPI/Swagger" → "URL 导入"
3. 输入 `http://<server-ip>:8080/v1/openapi.json`
4. 点击导入即可获取所有接口定义

### SQLite 常用命令

oxmon 使用 SQLite 存储数据：

- `data/cert.db`：用户、白名单、证书域名、证书详情
- `data/YYYY-MM-DD.db`：按天分区的指标与告警数据（`metrics`、`alert_events`）

```bash
# 查看当前数据目录下的数据库文件
ls -lh data/*.db

# 打开主库
sqlite3 data/cert.db

# 打开某一天的分区库
sqlite3 data/2026-02-09.db
```

进入 `sqlite3` 后常用命令：

```sql
.headers on
.mode column
.tables
.schema
.schema users
PRAGMA table_info(users);
.quit
```

基础查询（SELECT）：

```sql
SELECT id, username, created_at FROM users LIMIT 20;

SELECT id, domain, port, enabled
FROM cert_domains
ORDER BY updated_at DESC
LIMIT 20;

SELECT id, rule_id, agent_id, severity, metric_name, timestamp
FROM alert_events
ORDER BY timestamp DESC
LIMIT 20;
```

基础增删改查（CRUD）示例：

```sql
-- 增（INSERT）
INSERT INTO cert_domains (id, domain, port, enabled, created_at, updated_at)
VALUES ('manual-001', 'example.com', 443, 1, strftime('%s','now'), strftime('%s','now'));

-- 查（SELECT）
SELECT id, domain, enabled FROM cert_domains WHERE id = 'manual-001';

-- 改（UPDATE）
UPDATE cert_domains
SET enabled = 0, updated_at = strftime('%s','now')
WHERE id = 'manual-001';

-- 删（DELETE）
DELETE FROM cert_domains WHERE id = 'manual-001';
```

> 建议优先通过 REST API 写入业务数据；对 `users`、`agent_whitelist` 等认证相关表的手工修改可能导致登录或鉴权失败。

### 证书检测配置

在 `server.toml` 中配置证书检测：

```toml
[cert_check]
enabled = true
default_interval_secs = 86400   # 默认检测间隔（24小时）
tick_secs = 60                  # 调度器 tick 间隔
connect_timeout_secs = 10       # TLS 连接超时
max_concurrent = 10              # 最大并发检测数
```

域名通过 REST API 动态管理，每个域名可单独配置 `check_interval_secs` 覆盖全局默认值。

## Linux 快速部署

使用 `curl | bash` 一键安装，自动下载 GitHub Releases 中的预编译二进制文件，生成配置文件，并可选配置 PM2 进程守护。

> Server 和 Agent 分开部署 — 中心机器装 `server`，被监控主机装 `agent`。

### 安装 Server（中心机器）

```bash
# 基础安装
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- server

# 安装并配置 PM2 进程守护
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- server --setup-pm2
```

### 安装 Agent（被监控主机）

```bash
# 指向 Server 的 gRPC 地址
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- agent \
  --server-endpoint 10.0.1.100:9090

# 自定义 Agent ID + PM2
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- agent \
  --server-endpoint 10.0.1.100:9090 \
  --agent-id web-server-01 \
  --setup-pm2
```

### 为已有安装添加 PM2 守护

如果已经手动安装了 oxmon，可以单独生成 PM2 配置：

```bash
# Server 机器上
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- server --pm2-only

# Agent 机器上
curl -fsSL https://raw.githubusercontent.com/skingford/oxmon/main/scripts/install.sh | bash -s -- agent --pm2-only
```

### PM2 常用命令

```bash
pm2 status                    # 查看进程状态
pm2 logs oxmon-server         # 实时查看 Server 日志
pm2 logs oxmon-agent          # 实时查看 Agent 日志
pm2 restart oxmon-server      # 重启 Server
pm2 restart oxmon-agent       # 重启 Agent
pm2 stop oxmon-server         # 停止服务
pm2 startup                   # 设置开机自启
pm2 save                      # 保存当前进程列表
```

### 常见问题

如果 PM2 启动时报 `EACCES: permission denied` 权限错误，需要修复目录所有权：

```bash
sudo chown $(id -u):$(id -g) /var/log/oxmon /var/lib/oxmon
pm2 restart oxmon-server   # 或: pm2 reload oxmon-server
```

### 安装脚本参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `server` / `agent` | 安装组件（必填，第一个参数） | — |
| `--version` | 指定 Release 版本号 | `latest` |
| `--install-dir` | 二进制安装路径 | `/usr/local/bin` |
| `--config-dir` | 配置文件路径 | `/etc/oxmon` |
| `--data-dir` | Server 数据存储目录（仅 server） | `/var/lib/oxmon` |
| `--agent-id` | Agent 标识（仅 agent） | `$(hostname)` |
| `--server-endpoint` | Agent 连接的 gRPC 地址（仅 agent） | `127.0.0.1:9090` |
| `--setup-pm2` | 生成 PM2 配置并启动服务 | 关闭 |
| `--pm2-only` | 仅生成 PM2 配置（跳过下载） | 关闭 |

## 交叉编译 / 多平台构建

支持以下目标平台：

| 目标 | 说明 |
|------|------|
| `x86_64-unknown-linux-gnu` | Linux AMD64 |
| `aarch64-unknown-linux-gnu` | Linux ARM64 |
| `x86_64-apple-darwin` | macOS Intel |
| `aarch64-apple-darwin` | macOS Apple Silicon |

### 前置依赖

- [cross](https://github.com/cross-rs/cross)（Linux 交叉编译需要 Docker）
- Rust 工具链及对应 target：`rustup target add <triple>`

### 使用 Makefile

```bash
# 构建单个 Linux 目标（通过 cross）
make x86_64-unknown-linux-gnu
make aarch64-unknown-linux-gnu

# 构建 macOS 目标（原生编译）
make aarch64-apple-darwin

# 打包某个目标的产物
make package TARGET=x86_64-unknown-linux-gnu

# 构建并打包所有目标
make release
```

### 手动使用 cross

```bash
cross build --release --target aarch64-unknown-linux-gnu
```

### 验证 OpenSSL 已移除

```bash
cargo tree -i openssl-sys
# 应输出 "openssl-sys" 不存在
```

## Docker 部署

### 构建镜像

```bash
# 单架构
docker build -f Dockerfile.server -t oxmon-server .
docker build -f Dockerfile.agent -t oxmon-agent .

# 多架构（需要 docker buildx）
docker buildx build --platform linux/amd64,linux/arm64 \
  -f Dockerfile.agent -t oxmon-agent:latest --push .
docker buildx build --platform linux/amd64,linux/arm64 \
  -f Dockerfile.server -t oxmon-server:latest --push .
```

### 运行服务端

```bash
docker run -d \
  -p 9090:9090 \
  -p 8080:8080 \
  -v $(pwd)/config/server.toml:/etc/oxmon/server.toml \
  -v $(pwd)/data:/data \
  --name oxmon-server \
  oxmon-server
```

### 运行采集端

```bash
docker run -d \
  -v $(pwd)/config/agent.toml:/etc/oxmon/agent.toml \
  --name oxmon-agent \
  oxmon-agent
```

## 告警工作流程

系统自动运行，无需手动干预：

1. **采集** — Agent 按配置间隔采集 CPU、内存、磁盘、网络、负载指标
2. **上报** — 通过 gRPC 发送到 Server，连接失败时自动缓冲，恢复后重传
3. **存储** — Server 写入按天分区的 SQLite，自动清理过期数据
4. **评估** — Alert Engine 对每个数据点评估所有匹配的告警规则
5. **去重** — 同一告警在静默期内不重复触发
6. **聚合** — 聚合窗口内的同类告警合并为一条通知
7. **通知** — 按严重级别路由到对应渠道（邮件/Webhook/短信/钉钉/企业微信），静默窗口内不发送

## License

MIT
