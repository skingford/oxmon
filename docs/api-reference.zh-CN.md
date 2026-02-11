# API 接口说明

> 本文件从 README 抽离，作为独立接口文档维护。

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

默认按 `last_seen` 倒序，默认分页 `limit=20&offset=0`。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

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

### 指标发现

#### `GET /v1/metrics/names`

获取时间范围内所有不同的指标名称。

| 参数 | 说明 | 必填 |
|------|------|------|
| `timestamp__gte` | 时间下界（默认 24 小时前） | 否 |
| `timestamp__lte` | 时间上界（默认当前） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/metrics/names
```

响应示例：

```json
["cpu.usage", "cpu.core_usage", "memory.used_percent", "disk.used_percent"]
```

#### `GET /v1/metrics/agents`

获取时间范围内所有上报过的 Agent ID。

| 参数 | 说明 | 必填 |
|------|------|------|
| `timestamp__gte` | 时间下界（默认 24 小时前） | 否 |
| `timestamp__lte` | 时间上界（默认当前） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/metrics/agents
```

#### `GET /v1/metrics/summary`

获取指标聚合统计（最小值/最大值/平均值/计数）。

| 参数 | 说明 | 必填 |
|------|------|------|
| `agent_id` | Agent ID | 是 |
| `metric_name` | 指标名 | 是 |
| `timestamp__gte` | 时间下界（默认 1 小时前） | 否 |
| `timestamp__lte` | 时间上界（默认当前） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/v1/metrics/summary?agent_id=web-01&metric_name=cpu.usage"
```

### `GET /v1/metrics`

分页查询指标数据（支持按 `agent_id__eq`、`metric_name__eq` 过滤）。

默认按 `created_at` 倒序，默认分页 `limit=20&offset=0`。

| 参数 | 说明 | 必填 |
|------|------|------|
| `agent_id__eq` | Agent ID 精确匹配 | 否 |
| `metric_name__eq` | 指标名精确匹配 | 否 |
| `timestamp__gte` | 时间下界 (ISO 8601) | 否 |
| `timestamp__lte` | 时间上界 (ISO 8601) | 否 |
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
# 不传分页参数时默认返回 20 条
curl "http://localhost:8080/v1/metrics"

# 指定分页
curl "http://localhost:8080/v1/metrics?limit=50&offset=100"
```

响应示例：

```json
[
  {
    "id": "m_01JABCDEF1234567890",
    "timestamp": "2026-02-09T10:00:00Z",
    "agent_id": "web-server-01",
    "metric_name": "cpu.usage",
    "value": 37.5,
    "labels": {
      "core": "0"
    },
    "created_at": "2026-02-09T10:00:01Z"
  }
]
```

### 告警规则管理

#### `GET /v1/alerts/rules`

列出引擎中所有活跃的告警规则。

默认分页 `limit=20&offset=0`。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/rules
```

#### `GET /v1/alerts/rules/config`

列出数据库中持久化的告警规则配置。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/rules/config
```

#### `GET /v1/alerts/rules/{id}`

获取单条告警规则详情。

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/rules/<id>
```

#### `POST /v1/alerts/rules`

创建告警规则。

```bash
curl -X POST http://localhost:8080/v1/alerts/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "high-cpu",
    "rule_type": "threshold",
    "metric": "cpu.usage",
    "agent_pattern": "*",
    "severity": "critical",
    "config_json": "{\"operator\":\"greater_than\",\"value\":90.0,\"duration_secs\":300}",
    "silence_secs": 600
  }'
```

#### `PUT /v1/alerts/rules/{id}`

更新告警规则（部分更新）。

```bash
curl -X PUT http://localhost:8080/v1/alerts/rules/<id> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"severity": "warning", "silence_secs": 1200}'
```

#### `DELETE /v1/alerts/rules/{id}`

删除告警规则。

```bash
curl -X DELETE http://localhost:8080/v1/alerts/rules/<id> \
  -H "Authorization: Bearer $TOKEN"
```

#### `PUT /v1/alerts/rules/{id}/enable`

启用或禁用告警规则。

```bash
curl -X PUT http://localhost:8080/v1/alerts/rules/<id>/enable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### 告警历史与生命周期

#### `GET /v1/alerts/history`

查询告警历史。

默认按 `timestamp` 倒序，默认分页 `limit=20&offset=0`。

| 参数 | 说明 | 必填 |
|------|------|------|
| `agent_id__eq` | Agent ID 精确匹配 | 否 |
| `severity__eq` | 严重级别精确匹配 (info/warning/critical) | 否 |
| `timestamp__gte` | 时间下界 | 否 |
| `timestamp__lte` | 时间上界 | 否 |
| `limit` | 返回条数限制（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/v1/alerts/history?severity__eq=critical&limit=50"
```

#### `POST /v1/alerts/history/{id}/acknowledge`

标记告警为已确认。

```bash
curl -X POST http://localhost:8080/v1/alerts/history/<id>/acknowledge \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /v1/alerts/history/{id}/resolve`

标记告警为已解决。

```bash
curl -X POST http://localhost:8080/v1/alerts/history/<id>/resolve \
  -H "Authorization: Bearer $TOKEN"
```

#### `GET /v1/alerts/active`

获取所有活跃（未解决）的告警。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/active
```

#### `GET /v1/alerts/summary`

获取最近 24 小时告警统计摘要。

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/summary
```

响应示例：

```json
{
  "total": 42,
  "by_severity": {
    "critical": 3,
    "warning": 15,
    "info": 24
  }
}
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

默认按 `created_at` 倒序，默认分页 `limit=20&offset=0`。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

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

默认按 `not_after` 升序，默认分页 `limit=20&offset=0`。

| 参数 | 说明 | 必填 |
|------|------|------|
| `not_after__lte` | 证书过期时间上界（Unix 时间戳） | 否 |
| `ip_address__contains` | IP 包含匹配 | 否 |
| `issuer__contains` | 颁发者包含匹配 | 否 |
| `limit` | 每页数量（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
# 查询所有证书
curl http://localhost:8080/v1/certificates

# 按证书过期时间上界过滤（示例时间戳）
curl "http://localhost:8080/v1/certificates?not_after__lte=1767225600"

# 按颁发者过滤
curl "http://localhost:8080/v1/certificates?issuer__contains=Let%27s%20Encrypt"
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

查询域名列表（支持 `?enabled__eq=true&domain__contains=example&limit=20&offset=0`）。

默认按 `created_at` 倒序，默认分页 `limit=20&offset=0`。

| 参数 | 说明 | 必填 |
|------|------|------|
| `enabled__eq` | 启用状态精确匹配 | 否 |
| `domain__contains` | 域名包含匹配 | 否 |
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

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

默认按 `checked_at` 倒序，默认分页 `limit=20&offset=0`。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

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

#### `GET /v1/certs/domains/{id}/history`

获取域名的证书检测历史记录。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/certs/domains/<id>/history
```

#### `GET /v1/certs/summary`

获取证书健康摘要（域名总数、有效/无效/即将过期数量）。

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/certs/summary
```

### 通知渠道管理

通知渠道存储在数据库中，通过 REST API 动态管理。每种渠道类型（email、webhook、sms、dingtalk、weixin）支持创建多个实例。收件人按渠道独立管理。

#### `GET /v1/notifications/channels`

列出所有通知渠道（含收件人列表和收件人类型）。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/notifications/channels
```

响应示例：

```json
[
  {
    "id": "ch_01JABCDEF",
    "name": "ops-email",
    "channel_type": "email",
    "description": "运维团队邮件通道",
    "min_severity": "warning",
    "enabled": true,
    "recipient_type": "email",
    "recipients": ["ops@example.com", "admin@example.com"],
    "created_at": "2026-02-10T10:00:00Z",
    "updated_at": "2026-02-10T10:00:00Z"
  }
]
```

#### `GET /v1/notifications/channels/config`

列出持久化的通知渠道配置（原始 DB 行数据）。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/notifications/channels/config
```

#### `POST /v1/notifications/channels/config`

创建通知渠道。`config_json` 字段包含渠道类型特定配置（邮件的 SMTP 设置、短信的网关 URL 等）。创建时可同时设置收件人。

```bash
curl -X POST http://localhost:8080/v1/notifications/channels/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ops-email",
    "channel_type": "email",
    "description": "运维团队邮件告警",
    "min_severity": "warning",
    "config_json": "{\"smtp_host\":\"smtp.example.com\",\"smtp_port\":587,\"from\":\"alerts@example.com\"}",
    "recipients": ["ops@example.com"]
  }'
```

各渠道类型的 `config_json` 字段：

| 类型 | 必填配置 | 可选配置 |
|------|---------|---------|
| `email` | `smtp_host`, `smtp_port`, `from` | `smtp_username`, `smtp_password` |
| `webhook` | （无） | `body_template` |
| `sms` | `gateway_url`, `api_key` | — |
| `dingtalk` | `webhook_url` | `secret` |
| `weixin` | `webhook_url` | — |

各渠道对应的收件人类型：

| 渠道 | 收件人类型 | 示例 |
|------|-----------|------|
| `email` | 邮箱地址 | `admin@example.com` |
| `sms` | 手机号 | `+8613800138000` |
| `webhook` | URL | `https://hooks.slack.com/services/xxx` |
| `dingtalk` | Webhook URL | `https://oapi.dingtalk.com/robot/send?access_token=...` |
| `weixin` | Webhook URL | `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...` |

#### `PUT /v1/notifications/channels/config/{id}`

更新通知渠道配置（部分更新）。修改后立即通过热重载生效。

```bash
curl -X PUT http://localhost:8080/v1/notifications/channels/config/<id> \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"min_severity": "critical", "enabled": false}'
```

#### `DELETE /v1/notifications/channels/config/{id}`

删除通知渠道及其收件人。

```bash
curl -X DELETE http://localhost:8080/v1/notifications/channels/config/<id> \
  -H "Authorization: Bearer $TOKEN"
```

#### `POST /v1/notifications/channels/{id}/test`

发送测试通知到指定渠道，验证配置是否正常。使用该渠道当前的收件人列表。

```bash
curl -X POST http://localhost:8080/v1/notifications/channels/<id>/test \
  -H "Authorization: Bearer $TOKEN"
```

#### `PUT /v1/notifications/channels/{id}/recipients`

设置（替换）渠道的收件人列表。

```bash
curl -X PUT http://localhost:8080/v1/notifications/channels/<id>/recipients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"recipients": ["admin@example.com", "ops@example.com"]}'
```

#### `GET /v1/notifications/channels/{id}/recipients`

获取渠道的当前收件人列表。

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/v1/notifications/channels/<id>/recipients
```

### 静默窗口

静默窗口在维护期间抑制通知发送，通过 REST API 管理，存储在数据库中。

#### `GET /v1/notifications/silence-windows`

列出所有静默窗口。

| 参数 | 说明 | 必填 |
|------|------|------|
| `limit` | 每页条数（默认 20） | 否 |
| `offset` | 偏移量（默认 0） | 否 |

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/notifications/silence-windows
```

#### `POST /v1/notifications/silence-windows`

创建静默窗口。

```bash
curl -X POST http://localhost:8080/v1/notifications/silence-windows \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"start_time": "02:00", "end_time": "04:00", "recurrence": "daily"}'
```

#### `DELETE /v1/notifications/silence-windows/{id}`

删除静默窗口。

```bash
curl -X DELETE http://localhost:8080/v1/notifications/silence-windows/<id> \
  -H "Authorization: Bearer $TOKEN"
```

### 仪表盘

#### `GET /v1/dashboard/overview`

获取综合仪表盘概览，包含 Agent 状态、告警摘要、证书健康状态和存储信息。

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/dashboard/overview
```

响应示例：

```json
{
  "active_agents": 5,
  "total_agents": 8,
  "alerts_24h": 42,
  "alerts_by_severity": {"critical": 3, "warning": 15, "info": 24},
  "cert_summary": {"total_domains": 10, "valid": 8, "invalid": 1, "expiring_soon": 1},
  "partition_count": 7,
  "storage_total_bytes": 52428800,
  "uptime_secs": 86400
}
```

### 系统管理

#### `GET /v1/system/config`

获取运行时服务端配置（敏感字段已脱敏）。

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/system/config
```

#### `GET /v1/system/storage`

获取存储分区信息（文件列表、大小）。

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/system/storage
```

响应示例：

```json
{
  "partitions": [
    {"date": "2026-02-10", "size_bytes": 8388608},
    {"date": "2026-02-09", "size_bytes": 7340032}
  ],
  "total_partitions": 2,
  "total_size_bytes": 15728640
}
```

#### `POST /v1/system/storage/cleanup`

手动触发按保留策略的存储清理。

```bash
curl -X POST http://localhost:8080/v1/system/storage/cleanup \
  -H "Authorization: Bearer $TOKEN"
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

### 参数命名约定

为统一各接口过滤语义，查询参数采用 `字段__操作符` 形式：

- `__eq`：精确匹配（示例：`agent_id__eq=web-server-01`）
- `__contains`：包含匹配（示例：`issuer__contains=Let%27s%20Encrypt`）
- `__gte`：下界，大于等于（示例：`timestamp__gte=2026-02-09T00:00:00Z`）
- `__lte`：上界，小于等于（示例：`timestamp__lte=2026-02-09T23:59:59Z`）

列表接口分页参数统一为：

- `limit`：每页条数（默认 `20`）
- `offset`：偏移量（默认 `0`）


## 统一响应格式

所有 REST API 统一返回如下 JSON 包裹：

```json
{
  "err_code": 0,
  "err_msg": "success",
  "trace_id": "",
  "data": {}
}
```

- `err_code`：整型错误码（`0` 表示成功，非 `0` 表示自定义失败错误码）
- `err_msg`：错误或成功信息
- `trace_id`：链路追踪 ID（当前默认空字符串）
- `data`：业务数据（无返回数据时为 `null`）

失败响应的 `err_code` 使用自定义业务错误码（不是 HTTP 状态码）。

## 错误码表

| err_code | 标识名 | 说明 |
|----------|--------|------|
| 0 | OK | 成功 |
| 1001 | BAD_REQUEST | 请求参数错误 |
| 1002 | UNAUTHORIZED | 未认证或无权限 |
| 1003 | TOKEN_EXPIRED | JWT Token 已过期 |
| 1004 | NOT_FOUND | 资源不存在 |
| 1005 | CONFLICT | 资源冲突 |
| 1101 | duplicate_domain | 域名已存在 |
| 1102 | invalid_domain | 域名参数非法 |
| 1103 | invalid_port | 端口参数非法 |
| 1104 | empty_batch | 批量请求为空 |
| 1105 | no_results | 暂无检查结果 |
| 1500 | INTERNAL_ERROR | 服务内部错误 |
| 1501 | storage_error | 存储层错误 |
| 1999 | unknown | 未知自定义错误 |

## 测试覆盖策略

- 接口矩阵测试：每个 API 覆盖成功、鉴权失败、参数/业务分支失败场景。
- 真实 Agent 模拟：通过 gRPC `ReportMetrics` 的真实 metadata + payload 路径验证链路。
- OpenAPI 契约守卫：若 OpenAPI 暴露了新接口但测试矩阵未覆盖，CI 直接失败。

另见：[`docs/api-improvement-plan.md`](api-improvement-plan.md)
