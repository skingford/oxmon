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
│ └──────────────┘ │                │ │ Engine │─────────→│ Email/     │  │
└──────────────────┘                │ └────────┘          │ Webhook/   │  │
                                    │                     │ SMS        │  │
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
| `oxmon-notify` | 通知渠道（邮件、Webhook、短信） |
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
./target/release/oxmon-server config/server.toml
```

Server 启动后监听 gRPC 端口 9090 和 REST API 端口 8080（可配置）。

### 4. 启动采集端

```bash
./target/release/oxmon-agent config/agent.toml
```

Agent 每 10 秒（可配置）采集一次系统指标，通过 gRPC 上报给 Server。

## 配置说明

### Agent 配置 (`agent.toml`)

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `agent_id` | 该节点唯一标识，用于区分不同服务器 | `"web-server-01"` |
| `server_endpoint` | Server 的 gRPC 地址 | `"http://127.0.0.1:9090"` |
| `collection_interval_secs` | 指标采集间隔（秒） | `10` |
| `buffer_max_size` | Server 不可达时本地缓冲的最大批次数 | `1000` |

示例：

```toml
agent_id = "web-server-01"
server_endpoint = "http://10.0.1.100:9090"
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

#### 告警规则 (`[[alert.rules]]`)

支持三种规则类型：

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
recipients = ["+8613800138000"]
```

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

## REST API

### `GET /api/v1/health`

健康检查，返回服务端状态。

```bash
curl http://localhost:8080/api/v1/health
```

### `GET /api/v1/agents`

列出所有已注册的 Agent。

```bash
curl http://localhost:8080/api/v1/agents
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

### `GET /api/v1/agents/:id/latest`

获取指定 Agent 的最新指标值。

```bash
curl http://localhost:8080/api/v1/agents/web-server-01/latest
```

### `GET /api/v1/metrics`

查询时序数据。

| 参数 | 说明 | 必填 |
|------|------|------|
| `agent` | Agent ID | 是 |
| `metric` | 指标名 | 是 |
| `from` | 起始时间 (ISO 8601) | 是 |
| `to` | 结束时间 (ISO 8601) | 是 |

```bash
curl "http://localhost:8080/api/v1/metrics?agent=web-server-01&metric=cpu.usage&from=2026-02-06T00:00:00Z&to=2026-02-06T23:59:59Z"
```

### `GET /api/v1/alerts/rules`

列出所有已配置的告警规则。

```bash
curl http://localhost:8080/api/v1/alerts/rules
```

### `GET /api/v1/alerts/history`

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
curl "http://localhost:8080/api/v1/alerts/history?severity=critical&limit=50"
```

## Docker 部署

### 构建镜像

```bash
docker build -f Dockerfile.server -t oxmon-server .
docker build -f Dockerfile.agent -t oxmon-agent .
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
7. **通知** — 按严重级别路由到对应渠道（邮件/Webhook/短信），静默窗口内不发送

## License

MIT
