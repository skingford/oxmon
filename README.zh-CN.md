[English](README.md) | 中文

# oxmon

轻量级服务器监控系统，使用 Rust 构建。采集系统指标（CPU、内存、磁盘、网络、负载），存储时序数据，评估告警规则，并通过多种渠道发送通知。

## 目录

- [架构](#架构)
- [Crate 结构](#crate-结构)
- [快速开始](#快速开始)
- [本地联调（模拟上报 + 接口校验）](#本地联调模拟上报--接口校验)
- [配置说明](#配置说明)
- [采集指标列表](#采集指标列表)
- [API Reference](#api-reference)
- [Linux 快速部署](#linux-快速部署)
- [Docker 部署](#docker-部署)
- [License](#license)

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

## 本地联调（模拟上报 + 接口校验）

仓库内置了 3 个联调脚本：

- `scripts/mock-report-all.sh`：上报全场景测试数据（正常 + 告警触发）
- `scripts/mock-query-check.sh`：校验核心读取接口并输出摘要表
- `scripts/mock-e2e.sh`：一键串联“上报 + 校验”

### 1）一键 E2E（推荐）

```bash
# 默认跑 all 场景，完成上报后自动校验接口
scripts/mock-e2e.sh

# 服务端开启 require_agent_auth=true 时
scripts/mock-e2e.sh --auto-auth --username admin --password changeme
```

### 2）分步执行（便于排查）

```bash
# 第一步：上报所有场景
scripts/mock-report-all.sh --scenario all --agent-count 5

# 第二步：校验 metrics / alerts / dashboard
scripts/mock-query-check.sh
```

### 3）只跑单一场景

```bash
# 仅触发 rate_of_change 场景
scripts/mock-report-all.sh --scenario rate

# 仅触发 trend_prediction 场景
scripts/mock-report-all.sh --scenario trend
```

支持场景：`all`、`baseline`、`threshold`、`rate`、`trend`、`cert`。

### 4）常用参数

```bash
# 上报阶段打印每个批次摘要
scripts/mock-report-all.sh --print-payload

# 校验阶段打印接口原始响应
scripts/mock-query-check.sh --verbose

# 指定 metrics/summary 的查询目标
scripts/mock-query-check.sh --summary-agent mock-threshold --summary-metric cpu.usage
```

### 5）token 文件格式（可选）

当你不使用 `--auto-auth`，但服务端要求 Agent 认证时，可以传 token 映射文件：

```ini
mock-normal-01=token_xxx
mock-normal-02=token_yyy
mock-threshold=token_zzz
mock-rate=token_aaa
mock-trend=token_bbb
cert-checker=token_ccc
```

然后执行：

```bash
scripts/mock-report-all.sh --auth-token-file ./tokens.env
```

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

#### 告警规则（数据库存储，API 管理）

告警规则存储在数据库中，通过 REST API 或 CLI 动态管理。支持四种规则类型：`threshold`（阈值）、`rate_of_change`（变化率）、`trend_prediction`（趋势预测）、`cert_expiration`（证书过期）。

**初始化**使用 `init-rules` CLI 子命令和 JSON 种子文件：

```bash
oxmon-server init-rules config/server.toml config/rules.seed.json
```

规则配置示例见 `config/rules.seed.example.json`，包括：
- **阈值告警 (threshold)** — 指标持续超过阈值时触发
- **变化率告警 (rate_of_change)** — 指标在时间窗口内变化超过百分比时触发
- **趋势预测告警 (trend_prediction)** — 通过线性回归预测指标何时突破阈值
- **证书过期告警 (cert_expiration)** — 根据证书剩余有效天数触发分级告警

重复运行时，同名规则会被跳过。初始化完成后，使用 REST API (`/v1/alerts/rules`) 管理规则。CRUD 操作触发立即热重载，无需重启服务。

详细接口文档见 [API 接口文档](#api-reference)。

#### 通知渠道（数据库存储，API 管理）

通知渠道存储在数据库中，通过 REST API 动态管理。每种渠道类型支持**创建多个实例**（例如：为运维团队和开发团队分别配置不同的邮件渠道）。收件人（邮箱、手机号、Webhook URL）按渠道独立管理。

**初始化**使用 `init-channels` CLI 子命令和 JSON 种子文件：

```bash
oxmon-server init-channels config/server.toml config/channels.seed.json
```

模板文件见 `config/channels.seed.example.json`。重复运行时，同名渠道会被跳过。初始化完成后，使用 REST API (`/v1/notifications/channels`) 管理渠道、收件人和发送测试通知。

内置渠道类型：`email`、`webhook`、`sms`、`dingtalk`、`weixin`。

**各渠道配置参考：**

| 类型 | 必填配置 | 收件人类型 |
|------|---------|-----------|
| `email` | `smtp_host`, `smtp_port`, `from_name`, `from_email` | 邮箱地址 |
| `webhook` | （无） | URL |
| `sms` | `gateway_url`, `api_key` | 手机号 |
| `dingtalk` | `webhook_url` | Webhook URL |
| `weixin` | `webhook_url` | Webhook URL |

钉钉支持可选的 `secret` 用于 HMAC-SHA256 签名。Webhook 支持可选的 `body_template`，可使用 `{{agent_id}}`、`{{metric}}`、`{{value}}`、`{{severity}}`、`{{message}}` 变量。

> **插件系统**：每种渠道是一个独立的 `ChannelPlugin`，通过 `ChannelRegistry` 动态查找和实例化。配置变更触发热重载，无需重启服务。

#### 静默窗口（数据库存储，API 管理）

在维护时段抑制通知发送，通过 REST API (`/v1/notifications/silence-windows`) 管理。

#### 运行时设置（数据库存储）

运行时参数如告警聚合、日志保留等存储在数据库（`system_configs` 表）中，通过 REST API (`/v1/system/configs`) 管理。默认值在首次启动时自动初始化：
- `aggregation_window_secs`: 60（秒，窗口内的同类告警合并为一条通知）
- `log_retention_days`: 30（通知日志保留天数）

#### 系统字典（数据库存储）

集中管理系统常量枚举（渠道类型、严重级别、规则类型、告警状态等）。存储在数据库（`system_dictionaries` 表）中，通过 REST API (`/v1/dictionaries`) 或 CLI 管理。

**初始化**使用 `init-dictionaries` CLI 子命令和 JSON 种子文件：

```bash
oxmon-server init-dictionaries config/server.toml config/dictionaries.seed.json
```

默认种子数据（约 50 条）见 `config/dictionaries.seed.example.json`。表为空时，首次启动会自动初始化默认字典。

可用字典类型：`channel_type`、`severity`、`rule_type`、`alert_status`、`agent_status`、`compare_operator`、`metric_name`、`rule_source`、`recipient_type`。系统内置项受保护，不可删除。

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

<a id="api-reference"></a>

## API 接口文档

REST API 已从 README 抽离到独立说明：

- 中文版：[`docs/api-reference.zh-CN.md`](docs/api-reference.zh-CN.md)
- English: [`docs/api-reference.md`](docs/api-reference.md)

OpenAPI 端点保持不变：

| 端点 | 格式 |
|------|------|
| `GET /v1/openapi.json` | JSON 格式 |
| `GET /v1/openapi.yaml` | YAML 格式 |

Apifox/Postman/Swagger 快速导入 URL：`http://<server-ip>:8080/v1/openapi.json`

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

-- 例子
sqlite3 2026-02-09.db 
sqlite3 2026-02-09.db .tables
sqlite3 2026-02-09.db ".schema metrics"
sqlite3 -header -column 2026-02-09.db "SELECT * FROM metrics LIMIT 1;"
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

| 平台 | 说明 |
|------|------|
| `x86_64-linux` | Linux AMD64 |
| `aarch64-linux` | Linux ARM64 |
| `x86_64-macos` | macOS Intel |
| `aarch64-macos` | macOS Apple Silicon |

> 发布产物使用简化的平台名称（如 `x86_64-linux`）。内部 Rust 构建使用标准目标三元组（如 `x86_64-unknown-linux-gnu`）。

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

### GitHub Release 发布流程

```bash
# 1）同步 main 分支并确认测试通过
git checkout main
git pull --ff-only
cargo test --workspace

# 2）更新版本号
# 修改 Cargo.toml: [workspace.package].version = "0.1.2"
cargo check --workspace

# 3）提交版本文件
git add Cargo.toml Cargo.lock
git commit -m "chore(release): bump version to 0.1.2"

# 4）创建并推送 tag
git tag -a v0.1.2 -m "v0.1.2"
git push origin main
git push origin v0.1.2
```

也可以使用辅助脚本（不传版本时自动 patch +1）：

```bash
# 自动递增 patch（如 0.1.1 -> 0.1.2），并完成 commit + tag
./scripts/release.sh

# 指定版本并自动推送
./scripts/release.sh --version 0.1.2 --push
```

- 推送 `v*` tag 后会自动触发 `.github/workflows/release.yml`。
- 工作流成功后，请在 GitHub Releases 检查产物（`oxmon-agent-*` / `oxmon-server-*` 压缩包和 `SHA256SUMS`）。
- Linux 升级可直接重复执行安装命令（默认拉取 `latest`）。

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
