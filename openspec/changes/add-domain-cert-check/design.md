## Context

oxmon 当前仅通过 Agent 采集系统级指标（CPU/内存/磁盘/网络/负载），缺乏域名证书监控能力。证书检测是网络操作，不依赖特定主机的系统信息，因此适合放在 Server 端执行。Server 已具备 SQLite 存储、REST API（axum）、告警引擎和通知系统，新功能可最大程度复用现有基础设施。

现有架构关键约束：
- 存储层使用按天分区的 SQLite（`PartitionManager`），每个分区独立创建表
- REST API 使用 axum + `AppState`（`Arc<SqliteStorageEngine>` 等）
- 周期任务使用 `tokio::time::interval` + `tokio::spawn`
- 告警引擎基于滑动窗口评估 `MetricDataPoint`

## Goals / Non-Goals

**Goals:**

- Server 端定期检测所有已注册域名的 TLS 证书状态
- 提供 REST API 动态管理监控域名（CRUD），支持任意数量域名
- 检测结果写入标准指标存储，复用现有告警和通知链路
- 支持自定义端口（默认 443）、启用/禁用单个域名、每域名独立检测间隔

**Non-Goals:**

- 不做客户端证书（mTLS）检测
- 不做 OCSP stapling 或 CRL 检查
- 不支持 Agent 端证书检测（仅 Server 端）
- 不做证书自动续签

## Decisions

### 1. 证书域名存储：独立全局表 vs 分区表

**选择：独立全局 SQLite 数据库文件**

域名列表是配置性数据，不是时序数据，不适合放在按天分区的表中。在 `data_dir` 下创建独立的 `cert.db` 文件，包含 `cert_domains` 表。

替代方案：放入分区表——会导致域名数据分散在多个分区中，查询和更新都不方便。

### 2. 检测结果存储：标准指标 vs 独立表

**选择：双写——独立结果表 + 标准指标**

- `cert_check_results` 表（在 `cert.db` 中）存储完整检测结果（证书颁发者、有效期、SAN 列表等详细信息），供 API 查询
- 同时将关键数值（`certificate.days_until_expiry`、`certificate.is_valid`）作为标准 `MetricDataPoint` 写入分区存储，供告警引擎评估

替代方案：仅写标准指标——会丢失证书详细信息（颁发者、SAN 等），API 无法返回结构化的证书状态。

### 3. TLS 连接和证书解析依赖

**选择：`rustls` + `x509-parser`**

- `rustls`：项目已全面使用 rustls 生态（reqwest、lettre），无需引入 OpenSSL
- `x509-parser`：纯 Rust 的 X.509 证书解析库，可提取有效期、颁发者、SAN 等字段
- 使用 `tokio-rustls` 进行异步 TLS 连接

替代方案：`native-tls`——会重新引入 OpenSSL 系统依赖，破坏交叉编译支持。

### 4. 检测调度：全局默认间隔 + 每域名可覆盖

**选择：全局默认间隔 + 每域名可配独立间隔**

`server.toml` 中配置全局默认值，每个域名可通过 API 设置独立的 `check_interval_secs` 覆盖全局默认值。调度器采用统一的 tick 循环（tick 间隔为全局 `tick_secs`，默认 60s），每次 tick 时遍历域名列表，检查距上次检测是否已超过该域名的检测间隔，满足条件才发起检测。

在 `server.toml` 中增加 `[cert_check]` 配置段：

```toml
[cert_check]
enabled = true
default_interval_secs = 86400 # 全局默认检测间隔，默认 24 小时
tick_secs = 60                # 调度器 tick 间隔，默认 60 秒
connect_timeout_secs = 10     # TLS 连接超时
max_concurrent = 10           # 最大并发检测数
```

每个域名通过 API 创建/更新时可指定 `check_interval_secs`，为 `null` 时使用全局默认值。

证书有效期通常以月为单位，每天检测一次足以提前发现即将过期的证书。对于临近过期的重要域名，可通过 API 单独设置更短的间隔（如数小时）。

替代方案：仅全局固定间隔——无法对重要域名设置更频繁的检测频率，对不重要的域名无法降低检测频率以节省资源。

### 5. 代码组织：新 crate vs Server 内模块

**选择：在 `oxmon-server` 中新增 `cert` 模块**

证书检测与 Server 的存储、告警、通知紧密耦合，独立 crate 会增加不必要的接口抽象。模块结构：

```
oxmon-server/src/
├── cert/
│   ├── mod.rs          # 模块入口
│   ├── checker.rs      # TLS 连接 + 证书解析逻辑
│   ├── scheduler.rs    # 定期检测调度
│   └── api.rs          # 域名管理 REST API handlers
```

存储相关：在 `oxmon-storage` 中新增 `cert_store.rs`，封装 `cert.db` 的操作。

### 6. API 设计

```
POST   /v1/certs/domains          添加域名（支持单个或批量）
GET    /v1/certs/domains          查询域名列表（支持分页、状态过滤）
GET    /v1/certs/domains/:id      查询单个域名详情
PUT    /v1/certs/domains/:id      更新域名配置（端口、启用状态、检测间隔）
DELETE /v1/certs/domains/:id      删除域名
GET    /v1/certs/status           查询所有域名最新检测结果
GET    /v1/certs/status/:domain   查询单个域名检测结果
```

### 7. 数据库 Schema

**cert_domains 表：**

| 字段 | 类型 | 说明 |
|------|------|------|
| id | TEXT PK | UUID |
| domain | TEXT NOT NULL UNIQUE | 域名 |
| port | INTEGER | 端口，默认 443 |
| enabled | INTEGER | 1=启用 0=禁用 |
| check_interval_secs | INTEGER | 检测间隔（秒），NULL 时使用全局默认值 |
| note | TEXT | 备注 |
| last_checked_at | INTEGER | 上次检测时间戳，调度器据此判断是否到期 |
| created_at | INTEGER | 创建时间戳 |
| updated_at | INTEGER | 更新时间戳 |

**cert_check_results 表：**

| 字段 | 类型 | 说明 |
|------|------|------|
| id | TEXT PK | UUID |
| domain_id | TEXT FK | 关联 cert_domains.id |
| domain | TEXT | 域名（冗余，便于查询） |
| is_valid | INTEGER | 1=有效 0=无效 |
| chain_valid | INTEGER | 1=链完整 0=不完整 |
| not_before | INTEGER | 证书生效时间 |
| not_after | INTEGER | 证书过期时间 |
| days_until_expiry | INTEGER | 剩余天数 |
| issuer | TEXT | 颁发者 |
| subject | TEXT | 主体 |
| san_list | TEXT | SAN 列表（JSON 数组） |
| error | TEXT | 检测失败时的错误信息 |
| checked_at | INTEGER | 检测时间戳 |

## Risks / Trade-offs

**[大量域名并发检测导致连接风暴]** → 串行检测或限制并发数（如 `tokio::sync::Semaphore` 限制为 10 个并发连接），单次检测轮次超时则跳过剩余域名

**[目标域名不可达导致检测阻塞]** → 每个连接设置 `connect_timeout_secs`（默认 10s），超时记录为检测失败而非阻塞整个检测循环

**[cert.db 与分区存储一致性]** → 检测结果双写（cert.db 详情 + 分区指标），两者独立，cert.db 故障不影响主指标存储

**[域名删除后残留指标数据]** → 不主动清理历史指标（与其他指标一致，由 retention_days 统一管理），删除域名仅停止后续检测

**[rustls 不信任某些证书链]** → rustls 默认使用 `webpki-roots`（Mozilla 根证书），覆盖绝大多数公共 CA；如需自签证书支持可后续扩展
