## Context

oxmon 是一个全新的 Rust 项目，目标是构建轻量级服务器监控系统。项目采用 Agent-Server 架构：Agent 部署在被监控机器上采集指标，Server 作为中心化服务负责存储、告警和 API。当前项目为空白状态，无历史代码和技术债务。

约束条件：
- 语言：Rust，追求低资源占用和高性能
- Agent 必须足够轻量，不能对被监控服务器造成明显负担
- Server 需支持单机部署，初期不引入重量级外部依赖（如 Kafka、InfluxDB）

## Goals / Non-Goals

**Goals:**

- Agent 能在 Linux/macOS 上采集 CPU、内存、磁盘、网络、系统负载指标
- Agent 定时上报指标到 Server，支持断线重连和本地缓存
- Server 持久化存储时序指标数据，支持按时间范围查询
- 告警引擎支持静态阈值、变化率、趋势预测三种规则类型
- 支持邮件、Webhook、短信三种通知通道，支持告警分级（info/warning/critical）和静默策略
- 提供 REST API 供外部查询指标和告警历史

**Non-Goals:**

- 不做前端 Dashboard UI（仅提供 API）
- 不做分布式 Server 集群（初期单机部署）
- 不做日志采集和分析（仅关注 metrics）
- 不做 APM / 应用级监控（仅关注系统级指标）
- 不做自动修复 / 自愈功能

## Decisions

### 1. 项目结构：Cargo Workspace

**决定**：使用 Cargo workspace 管理多个 crate。

```
oxmon/
├── Cargo.toml              # workspace root
├── crates/
│   ├── oxmon-agent/        # Agent 二进制
│   ├── oxmon-server/       # Server 二进制
│   ├── oxmon-common/       # 共享类型、协议定义、序列化
│   ├── oxmon-collector/    # 指标采集逻辑（Agent 调用）
│   ├── oxmon-storage/      # 时序数据存储引擎（Server 调用）
│   ├── oxmon-alert/        # 告警规则引擎（Server 调用）
│   └── oxmon-notify/       # 通知通道实现（Server 调用）
├── config/
│   ├── agent.example.toml
│   └── server.example.toml
```

**理由**：模块化拆分便于独立测试和复用，Agent 和 Server 编译为独立二进制，共享 common crate 保持协议一致。

**备选**：单一 crate + feature flags → 代码耦合度高，不利于 Agent 轻量化。

### 2. Agent-Server 通信协议：gRPC

**决定**：Agent 通过 gRPC 上报指标到 Server。

**理由**：
- Protocol Buffers 提供强类型和高效序列化，适合高频指标上报
- tonic 是 Rust 生态成熟的 gRPC 框架，性能优异
- 支持双向流，便于未来扩展（如 Server 推送配置变更到 Agent）

**备选**：
- HTTP + JSON → 序列化开销大，每次请求建立连接成本高
- MQTT → 引入额外 broker 依赖，增加部署复杂度

### 3. 时序数据存储：SQLite + 自定义时序分区

**决定**：使用 SQLite 作为底层存储引擎，按时间分区组织数据文件。

**理由**：
- 零外部依赖，Server 单二进制即可运行
- SQLite 在单机场景下写入性能足够（万级指标/秒）
- 按天/小时分区文件，便于数据过期清理（直接删除旧文件）

**备选**：
- InfluxDB → 功能强大但引入重量级外部依赖
- 纯文件 + 自定义格式 → 查询能力弱，需自行实现索引

### 4. 告警引擎架构：规则引擎 + 滑动窗口

**决定**：告警引擎基于滑动窗口进行规则评估，支持三种规则类型：

| 规则类型 | 说明 | 示例 |
|---------|------|------|
| 静态阈值 | 指标超过固定阈值触发 | CPU > 90% 持续 5 分钟 |
| 变化率 | 指标在时间窗口内变化率超阈值 | 内存使用 5 分钟内增长 > 20% |
| 趋势预测 | 线性回归预测指标到达阈值时间 | 磁盘使用量预计 24 小时内达到 95% |

**理由**：滑动窗口可避免瞬时抖动造成的误告警，趋势预测使用简单线性回归计算量小且效果直观。

### 5. 通知系统：Channel trait 抽象

**决定**：定义 `NotificationChannel` trait，每种通知方式实现该 trait。

```rust
#[async_trait]
pub trait NotificationChannel: Send + Sync {
    async fn send(&self, alert: &AlertEvent) -> Result<()>;
    fn channel_type(&self) -> ChannelType;
}
```

**理由**：trait 抽象使新增通知通道（如 Telegram、PagerDuty）只需实现一个 trait，无需修改核心逻辑。

### 6. 配置格式：TOML

**决定**：Agent 和 Server 配置均使用 TOML 格式。

**理由**：TOML 是 Rust 生态的事实标准（Cargo.toml），可读性好，serde 支持成熟。

### 7. HTTP API 框架：axum

**决定**：Server 的 REST API 使用 axum 框架。

**理由**：axum 基于 tokio，与 tonic（gRPC）共享同一个 tokio runtime，资源利用率高。类型安全的路由和提取器设计契合 Rust 风格。

**备选**：actix-web → 性能相当但生态兼容性不如 axum（tokio 原生）。

## Risks / Trade-offs

- **SQLite 并发写入限制** → 使用 WAL 模式 + 写入批量化（Agent 端攒批上报，Server 端批量插入）缓解。如果未来需要更高写入吞吐，可替换 storage crate 实现。
- **Agent 对宿主系统的影响** → Agent 限制内存使用（配置上限），采集间隔默认 10 秒避免频繁系统调用。设置采集超时防止异常挂起。
- **告警风暴** → 实现告警去重（相同规则在静默期内不重复发送）和告警聚合（多个同类告警合并为一条通知）。
- **趋势预测误报** → 线性回归对非线性变化场景会产生误判。初期仅作为辅助告警手段，默认告警级别设为 info。
- **跨平台兼容** → 指标采集依赖 `/proc` (Linux) 和 `sysctl` (macOS) 等系统接口。使用 sysinfo crate 抽象跨平台差异，但 Windows 支持初期不作优先级。

## Open Questions

- 是否需要支持自定义指标（用户通过 Agent 插件或 StatsD 协议上报业务指标）？
- 指标数据保留策略：默认保留多长时间？是否需要降采样（如 1 小时粒度保留 30 天）？
- 是否需要 Agent 自动发现（Server 端自动注册新 Agent）还是手动配置？
