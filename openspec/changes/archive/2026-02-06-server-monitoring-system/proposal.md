## Why

服务器运维中，内存泄漏、磁盘满、CPU 飙高等异常往往在造成宕机后才被发现，导致业务中断和数据丢失。需要一套轻量级的服务器监控系统，能够实时采集关键指标、基于阈值和趋势进行智能预警，并通过多种通道（邮件、Webhook、短信等）提前告警，将故障扼杀在萌芽阶段。

## What Changes

- 新增 Agent 端：部署在被监控服务器上，定时采集 CPU、内存、磁盘、网络、系统负载等指标，上报至 Server 端
- 新增 Server 端：接收并存储指标数据，提供 REST API 查询，执行告警规则引擎
- 新增告警引擎：支持静态阈值告警和基于趋势的预测性告警（如磁盘使用量线性增长预测何时满）
- 新增多通道通知：支持邮件、Webhook（飞书/钉钉/Slack）、短信等告警通知方式，支持告警分级和静默策略
- 新增 Dashboard API：提供指标查询和告警历史查询接口，供前端或第三方系统对接

## Capabilities

### New Capabilities

- `metric-collection`: Agent 端指标采集能力，覆盖 CPU、内存、磁盘、网络、系统负载等核心指标的定时采集与上报
- `metric-storage`: Server 端指标接收与存储能力，支持时序数据的高效写入与查询
- `alert-engine`: 告警规则引擎，支持静态阈值规则、变化率规则和趋势预测规则的配置与评估
- `notification`: 多通道告警通知能力，支持邮件、Webhook、短信等通道的统一发送与告警分级/静默策略
- `dashboard-api`: Dashboard 数据查询 API，提供指标数据和告警历史的 REST 查询接口

### Modified Capabilities

（无现有 capability 需要修改）

## Impact

- **新增代码**：Rust 实现的 Agent 二进制（部署到被监控机器）和 Server 二进制（中心化服务）
- **依赖**：时序数据库（如 SQLite + 自定义时序格式，或嵌入式方案）、SMTP 库、HTTP 客户端库
- **部署**：Agent 需部署到每台被监控服务器，Server 作为独立服务运行
- **API**：新增 REST API（指标上报、指标查询、告警规则管理、告警历史查询）
- **配置**：Agent 和 Server 均需配置文件（YAML/TOML），包含采集间隔、上报地址、告警规则、通知通道等
