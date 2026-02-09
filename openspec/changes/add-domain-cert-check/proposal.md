## Why

域名 TLS 证书过期是生产环境中常见的运维事故——证书失效后网站无法正常访问，而往往到用户报障时才发现。oxmon 当前仅监控系统级指标（CPU、内存、磁盘、网络、负载），缺少对域名证书有效性和过期时间的主动检测能力。增加证书检测可以提前告警，避免证书过期导致的服务中断。

## What Changes

- 证书检测运行在 **Server 端**（证书检测是网络操作，无需绑定特定主机），Server 定期检测所有已注册域名的证书状态
- 新增 REST API 管理监控域名（CRUD），支持动态添加/删除/查询任意数量的域名，域名列表持久化到 SQLite
- 每个域名可配置自定义端口（默认 443）和检测间隔
- 新增证书检测引擎，定期连接目标域名获取证书信息，产出证书相关指标（剩余天数、是否有效、证书链是否完整）
- 检测结果作为标准指标写入存储，复用现有告警引擎（阈值规则）实现提前告警
- 通过现有通知渠道（邮件/Webhook/短信）发送证书告警通知

## Capabilities

### New Capabilities

- `cert-domain-api`: 域名管理 REST API，提供 CRUD 接口管理待监控域名列表，支持批量添加，域名数据持久化到 SQLite
- `cert-checker`: 证书检测引擎，运行在 Server 端，定期从数据库读取域名列表，逐一连接目标域名的 TLS 端口获取证书信息，产出 `certificate.days_until_expiry`、`certificate.is_valid`、`certificate.chain_valid` 等指标，以域名作为 label 区分

### Modified Capabilities

- `metric-storage`: 新增 `cert_domains` 表存储待监控域名列表（域名、端口、启用状态、创建时间等）
- `dashboard-api`: REST API 路由中增加证书域名管理和证书状态查询的端点

## Impact

- **代码**: 新增 `oxmon-cert` crate（或在 `oxmon-server` 中新增模块）实现证书检测引擎；修改 `oxmon-storage` 增加域名表；修改 `oxmon-server` 增加 API 路由和检测调度
- **依赖**: 引入 `rustls` + `x509-parser`（或 `webpki`）用于 TLS 连接和证书解析，项目已使用 rustls 生态，兼容性好
- **数据库**: SQLite 新增 `cert_domains` 表（域名、端口、启用状态、备注、创建/更新时间）和 `cert_check_results` 表（检测结果历史）
- **API**: 新增 `/v1/certs/domains` (CRUD) 和 `/v1/certs/status` (查询检测结果) 端点
- **告警**: 复用现有阈值告警规则，配置 `certificate.days_until_expiry` 指标的规则即可，无需修改告警引擎
