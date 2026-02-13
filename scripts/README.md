# 初始化和管理脚本

## 统一重置脚本（推荐）⭐

`reset.sh` 是统一的重置和初始化脚本，支持两种模式：

### 模式 1: 只清理配置（保留监控数据）

```bash
./scripts/reset.sh config
```

这个模式会：
- ✅ 通过 REST API 登录
- ✅ 删除所有现有的告警规则
- ✅ 删除所有现有的通知渠道
- ✅ 删除所有静默窗口
- ✅ 自动重新初始化（使用 CLI）
- ✅ 保留监控历史数据

### 模式 2: 完全重置（删除所有数据）

```bash
./scripts/reset.sh full
```

这个模式会：
- ✅ 停止正在运行的服务器
- ✅ 删除整个数据目录（包括所有历史数据）
- ✅ 重新创建空的数据目录

然后启动服务器，自动初始化将生效：
- 9 条默认告警规则（已启用）
- 7 个默认通知渠道（已禁用，需要配置后启用）
- 默认管理员账号：`admin / changeme`

### 环境变量

可以通过环境变量自定义配置：

```bash
# 使用自定义 API 地址
API_BASE=http://localhost:9090/v1 ./scripts/reset.sh config

# 使用自定义配置文件
CONFIG_FILE=config/prod.toml ./scripts/reset.sh config

# 使用自定义数据目录
DATA_DIR=/var/lib/oxmon ./scripts/reset.sh full

# 使用自定义管理员账号
USERNAME=root PASSWORD=secret ./scripts/reset.sh config
```

### 帮助信息

```bash
./scripts/reset.sh --help
```

## 使用 CLI 命令初始化

### 初始化告警规则

```bash
cargo build --release
./target/release/oxmon-server init-rules config/server.toml config/rules.seed.example.json
```

### 初始化通知渠道

```bash
cargo build --release
./target/release/oxmon-server init-channels config/server.toml config/channels.seed.example.json
```

### 初始化系统字典

```bash
cargo build --release
./target/release/oxmon-server init-dictionaries config/server.toml config/dictionaries.seed.example.json
```

## 默认初始化内容

### 告警规则（9 条）

服务器首次启动时，如果数据库为空，会自动创建：

| 规则名称 | 类型 | 指标 | 阈值 | 严重级别 |
|---------|------|------|------|----------|
| CPU 使用率严重告警 | threshold | cpu.usage | >90% (60s) | critical |
| CPU 使用率警告 | threshold | cpu.usage | >80% (120s) | warning |
| 内存使用率严重告警 | threshold | memory.usage | >95% (60s) | critical |
| 内存使用率警告 | threshold | memory.usage | >85% (120s) | warning |
| 内存使用率突增 | rate_of_change | memory.usage | +20%/5min | warning |
| 磁盘使用率严重告警 | threshold | disk.usage | >95% | critical |
| 磁盘使用率警告 | threshold | disk.usage | >85% | warning |
| 磁盘空间趋势预测 | trend_prediction | disk.usage | 预测24h后>95% | warning |
| SSL 证书即将过期 | cert_expiration | cert.expiration | <30天 | warning |

### 通知渠道（7 个）

所有渠道默认为 **禁用** 状态，需要配置后启用：

| 渠道名称 | 类型 | 最低严重级别 | 状态 |
|---------|------|-------------|------|
| 默认邮件通知 | email | warning | 禁用 |
| 默认 Webhook 通知 | webhook | warning | 禁用 |
| 默认钉钉通知 | dingtalk | warning | 禁用 |
| 默认企业微信通知 | weixin | warning | 禁用 |
| 默认阿里云短信 | sms_aliyun | critical | 禁用 |
| 默认腾讯云短信 | sms_tencent | critical | 禁用 |
| 默认通用短信 | sms_generic | critical | 禁用 |

## REST API 管理

启动服务器后，可以通过 REST API 管理：

### 查看所有告警规则

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/alerts/rules
```

### 查看所有通知渠道

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/notifications/channels
```

### 启用/禁用告警规则

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}' \
  http://localhost:8080/v1/alerts/rules/{rule_id}/enable
```

### 启用/禁用通知渠道

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "默认邮件通知", "channel_type": "email", "enabled": true, ...}' \
  http://localhost:8080/v1/notifications/channels/config/{channel_id}
```

详细 API 文档：http://localhost:8080/openapi.json
