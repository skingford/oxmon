# Agent Authentication Migration Guide

本指南说明如何为现有的 oxmon 部署启用 agent 认证功能。

## 概述

Agent 认证功能通过白名单机制保护 gRPC 端点，防止未授权的第三方向服务器上报数据。

## 迁移步骤

### 1. 更新服务器配置

编辑 `config/server.toml`，添加或修改以下配置：

```toml
# 启用 agent 认证（默认为 false，保持向后兼容）
require_agent_auth = false  # 先保持为 false，稍后启用
```

### 2. 重启服务器

```bash
# 重启服务器以加载新配置
./oxmon-server config/server.toml
```

### 3. 添加 Agent 到白名单

使用 REST API 为每个 agent 生成认证 token：

```bash
# 为 agent 添加到白名单
curl -X POST http://localhost:8080/api/v1/agents/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "web-server-01",
    "description": "Production web server"
  }'

# 响应示例：
# {
#   "agent_id": "web-server-01",
#   "token": "AbCdEf1234567890...",  # 保存此 token！
#   "created_at": "2024-01-01T00:00:00Z"
# }
```

**重要**: Token 只在创建时返回一次，请妥善保存！

### 4. 更新 Agent 配置

编辑每个 agent 的 `config/agent.toml`，添加 token：

```toml
# Agent 配置
agent_id = "web-server-01"
server_endpoint = "http://server-ip:9090"

# 添加认证 token
auth_token = "AbCdEf1234567890..."  # 使用步骤 3 中获取的 token

collection_interval_secs = 10
buffer_max_size = 1000
```

### 5. 重启所有 Agent

```bash
# 在每台 agent 机器上重启
./oxmon-agent config/agent.toml
```

### 6. 验证 Agent 连接

检查 agent 日志，确认连接成功：

```bash
# Agent 日志应显示：
# INFO Metrics reported count=X
```

检查服务器日志，确认认证成功（如果启用了 debug 日志）：

```bash
# Server 日志应显示：
# DEBUG Agent authenticated successfully agent_id=web-server-01
```

### 7. 启用强制认证

确认所有 agent 都正常工作后，启用强制认证：

编辑 `config/server.toml`：

```toml
# 启用强制认证
require_agent_auth = true
```

重启服务器：

```bash
./oxmon-server config/server.toml
```

### 8. 监控认证失败

启用认证后，监控服务器日志中的认证失败：

```bash
# 查看认证失败的日志
tail -f logs/server.log | grep "UNAUTHENTICATED\|not in whitelist\|Invalid token"
```

## 白名单管理

### 列出所有白名单 Agent

```bash
curl http://localhost:8080/api/v1/agents/whitelist
```

### 删除 Agent

```bash
curl -X DELETE http://localhost:8080/api/v1/agents/whitelist/web-server-01
```

### Token 轮换

如果需要轮换 token：

1. 删除旧的 agent 条目
2. 重新添加 agent（会生成新 token）
3. 更新 agent 配置
4. 重启 agent

## 回滚步骤

如果遇到问题，可以快速回滚：

1. 编辑 `config/server.toml`，设置 `require_agent_auth = false`
2. 重启服务器
3. Agent 将继续正常工作（即使配置了 token）

## 故障排查

### Agent 无法连接

**症状**: Agent 日志显示 "UNAUTHENTICATED" 错误

**解决方案**:
1. 检查 agent 配置中的 `auth_token` 是否正确
2. 检查 `agent_id` 是否与白名单中的一致
3. 使用 API 验证 agent 是否在白名单中

### Token 丢失

**症状**: 忘记保存 token

**解决方案**:
1. 从白名单中删除该 agent
2. 重新添加 agent 获取新 token
3. 更新 agent 配置

### 性能影响

**症状**: 担心认证影响性能

**说明**: Token 验证使用 bcrypt，每次请求增加 <1ms 延迟，对正常监控影响可忽略不计。

## 安全建议

1. **Token 存储**: 将 token 存储在安全的配置管理系统中（如 Vault、AWS Secrets Manager）
2. **定期轮换**: 建议每 90 天轮换一次 token
3. **最小权限**: 每个 agent 使用独立的 token，不要共享
4. **监控**: 定期检查认证失败日志，发现异常访问
5. **网络隔离**: 即使启用认证，仍建议在防火墙层面限制 gRPC 端口访问

## 相关 API

- `POST /api/v1/agents/whitelist` - 添加 agent
- `GET /api/v1/agents/whitelist` - 列出所有 agent
- `DELETE /api/v1/agents/whitelist/{agent_id}` - 删除 agent

详细 API 文档请访问: `http://localhost:8080/docs`
