# 云监控功能测试指南

## 测试环境准备

### 1. 编译项目
```bash
cargo build --release
```

### 2. 准备云账户凭证

#### 腾讯云
- 访问 https://console.cloud.tencent.com/cam/capi
- 获取 `SecretId` 和 `SecretKey`
- 确保账户有 CVM 和 Monitor 的读权限

#### 阿里云
- 访问 https://ram.console.aliyun.com/manage/ak
- 获取 `AccessKeyId` 和 `AccessKeySecret`
- 确保账户有 ECS 和 CMS 的读权限

### 3. 启动服务器

**终端1：启动 oxmon-server**
```bash
cd /Users/kingford/workspace/github.com/oxmon
./target/release/oxmon-server config/server.test.toml
```

等待服务器启动，看到以下日志表示成功：
```
INFO oxmon_server: oxmon-server starting
INFO oxmon_server: Cloud metrics scheduler enabled
```

## 自动化测试

**依赖要求**
- Python 3 (用于 JSON 解析)
- curl (用于 HTTP 请求)
- openssl (用于 RSA 加密,系统通常预装)

**终端2：运行测试脚本**
```bash
cd /Users/kingford/workspace/github.com/oxmon
./scripts/test-cloud-monitoring.sh
```

测试脚本会：
1. ✓ 检查服务器状态
2. ✓ 获取认证 token
3. ✓ 提示您输入云账户凭证
4. ✓ 创建云账户配置
5. ✓ 测试云 API 连接
6. ✓ 触发手动采集
7. ✓ 查询云实例列表
8. ✓ 查询各项指标数据（CPU、内存、网络、磁盘IOPS、连接数）

## 手动测试步骤

### 1. 获取 Token
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"changeme"}' | jq -r '.data.token')
```

### 2. 创建云账户（腾讯云示例）
```bash
curl -X POST http://localhost:8080/v1/cloud/accounts \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
  "config_key": "tencent-test",
  "provider": "tencent",
  "display_name": "腾讯云测试",
  "enabled": true,
  "config": {
    "secret_id": "YOUR_SECRET_ID",
    "secret_key": "YOUR_SECRET_KEY",
    "regions": ["ap-guangzhou"],
    "collection_interval_secs": 60,
    "instance_filter": {
      "status_whitelist": ["RUNNING"],
      "required_tags": {
        "env": "prod"
      }
    }
  }
}'
```

保存返回的 `account_id`。

### 3. 测试连接
```bash
ACCOUNT_ID="刚才返回的ID"
curl -X POST http://localhost:8080/v1/cloud/accounts/$ACCOUNT_ID/test \
    -H "Authorization: Bearer $TOKEN"
```

### 4. 手动触发采集
```bash
curl -X POST http://localhost:8080/v1/cloud/accounts/$ACCOUNT_ID/collect \
    -H "Authorization: Bearer $TOKEN"
```

### 5. 查询云实例
```bash
curl -X GET "http://localhost:8080/v1/cloud/instances?limit=10" \
    -H "Authorization: Bearer $TOKEN" | jq .
```

### 6. 查询指标数据

#### CPU 使用率
```bash
curl -X GET "http://localhost:8080/v1/metrics?agent_id__eq=cloud:tencent:ins-xxx&metric_name__eq=cloud.cpu.usage&limit=10" \
    -H "Authorization: Bearer $TOKEN" | jq .
```

#### 内存使用率
```bash
curl -X GET "http://localhost:8080/v1/metrics?metric_name__eq=cloud.memory.usage&limit=10" \
    -H "Authorization: Bearer $TOKEN" | jq .
```

#### 网络流量
```bash
curl -X GET "http://localhost:8080/v1/metrics?metric_name__eq=cloud.network.in_bytes&limit=10" \
    -H "Authorization: Bearer $TOKEN" | jq .
```

#### 磁盘 IOPS
```bash
curl -X GET "http://localhost:8080/v1/metrics?metric_name__eq=cloud.disk.iops_read&limit=10" \
    -H "Authorization: Bearer $TOKEN" | jq .
```

#### TCP 连接数
```bash
curl -X GET "http://localhost:8080/v1/metrics?metric_name__eq=cloud.connections&limit=10" \
    -H "Authorization: Bearer $TOKEN" | jq .
```

## 验证实例筛选功能

### 测试标签筛选
```bash
# 创建只监控 prod 环境的账户
curl -X POST http://localhost:8080/v1/cloud/accounts \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
  "config_key": "tencent-prod-only",
  "provider": "tencent",
  "display_name": "仅生产环境",
  "enabled": true,
  "config": {
    "secret_id": "YOUR_SECRET_ID",
    "secret_key": "YOUR_SECRET_KEY",
    "regions": ["ap-guangzhou"],
    "collection_interval_secs": 300,
    "instance_filter": {
      "status_whitelist": ["RUNNING"],
      "required_tags": {
        "env": "prod",
        "monitoring": "enabled"
      },
      "excluded_tags": {
        "deprecated": "true"
      }
    }
  }
}'
```

测试连接后，对比实例数量差异。

## 验证扩缩容告警（需要先集成到 rule_builder）

### 创建扩容告警规则
```bash
curl -X POST http://localhost:8080/v1/alerts/rules \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
  "name": "云实例CPU扩容建议",
  "rule_type": "cloud_scale_recommendation",
  "metric": "cloud.cpu.usage",
  "agent_pattern": "cloud:*",
  "severity": "warning",
  "enabled": true,
  "silence_secs": 3600,
  "config": {
    "high_threshold": 80.0,
    "low_threshold": 20.0,
    "duration_secs": 600
  }
}'
```

注意：目前 CloudScaleRecommendationRule 还需要在 `oxmon-server/src/rule_builder.rs` 中添加序列化/反序列化支持。

## 查看日志

服务器日志会显示：
```
INFO oxmon_server::cloud::scheduler: Cloud metrics scheduler starting
INFO oxmon_server::cloud::scheduler: Checking due cloud accounts
INFO oxmon_server::cloud::scheduler: Account 'tencent-test' is due for collection
INFO oxmon_server::cloud::scheduler: Collected 15 metrics from 3 instances
```

## 预期结果

### 成功指标
- ✅ 服务器成功启动，云调度器已启用
- ✅ 云账户创建成功，凭证已脱敏
- ✅ 连接测试成功，发现实例
- ✅ 手动采集成功，收集指标
- ✅ 查询到云实例列表
- ✅ 查询到 8 种指标数据：
  - cloud.cpu.usage
  - cloud.memory.usage
  - cloud.disk.usage
  - cloud.network.in_bytes
  - cloud.network.out_bytes
  - cloud.disk.iops_read
  - cloud.disk.iops_write
  - cloud.connections
- ✅ 实例筛选按预期工作
- ✅ 自动调度持续采集（每 collection_interval_secs 秒）

### 故障排查

#### 连接失败
- 检查云账户凭证是否正确
- 检查网络连接
- 检查云账户权限

#### 未发现实例
- 确认指定的地域中有运行中的实例
- 检查实例筛选配置（status_whitelist, required_tags）
- 查看服务器日志了解详情

#### 无指标数据
- 等待至少一个采集周期（collection_interval_secs）
- 检查云厂商监控 API 是否有数据延迟
- 查看服务器日志中的错误信息

## API 文档

访问 http://localhost:8080/docs 查看完整的 Swagger API 文档。

云监控相关端点：
- `GET /v1/cloud/accounts` - 列出云账户
- `POST /v1/cloud/accounts` - 创建云账户
- `GET /v1/cloud/accounts/{id}` - 查询云账户详情
- `PUT /v1/cloud/accounts/{id}` - 更新云账户
- `DELETE /v1/cloud/accounts/{id}` - 删除云账户
- `POST /v1/cloud/accounts/{id}/test` - 测试连接
- `POST /v1/cloud/accounts/{id}/collect` - 手动触发采集
- `GET /v1/cloud/instances` - 查询云实例列表

## 压力测试

### 大规模实例测试
配置多个地域，测试大量实例的采集性能：
```json
{
  "regions": [
    "ap-guangzhou", "ap-shanghai", "ap-beijing",
    "ap-chengdu", "ap-chongqing", "ap-nanjing"
  ],
  "collection_interval_secs": 300
}
```

观察：
- 采集耗时
- 并发控制是否生效
- 内存和 CPU 使用情况

### 高频采集测试
设置较短的采集间隔测试性能：
```json
{
  "collection_interval_secs": 60
}
```

确保：
- 不会触发云厂商速率限制
- 系统资源使用合理
- 数据库写入性能良好
