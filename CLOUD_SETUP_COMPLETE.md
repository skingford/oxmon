# 云监控配置完成 ✅

## 🎉 配置状态

已成功根据 .env 文件配置云监控系统，并修复了实例数据写入问题。

## 📊 当前配置

### 云账户 (4个)

| 账户名称 | 云厂商 | 地域数量 | 状态 |
|---------|-------|---------|------|
| 腾讯云-主账号 | 腾讯云 | 1 (ap-shanghai) | ✅ 启用 |
| 腾讯云-子账号 | 腾讯云 | 3 (ap-shenzhen, ap-shanghai, ap-nanjing) | ✅ 启用 |
| 阿里云-主账号 | 阿里云 | 2 (cn-shanghai, cn-shenzhen) | ✅ 启用 |
| 阿里云-主账号-2 | 阿里云 | 2 (cn-shenzhen, cn-hangzhou) | ✅ 启用 |

### 云实例 (82个)

- **腾讯云**: 44 个实例
- **阿里云**: 38 个实例

### 监控指标 (8种)

1. `cloud.cpu.usage` - CPU使用率 (%)
2. `cloud.memory.usage` - 内存使用率 (%)
3. `cloud.disk.usage` - 磁盘使用率 (%)
4. `cloud.network.in_bytes` - 网络入流量 (bytes/s)
5. `cloud.network.out_bytes` - 网络出流量 (bytes/s)
6. `cloud.disk.iops_read` - 磁盘读IOPS (ops/s)
7. `cloud.disk.iops_write` - 磁盘写IOPS (ops/s)
8. `cloud.connections` - TCP连接数

## 🔧 技术修复

### 问题1: 实例数据未写入数据库

**现象**: 采集日志显示"Collected metrics from X instances"，但查询 `/v1/cloud/instances` 返回 0 个实例。

**原因**: 调度器代码只采集指标，没有将实例信息写入 `cloud_instances` 表。

**修复**: 在 `crates/oxmon-server/src/cloud/scheduler.rs` 中添加了实例数据写入逻辑：
- 在采集指标前，先调用 `provider.list_instances()` 获取所有实例
- 将每个实例通过 `cert_store.upsert_cloud_instance()` 写入数据库

### 问题2: agent_id 格式不匹配

**现象**: 指标数据已写入，但查询时返回空。

**原因**: `CloudMetrics` 中的 `provider` 字段格式为 `tencent:account_name` 或 `alibaba:account_name`，但调度器直接使用它生成 agent_id，导致格式变成 `cloud:tencent:account_name:instance_id` 而不是预期的 `cloud:tencent:instance_id`。

**修复**: 从 `m.provider` 中提取 provider 类型（`tencent` 或 `alibaba`），然后生成正确的 agent_id：
```rust
let provider_type = m.provider.split(':').next().unwrap_or("unknown");
let agent_id = format!("cloud:{}:{}", provider_type, m.instance_id);
```

## ✅ 验证结果

### 数据库验证
```bash
$ sqlite3 data-test/cert.db "SELECT provider, COUNT(*) FROM cloud_instances GROUP BY provider;"
alibaba|38
tencent|44
```

### API 验证
```bash
$ curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/cloud/instances | jq '.data.total'
82
```

### 指标数据验证
```bash
$ curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/v1/metrics?agent_id__eq=cloud:alibaba:i-wz99sjnoczeudzwccekq&metric_name__eq=cloud.cpu.usage&limit=1"
{
  "data": {
    "items": [{
      "value": 0.34,
      "metric_name": "cloud.cpu.usage",
      "timestamp": "2026-02-25T04:27:35.354Z"
    }]
  }
}
```

## 📝 使用说明

### 查看云实例
```bash
./scripts/check-cloud-instances.sh
```

### 手动触发采集
```bash
./scripts/trigger-cloud-collection.sh
```

### 导入云账户
```bash
ENV_FILE=/path/to/.env ./scripts/import-cloud-accounts.sh
```

### 查询指标数据
```bash
# 通过 API
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/v1/metrics?agent_id__eq=cloud:tencent:ins-xxx&metric_name__eq=cloud.cpu.usage"

# 通过 Web UI
open http://localhost:8080/docs
```

## ⚙️ 系统配置

- **采集间隔**: 300秒 (5分钟)
- **调度器 tick**: 30秒
- **最大并发**: 5个云账户
- **实例筛选**: 仅监控 Running 状态的实例
- **自动采集**: 启用

## 🎯 下一步

1. **监控数据**: 等待 5-10 分钟，让系统采集更多数据点
2. **配置告警**: 创建云实例的告警规则
3. **查看趋势**: 通过 API 或 Web UI 查看指标趋势
4. **优化筛选**: 根据需要调整实例筛选规则

## 📚 相关文档

- [云监控功能说明](./CLOUD_FEATURES.md)
- [测试总结](./TEST_SUMMARY.md)
- [架构文档](./CLAUDE.md)
- [脚本说明](./scripts/README.md)

## 🚀 快速命令

```bash
# 查看服务器状态
curl -s http://localhost:8080/v1/health | jq

# 查看所有云账户
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/cloud/accounts | jq

# 查看所有云实例
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/v1/cloud/instances | jq

# 查看指标名称列表
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/metrics/names" | jq

# 查看所有 agent
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8080/v1/metrics/agents" | jq
```

## ✨ 完成时间

**2026-02-25 12:27 (UTC+8)**

---

**状态**: ✅ 配置完成，系统运行正常
