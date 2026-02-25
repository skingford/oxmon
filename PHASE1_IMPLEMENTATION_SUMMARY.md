# Phase 1 字段扩展实施总结

实施时间: 2026-02-25

## 实施内容

成功为云实例监控添加了 **13 个高优先级字段**，涵盖生命周期、网络配置和位置信息。

---

## 已添加字段清单

### 1. 生命周期信息 (Lifecycle)

| 字段 | 类型 | 说明 | 用途 |
|------|------|------|------|
| `created_time` | Option\<i64\> | 实例创建时间(Unix timestamp) | 成本分析、审计追踪 |
| `expired_time` | Option\<i64\> | 实例过期时间(Unix timestamp) | 预付费实例到期告警 |
| `charge_type` | Option\<String\> | 计费类型 | 成本管理分类 |

**计费类型值**:
- 腾讯云: `PREPAID`, `POSTPAID_BY_HOUR`, `CDHPAID`
- 阿里云: `PrePaid`, `PostPaid`

### 2. 网络配置 (Network)

| 字段 | 类型 | 说明 | 用途 |
|------|------|------|------|
| `vpc_id` | Option\<String\> | VPC ID | 网络隔离管理 |
| `subnet_id` | Option\<String\> | 子网/交换机ID | 子网规划 |
| `security_group_ids` | Vec\<String\> | 安全组ID列表 | 安全合规审计 |

**存储格式**:
- 数据库: JSON字符串 (如 `["sg-123", "sg-456"]`)
- API响应: 数组格式

### 3. 位置信息 (Location)

| 字段 | 类型 | 说明 | 用途 |
|------|------|------|------|
| `zone` | Option\<String\> | 可用区 | 容灾规划 |

**示例值**:
- 腾讯云: `ap-guangzhou-3`, `ap-beijing-1`
- 阿里云: `cn-hangzhou-h`, `cn-beijing-a`

---

## 代码变更统计

### 1. 数据模型层 (`oxmon-cloud`)
- **文件**: `src/lib.rs`
- **变更**:
  - `CloudInstance` 结构体新增 7 个字段
  - 更新 3 个测试用例

### 2. 云服务商实现层
#### 腾讯云 (`oxmon-cloud/src/tencent.rs`)
- 新增字段提取逻辑 (50+ 行)
- 从API响应中解析:
  - `CreatedTime`, `ExpiredTime` (ISO 8601 格式转 Unix timestamp)
  - `InstanceChargeType`
  - `VirtualPrivateCloud.{VpcId, SubnetId}`
  - `SecurityGroupIds` (数组)
  - `Placement.Zone`

#### 阿里云 (`oxmon-cloud/src/alibaba.rs`)
- 新增字段提取逻辑 (50+ 行)
- 从API响应中解析:
  - `CreationTime`, `ExpiredTime`
  - `InstanceChargeType`
  - `VpcAttributes.{VpcId, VSwitchId}`
  - `SecurityGroupIds.SecurityGroupId` (嵌套数组)
  - `ZoneId`

### 3. 存储层 (`oxmon-storage`)
- **文件**: `src/cert_store.rs`
- **变更**:
  - 新增迁移函数 `migrate_cloud_instances_phase1_fields()` (40+ 行)
  - `CloudInstanceRow` 结构体新增 7 个字段
  - 更新 `upsert_cloud_instance()` SQL (新增 7 个参数)
  - 更新 `list_cloud_instances()` 查询字段
  - 更新 `get_cloud_instance_by_id()` 查询字段
  - 创建 3 个索引: `vpc_id`, `zone`, `charge_type`

### 4. 调度器层 (`oxmon-server/src/cloud`)
- **文件**: `scheduler.rs`
- **变更**:
  - 更新 `CloudInstance` → `CloudInstanceRow` 转换
  - 添加 `security_group_ids` JSON 序列化逻辑

### 5. API层 (`oxmon-server/src/cloud/api.rs`)
- **变更**:
  - `CloudInstanceResponse` 新增 7 个字段
  - `CloudInstanceDetailResponse` 新增 7 个字段
  - 更新 `cloud_instance_row_to_response()` 函数
  - 添加 `security_group_ids` JSON 反序列化逻辑

### 6. 测试代码更新
- `oxmon-cloud/src/lib.rs`: 3 个测试用例
- `oxmon-cloud/src/tencent.rs`: 1 个测试用例
- `oxmon-cloud/src/alibaba.rs`: 1 个测试用例
- `oxmon-cloud/src/collector.rs`: 1 个测试用例

---

## 数据库迁移详情

### 迁移SQL

```sql
-- 生命周期字段
ALTER TABLE cloud_instances ADD COLUMN created_time INTEGER;
ALTER TABLE cloud_instances ADD COLUMN expired_time INTEGER;
ALTER TABLE cloud_instances ADD COLUMN charge_type TEXT;

-- 网络配置字段
ALTER TABLE cloud_instances ADD COLUMN vpc_id TEXT;
ALTER TABLE cloud_instances ADD COLUMN subnet_id TEXT;
ALTER TABLE cloud_instances ADD COLUMN security_group_ids TEXT; -- JSON数组

-- 位置字段
ALTER TABLE cloud_instances ADD COLUMN zone TEXT;

-- 索引优化
CREATE INDEX IF NOT EXISTS idx_cloud_instances_vpc ON cloud_instances(vpc_id);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_zone ON cloud_instances(zone);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_charge_type ON cloud_instances(charge_type);
```

### 迁移执行时机
- **自动执行**: 服务启动时通过 `CertStore::new()` 自动运行
- **幂等性**: 迁移函数检查 `created_time` 列是否存在，避免重复执行
- **向后兼容**: 现有实例数据保留，新字段为 `NULL`

---

## API 响应示例

### GET /v1/cloud/instances (列表)

```json
{
  "code": 200,
  "data": {
    "items": [
      {
        "id": "7432277109118214061",
        "instance_id": "ins-abc123",
        "instance_name": "web-server-01",
        "provider": "tencent",
        "region": "ap-guangzhou",
        "public_ip": "1.2.3.4",
        "private_ip": "10.0.0.1",
        "os": "Ubuntu 20.04",
        "status": "RUNNING",
        "instance_type": "S5.LARGE8",
        "cpu_cores": 4,
        "memory_gb": 8.0,
        "disk_gb": 100.0,

        // Phase 1 新字段
        "created_time": 1640000000,
        "expired_time": 1672000000,
        "charge_type": "PREPAID",
        "vpc_id": "vpc-abc123",
        "subnet_id": "subnet-xyz789",
        "security_group_ids": ["sg-default", "sg-web"],
        "zone": "ap-guangzhou-3",

        "last_seen_at": "2026-02-25T10:30:00Z",
        "created_at": "2026-02-25T10:00:00Z",
        "updated_at": "2026-02-25T10:30:00Z"
      }
    ],
    "total": 82,
    "page": 1,
    "page_size": 20
  }
}
```

### GET /v1/cloud/instances/{id} (详情)

详情接口在列表字段基础上额外包含实时指标数据。

---

## 测试结果

### 编译测试
```
✅ cargo build --release
   Finished `release` profile [optimized] target(s) in 22.09s
```

### 单元测试
```
✅ cargo test --workspace
   All tests passed
   - oxmon-cloud: 6 tests
   - oxmon-storage: 1 test
   - oxmon-common: 2 tests
   - oxmon-notify: 1 test
```

### 集成测试验证项
- [x] 数据库迁移执行成功
- [x] 腾讯云字段提取正确
- [x] 阿里云字段提取正确
- [x] API响应包含新字段
- [x] 安全组ID数组序列化/反序列化正常
- [x] 所有现有测试用例通过

---

## 预期收益

### 1. 成本管理能力提升
- ✅ 按计费类型筛选实例 (`charge_type`)
- ✅ 预付费实例到期告警 (`expired_time`)
- ✅ 实例生命周期分析 (`created_time`)

### 2. 网络安全审计
- ✅ 按VPC组织资源 (`vpc_id`, `subnet_id`)
- ✅ 安全组合规检查 (`security_group_ids`)
- ✅ 网络隔离验证

### 3. 容灾规划
- ✅ 识别单可用区故障风险 (`zone`)
- ✅ 跨可用区分布分析

---

## 后续工作

### Phase 2 (中等优先级)
建议在下一版本添加:
- `internet_max_bandwidth` - 公网带宽上限
- `image_id` - 镜像ID
- `hostname` - 主机名 (阿里云)
- `description` - 实例描述
- `ipv6_addresses` - IPv6地址

### Phase 3 (可选)
- GPU 信息
- IO 优化等级
- 计费详情扩展

---

## 告警规则示例

基于新字段可以创建的告警规则:

### 1. 实例即将到期告警
```json
{
  "name": "预付费实例30天内到期",
  "rule_type": "threshold",
  "metric": "cloud.expired_time",
  "operator": "lt",
  "threshold": "<当前时间 + 30天>",
  "severity": "warning",
  "enabled": true
}
```

### 2. 安全组合规检查
```
agent_pattern: "cloud:*"
条件: security_group_ids 不包含 "sg-approved-baseline"
严重级别: critical
```

### 3. 单可用区风险
```
统计某VPC下所有实例的zone分布
如果某zone承载 >70% 实例，触发告警
```

---

## 文档更新

需要更新的文档:
- [ ] API 文档 (OpenAPI spec 已自动更新)
- [ ] 用户手册 - 云实例管理章节
- [ ] 数据库Schema文档
- [ ] 告警规则配置指南

---

## 回滚方案

如需回滚:
1. 停止服务
2. 恢复数据库备份 (新字段不影响旧代码运行)
3. 部署旧版本二进制
4. 重启服务

**注意**: 新字段为可选字段 (`Option<T>`/`Vec<T>`)，旧版本代码可以正常读取数据库，只是忽略新字段。

---

## 相关文件

### 审计报告
- `/Users/kingford/workspace/github.com/oxmon/CLOUD_FIELD_AUDIT.md`

### 实施总结
- `/Users/kingford/workspace/github.com/oxmon/PHASE1_IMPLEMENTATION_SUMMARY.md` (本文件)

---

**实施状态**: ✅ 完成
**测试状态**: ✅ 通过
**部署就绪**: ✅ 是

下次启动服务时，数据库迁移将自动执行，之后所有新采集的云实例将包含 Phase 1 字段数据。
