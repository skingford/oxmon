# 云服务商字段捕获审计报告

生成时间: 2026-02-25

## 执行摘要

本报告审计了当前系统从腾讯云和阿里云采集的字段，并识别出遗漏的重要字段。建议添加 **13个高优先级字段** 以提升监控能力。

---

## 当前已捕获的字段

### CloudInstance 结构体

| 字段 | 类型 | 说明 | 数据库存储 |
|------|------|------|-----------|
| instance_id | String | 云实例ID | ✅ |
| instance_name | String | 实例名称 | ✅ |
| provider | String | 提供商(格式: "tencent:acct" 或 "alibaba:acct") | ✅ |
| region | String | 区域 | ✅ |
| public_ip | String | 公网IP | ✅ |
| private_ip | String | 内网IP | ✅ |
| os | String | 操作系统 | ✅ |
| status | String | 状态 | ✅ |
| tags | HashMap | 标签 | ❌ (未存储) |
| instance_type | String | 实例规格 | ✅ |
| cpu_cores | Option\<u32\> | CPU核数 | ✅ |
| memory_gb | Option\<f64\> | 内存(GB) | ✅ |
| disk_gb | Option\<f64\> | 磁盘容量(GB) | ✅ |

### CloudMetrics 结构体 (时序指标)

| 指标 | 类型 | 说明 |
|------|------|------|
| cpu_usage | Option\<f64\> | CPU使用率(%) |
| memory_usage | Option\<f64\> | 内存使用率(%) |
| disk_usage | Option\<f64\> | 磁盘使用率(%) |
| network_in_bytes | Option\<f64\> | 网络入流量(字节/秒) |
| network_out_bytes | Option\<f64\> | 网络出流量(字节/秒) |
| disk_iops_read | Option\<f64\> | 磁盘读IOPS |
| disk_iops_write | Option\<f64\> | 磁盘写IOPS |
| connections | Option\<f64\> | TCP连接数 |

---

## 遗漏的重要字段分析

### 高优先级字段 (建议添加)

#### 1. 生命周期信息

| 字段 | 腾讯云 | 阿里云 | 重要性 | 建议 |
|------|--------|--------|--------|------|
| **created_time** | CreatedTime | CreationTime | ⭐⭐⭐⭐⭐ | 用于成本分析、审计追踪 |
| **expired_time** | ExpiredTime | ExpiredTime | ⭐⭐⭐⭐⭐ | 预付费实例到期告警 |
| **instance_charge_type** | InstanceChargeType | InstanceChargeType | ⭐⭐⭐⭐ | 成本管理(PREPAID/POSTPAID) |

**影响**:
- 无法识别哪些实例即将到期
- 无法按计费类型进行成本分析
- 缺少实例创建时间用于审计

#### 2. 网络配置

| 字段 | 腾讯云 | 阿里云 | 重要性 | 建议 |
|------|--------|--------|--------|------|
| **vpc_id** | VirtualPrivateCloud.VpcId | VpcAttributes.VpcId | ⭐⭐⭐⭐⭐ | 网络隔离管理 |
| **subnet_id** | VirtualPrivateCloud.SubnetId | VpcAttributes.VSwitchId | ⭐⭐⭐⭐ | 子网规划 |
| **security_group_ids** | SecurityGroupIds | SecurityGroupIds.SecurityGroupId | ⭐⭐⭐⭐⭐ | 安全合规审计 |
| **internet_max_bandwidth** | InternetAccessible.InternetMaxBandwidthOut | InternetMaxBandwidthOut | ⭐⭐⭐ | 带宽成本优化 |

**影响**:
- 无法按VPC/子网进行资源组织
- 无法审计安全组配置
- 缺少带宽信息用于成本优化

#### 3. 位置信息

| 字段 | 腾讯云 | 阿里云 | 重要性 | 建议 |
|------|--------|--------|--------|------|
| **zone** | Placement.Zone | ZoneId | ⭐⭐⭐⭐ | 可用区级别的容灾规划 |
| **hostname** | - | HostName | ⭐⭐⭐ | 主机名识别 |

**影响**:
- 无法识别单可用区故障风险
- 缺少主机名用于服务定位(阿里云)

#### 4. 镜像与操作信息

| 字段 | 腾讯云 | 阿里云 | 重要性 | 建议 |
|------|--------|--------|--------|------|
| **image_id** | ImageId | ImageId | ⭐⭐⭐ | 镜像合规性审计 |
| **description** | - | Description | ⭐⭐ | 实例备注说明(阿里云) |

**影响**:
- 无法识别使用非授权镜像的实例
- 缺少实例用途描述

---

### 中等优先级字段 (可选添加)

#### 5. 高级网络特性

| 字段 | 腾讯云 | 阿里云 | 重要性 | 说明 |
|------|--------|--------|--------|------|
| **IPv6Addresses** | IPv6Addresses | Ipv6Addresses | ⭐⭐ | IPv6支持识别 |
| **EIP关联** | - | EipAddress.AllocationId | ⭐⭐ | 弹性公网IP管理(阿里云) |

#### 6. 计算资源扩展

| 字段 | 腾讯云 | 阿里云 | 重要性 | 说明 |
|------|--------|--------|--------|------|
| **GPU** | GPU | GPUAmount | ⭐⭐ | GPU实例识别 |
| **IO优化** | - | IoOptimized | ⭐ | IO性能级别(阿里云) |

#### 7. 运维信息

| 字段 | 腾讯云 | 阿里云 | 重要性 | 说明 |
|------|--------|--------|--------|------|
| **LatestOperation** | LatestOperation | - | ⭐⭐ | 最近操作追踪(腾讯云) |
| **LatestOperationState** | LatestOperationState | - | ⭐⭐ | 操作状态(腾讯云) |

---

### 低优先级字段 (暂不建议)

| 字段 | 原因 |
|------|------|
| ProjectId | 业务属性,tags已足够 |
| CamRoleName | IAM角色管理不在监控范围 |
| LoginSettings.KeyIds | SSH密钥管理不在监控范围 |
| RenewFlag | 续费设置,财务系统处理 |
| Uuid | 系统内部标识,无业务价值 |
| InstanceNetworkType | classic已废弃,VPC为主流 |

---

## 数据库Schema变更建议

### 方案1: 扩展 cloud_instances 表 (推荐)

```sql
ALTER TABLE cloud_instances ADD COLUMN created_time INTEGER;          -- 创建时间(Unix timestamp)
ALTER TABLE cloud_instances ADD COLUMN expired_time INTEGER;          -- 过期时间(Unix timestamp)
ALTER TABLE cloud_instances ADD COLUMN charge_type TEXT;              -- 计费类型
ALTER TABLE cloud_instances ADD COLUMN vpc_id TEXT;                   -- VPC ID
ALTER TABLE cloud_instances ADD COLUMN subnet_id TEXT;                -- 子网/交换机ID
ALTER TABLE cloud_instances ADD COLUMN zone TEXT;                     -- 可用区
ALTER TABLE cloud_instances ADD COLUMN internet_max_bandwidth INTEGER; -- 公网带宽上限(Mbps)
ALTER TABLE cloud_instances ADD COLUMN image_id TEXT;                 -- 镜像ID
ALTER TABLE cloud_instances ADD COLUMN hostname TEXT;                 -- 主机名
ALTER TABLE cloud_instances ADD COLUMN description TEXT;              -- 实例描述
ALTER TABLE cloud_instances ADD COLUMN ipv6_addresses TEXT;           -- IPv6地址(JSON数组)

-- 新建安全组关联表
CREATE TABLE IF NOT EXISTS cloud_instance_security_groups (
    instance_id TEXT NOT NULL,
    security_group_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (instance_id, security_group_id),
    FOREIGN KEY (instance_id) REFERENCES cloud_instances(id) ON DELETE CASCADE
);
CREATE INDEX idx_cisg_instance ON cloud_instance_security_groups(instance_id);
CREATE INDEX idx_cisg_sg ON cloud_instance_security_groups(security_group_id);
```

### 方案2: 保留tags字段存储 (补充)

```sql
-- 当前tags字段在CloudInstance中存在但未存储到数据库
-- 建议添加tags存储
ALTER TABLE cloud_instances ADD COLUMN tags TEXT; -- JSON格式存储HashMap
```

---

## 代码变更清单

### 1. 更新 CloudInstance 结构体

**文件**: `crates/oxmon-cloud/src/lib.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudInstance {
    // 现有字段...
    pub instance_id: String,
    pub instance_name: String,
    // ... 其他现有字段 ...

    // 新增字段
    pub created_time: Option<i64>,        // Unix timestamp
    pub expired_time: Option<i64>,        // Unix timestamp
    pub charge_type: Option<String>,      // "PREPAID", "POSTPAID_BY_HOUR", "PrePaid", "PostPaid"
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub zone: Option<String>,
    pub internet_max_bandwidth: Option<u32>, // Mbps
    pub image_id: Option<String>,
    pub hostname: Option<String>,
    pub description: Option<String>,
    pub ipv6_addresses: Vec<String>,
    pub security_group_ids: Vec<String>,
}
```

### 2. 腾讯云提取逻辑

**文件**: `crates/oxmon-cloud/src/tencent.rs:151-298`

在 `list_instances_in_region()` 函数中添加字段提取:

```rust
// 在现有字段解析后添加
let created_time = inst
    .get("CreatedTime")
    .and_then(|v| v.as_str())
    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    .map(|dt| dt.timestamp());

let expired_time = inst
    .get("ExpiredTime")
    .and_then(|v| v.as_str())
    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    .map(|dt| dt.timestamp());

let charge_type = inst
    .get("InstanceChargeType")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let vpc_id = inst
    .get("VirtualPrivateCloud")
    .and_then(|vpc| vpc.get("VpcId"))
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let subnet_id = inst
    .get("VirtualPrivateCloud")
    .and_then(|vpc| vpc.get("SubnetId"))
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let zone = inst
    .get("Placement")
    .and_then(|p| p.get("Zone"))
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let internet_max_bandwidth = inst
    .get("InternetAccessible")
    .and_then(|ia| ia.get("InternetMaxBandwidthOut"))
    .and_then(|v| v.as_u64())
    .map(|v| v as u32);

let image_id = inst
    .get("ImageId")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let mut security_group_ids = Vec::new();
if let Some(sg_arr) = inst.get("SecurityGroupIds").and_then(|v| v.as_array()) {
    for sg in sg_arr {
        if let Some(sg_id) = sg.as_str() {
            security_group_ids.push(sg_id.to_string());
        }
    }
}

let mut ipv6_addresses = Vec::new();
if let Some(ipv6_arr) = inst.get("IPv6Addresses").and_then(|v| v.as_array()) {
    for ipv6 in ipv6_arr {
        if let Some(addr) = ipv6.as_str() {
            ipv6_addresses.push(addr.to_string());
        }
    }
}
```

### 3. 阿里云提取逻辑

**文件**: `crates/oxmon-cloud/src/alibaba.rs:231-384`

在 `list_instances_in_region()` 函数中添加字段提取:

```rust
// 在现有字段解析后添加
let created_time = inst
    .get("CreationTime")
    .and_then(|v| v.as_str())
    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    .map(|dt| dt.timestamp());

let expired_time = inst
    .get("ExpiredTime")
    .and_then(|v| v.as_str())
    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    .map(|dt| dt.timestamp());

let charge_type = inst
    .get("InstanceChargeType")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let vpc_id = inst
    .get("VpcAttributes")
    .and_then(|vpc| vpc.get("VpcId"))
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let subnet_id = inst
    .get("VpcAttributes")
    .and_then(|vpc| vpc.get("VSwitchId"))
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let zone = inst
    .get("ZoneId")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let internet_max_bandwidth = inst
    .get("InternetMaxBandwidthOut")
    .and_then(|v| v.as_u64())
    .map(|v| v as u32);

let image_id = inst
    .get("ImageId")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let hostname = inst
    .get("HostName")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let description = inst
    .get("Description")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string());

let mut security_group_ids = Vec::new();
if let Some(sg_obj) = inst.get("SecurityGroupIds") {
    if let Some(sg_arr) = sg_obj.get("SecurityGroupId").and_then(|v| v.as_array()) {
        for sg in sg_arr {
            if let Some(sg_id) = sg.as_str() {
                security_group_ids.push(sg_id.to_string());
            }
        }
    }
}

let mut ipv6_addresses = Vec::new();
if let Some(ipv6_obj) = inst.get("Ipv6Addresses") {
    if let Some(ipv6_arr) = ipv6_obj.get("Ipv6Address").and_then(|v| v.as_array()) {
        for ipv6 in ipv6_arr {
            if let Some(addr) = ipv6.as_str() {
                ipv6_addresses.push(addr.to_string());
            }
        }
    }
}
```

### 4. 数据库存储更新

**文件**: `crates/oxmon-storage/src/cert_store.rs`

更新 `upsert_cloud_instance()` 函数的SQL语句，添加新字段插入。

---

## 实施优先级建议

### Phase 1: 高优先级 (立即实施)

1. **生命周期字段**: created_time, expired_time, charge_type
2. **网络安全字段**: vpc_id, subnet_id, security_group_ids
3. **位置字段**: zone

**预期收益**:
- 到期告警功能
- 按VPC/可用区进行资源管理
- 安全合规审计能力

### Phase 2: 中等优先级 (后续版本)

1. **网络扩展**: internet_max_bandwidth, ipv6_addresses
2. **系统信息**: image_id, hostname, description

**预期收益**:
- 带宽成本优化
- 镜像合规审计
- 更好的实例识别

### Phase 3: 可选优先级

1. GPU信息、IO优化等级等特殊场景字段

---

## 测试验证清单

- [ ] 腾讯云实例字段完整性验证
- [ ] 阿里云实例字段完整性验证
- [ ] 数据库迁移脚本测试
- [ ] API响应格式兼容性测试 (字段为null的情况)
- [ ] 前端界面字段展示调整
- [ ] 告警规则扩展 (到期告警、安全组变更告警等)

---

## 参考文档

### 腾讯云
- [DescribeInstances API 文档](https://cloud.tencent.com/document/product/213/15728)
- [Instance 数据结构](https://cloud.tencent.com/document/api/213/15753#Instance)

### 阿里云
- [DescribeInstances API 文档](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-describeinstances)
- [Instance 数据结构](https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-describeinstances#api-detail-36)

---

## 附录: 字段映射表

| 通用字段 | 腾讯云字段 | 阿里云字段 | 当前捕获 |
|---------|-----------|-----------|---------|
| 实例ID | InstanceId | InstanceId | ✅ |
| 实例名称 | InstanceName | InstanceName | ✅ |
| 状态 | InstanceState | Status | ✅ |
| 操作系统 | OsName | OSName | ✅ |
| 规格 | InstanceType | InstanceType | ✅ |
| CPU | CPU | Cpu | ✅ |
| 内存 | Memory | Memory | ✅ |
| 创建时间 | CreatedTime | CreationTime | ❌ |
| 过期时间 | ExpiredTime | ExpiredTime | ❌ |
| 计费类型 | InstanceChargeType | InstanceChargeType | ❌ |
| VPC ID | VirtualPrivateCloud.VpcId | VpcAttributes.VpcId | ❌ |
| 子网ID | VirtualPrivateCloud.SubnetId | VpcAttributes.VSwitchId | ❌ |
| 可用区 | Placement.Zone | ZoneId | ❌ |
| 公网带宽 | InternetAccessible.InternetMaxBandwidthOut | InternetMaxBandwidthOut | ❌ |
| 镜像ID | ImageId | ImageId | ❌ |
| 安全组 | SecurityGroupIds | SecurityGroupIds.SecurityGroupId | ❌ |
| IPv6地址 | IPv6Addresses | Ipv6Addresses.Ipv6Address | ❌ |
| 主机名 | - | HostName | ❌ |
| 描述 | - | Description | ❌ |

---

**报告结束**
