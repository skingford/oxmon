# Implementation Plan: Instance Alert Notification with Designated Contacts

## Requirements Restatement

当前系统中，告警触发后会通知**所有**已启用通知渠道的**所有**接收人。用户需要：

1. 能为特定实例（agent/云实例）配置**负责人**（可多个）
2. 告警触发时，优先通知该实例的负责人，而非所有渠道的所有接收人
3. 负责人信息需要包含：姓名、联系方式（邮箱/手机/等）
4. 支持通过 REST API 管理实例负责人关系
5. 兼容现有的 glob pattern 匹配机制（agent_pattern）

## Design Approach

### Core Concept: Instance Contacts (实例联系人)

新增 `instance_contacts` 表，建立**实例 ↔ 联系人**的多对多关系。告警通知时：
- 如果触发告警的实例有配置联系人 → 只通知该实例的联系人
- 如果实例没有配置联系人 → 回退到现有逻辑（通知所有渠道接收人）

### Database Schema

**新表: `instance_contacts`**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | 雪花 ID（`oxmon_common::id::next_id()`） |
| agent_patterns | TEXT NOT NULL | JSON 数组，多个 glob pattern（如 `["prod-web-01","cloud:tencent:ins-*"]`），与 cloud_accounts.regions 风格一致 |
| contact_name | TEXT NOT NULL | 联系人姓名 |
| contact_email | TEXT | 邮箱（→ email 渠道） |
| contact_phone | TEXT | 手机号（→ sms 渠道） |
| contact_dingtalk | TEXT | 钉钉 Webhook URL（→ dingtalk 渠道） |
| contact_webhook | TEXT | 通用 Webhook URL（→ webhook/weixin 渠道） |
| enabled | BOOL DEFAULT true | 是否启用 |
| description | TEXT | 备注 |
| created_at | TEXT NOT NULL | 创建时间 |
| updated_at | TEXT NOT NULL | 更新时间 |

使用 `agent_patterns` JSON 数组存储多个 glob pattern，灵活匹配：
- 精确匹配: `["prod-web-01"]`
- 通配符: `["prod-*"]`（所有生产环境机器）
- 多模式: `["prod-web-*", "prod-api-*"]`（同时匹配多组实例）
- 云实例: `["cloud:tencent:*"]`（所有腾讯云实例）
- 存储风格与 `cloud_accounts.regions` 一致（JSON 数组字符串）

## Implementation Phases

### Phase 1: Database Layer (oxmon-storage)

1. **创建 SeaORM Entity**: `crates/oxmon-storage/src/entities/instance_contact.rs`
   - 定义 `Model` 结构体与字段映射
   - 实现 `ActiveModelBehavior`

2. **创建 Storage 方法**: `crates/oxmon-storage/src/store/instance_contact.rs`
   - `create_instance_contact()` - 创建联系人
   - `update_instance_contact()` - 更新联系人
   - `delete_instance_contact()` - 删除联系人
   - `get_instance_contact()` - 获取单个联系人
   - `list_instance_contacts()` - 分页列表（支持 contact_name 等过滤）
   - `count_instance_contacts()` - 计数
   - `find_contacts_for_agent(agent_id: &str)` - 根据 agent_id 查找匹配的联系人（核心方法：加载所有启用的联系人，解析 agent_patterns JSON 数组，逐一 glob_match）

3. **自动建表**: 在 `CertStore::new()` 或 migration 中添加 `CREATE TABLE IF NOT EXISTS instance_contacts`

### Phase 2: Notification Routing Enhancement (oxmon-notify)

4. **修改 `send_to_channels` 方法**: `crates/oxmon-notify/src/manager.rs`
   - 在发送前，通过 `find_contacts_for_agent(&event.agent_id)` 查询实例联系人
   - 如果有联系人：按联系方式匹配渠道类型，只发送给匹配的联系人
     - `contact_email` → 发送到 email 类型渠道
     - `contact_phone` → 发送到 sms 类型渠道
     - `contact_dingtalk` → 发送到 dingtalk 类型渠道（值为钉钉 Webhook URL）
     - `contact_webhook` → 发送到 webhook/weixin 类型渠道
   - 如果没有联系人：保持现有行为（发给所有渠道接收人）

5. **修改 `ChannelInstance` 或 `send` 调用**:
   - `send` 方法已接受 `recipients: &[String]`，只需传入联系人的对应值即可

### Phase 3: REST API (oxmon-server)

6. **创建 API 文件**: `crates/oxmon-server/src/api/instance_contacts.rs`

   路由设计：
   ```
   GET    /v1/instance-contacts              # 分页列表
   POST   /v1/instance-contacts              # 创建联系人
   GET    /v1/instance-contacts/{id}         # 获取详情
   PUT    /v1/instance-contacts/{id}         # 更新
   DELETE /v1/instance-contacts/{id}         # 删除
   GET    /v1/instance-contacts/match/{agent_id}  # 查询指定实例匹配的联系人
   ```

7. **注册路由**: 在 `oxmon-server/src/api.rs` 或路由注册处添加新路由

8. **更新 OpenAPI**: 在 `oxmon-server/src/openapi.rs` 中补充文档

### Phase 4: Dictionary & Seed Data

9. **添加字典项**: 在 `dictionary_seed.rs` 中添加 `contact_type` 相关字典（如 email、phone、webhook）
10. **添加种子数据**: 可选的 `init-instance-contacts` CLI 子命令

## Risks & Considerations

| Risk | Level | Mitigation |
|------|-------|------------|
| 性能：每次告警都查 DB 匹配联系人 | LOW | 联系人数量一般很少，且 glob_match 很快；可选加内存缓存 |
| 兼容性：现有系统无联系人配置 | LOW | 无联系人时回退到现有逻辑，完全向后兼容 |
| 多联系方式覆盖：一个联系人可能只有邮箱没有手机 | LOW | 各字段 Optional，只发送到有值的渠道 |
| glob pattern 冲突：多个 pattern 匹配同一实例 | LOW | 合并所有匹配的联系人去重发送 |

## Estimated Complexity: **MEDIUM**

- Phase 1 (Database): ~2h
- Phase 2 (Notification Routing): ~2h
- Phase 3 (REST API): ~2h
- Phase 4 (Dictionary/Seed): ~0.5h
- Testing: ~1.5h
- **Total: ~8h**

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `crates/oxmon-storage/src/entities/instance_contact.rs` | **NEW** | SeaORM entity |
| `crates/oxmon-storage/src/entities/mod.rs` | EDIT | 导出新 entity |
| `crates/oxmon-storage/src/store/instance_contact.rs` | **NEW** | CRUD + 匹配查询 |
| `crates/oxmon-storage/src/store/mod.rs` | EDIT | 导出新 store module |
| `crates/oxmon-storage/src/store/migration.rs` (or init) | EDIT | 建表 SQL |
| `crates/oxmon-notify/src/manager.rs` | EDIT | 通知路由逻辑增强 |
| `crates/oxmon-server/src/api/instance_contacts.rs` | **NEW** | REST API |
| `crates/oxmon-server/src/api/mod.rs` | EDIT | 注册路由 |
| `crates/oxmon-server/src/openapi.rs` | EDIT | API 文档 |
| `crates/oxmon-server/src/dictionary_seed.rs` | EDIT | 字典种子数据 |
