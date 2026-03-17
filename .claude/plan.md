# 计划：修复深信服（Sangfor SCP）历史指标趋势为空的问题

## 问题分析

用户报告深信服云实例的历史指标趋势全部为空。经过代码分析，核心数据流为：

```
Sangfor SCP API (/metrics/{server_id})
  → fetch_metrics_for_server() 解析响应
  → get_metrics() 封装为 CloudMetrics
  → metrics_to_batch() 转为 MetricDataPoint (agent_id = "cloud:sangfor:{id}")
  → storage.write_batch() 写入数据库
  → cloud_instance_metrics() 查询并返回时间序列
```

### 已排除的问题
- **Agent ID 格式不匹配** ✅ 写入和查询都使用 `cloud:sangfor:{instance_id}`，一致
- **Provider 匹配** ✅ `collect_for_instances` 中 provider 匹配逻辑正确

### 发现的根本原因

**深信服 SCP `/metrics/{server_id}` API 调用缺少时间范围参数 `start_time` / `end_time`**

文件：`crates/oxmon-cloud/src/sangfor.rs:457-460`

```rust
let qs = format!(
    "object_type=server&metric_names={}&timegap={}",
    metric_names, self.collection_interval_secs
);
```

当前只传了 `object_type`、`metric_names` 和 `timegap`，**没有传 `start_time` 和 `end_time`**。SCP 的指标 API 在没有时间范围参数时，不同版本行为不同：
- 部分版本返回空数组（最可能的情况）
- 部分版本返回最近一个 timegap 周期的数据

这解释了为什么**所有**指标都为空，而不是个别为空。

### 次要问题

1. **日志不够详细**：`fetch_metrics_for_server` 使用 `debug` 级别记录原始响应，但未记录解析后的 metric 数量，难以在生产环境诊断问题
2. **缺少采集结果的结构化日志**：无法知道单次采集返回了多少有效指标

## 实施步骤

### Phase 1: 修复 Sangfor 指标 API 时间参数（核心修复）

**文件**: `crates/oxmon-cloud/src/sangfor.rs`

在 `fetch_metrics_for_server()` 中添加 `start_time` 和 `end_time` 参数：
- `end_time` = 当前时间戳（秒）
- `start_time` = `end_time - timegap`（确保至少覆盖一个采集周期）

修改后的查询字符串：
```rust
let end = Utc::now().timestamp();
let start = end - self.collection_interval_secs as i64;
let qs = format!(
    "object_type=server&metric_names={}&timegap={}&start_time={}&end_time={}",
    metric_names, self.collection_interval_secs, start, end
);
```

### Phase 2: 增强诊断日志

**文件**: `crates/oxmon-cloud/src/sangfor.rs`

1. 在 `fetch_metrics_for_server()` 返回前，记录解析到的指标数量和具体指标名：
   ```rust
   tracing::info!(
       account = %self.account_name,
       server_id = %server_id,
       metrics_count = result.len(),
       metrics = ?result.keys().collect::<Vec<_>>(),
       "Sangfor SCP metrics parsed"
   );
   ```

2. 当 `data` 为 null 或空对象时，用 `warn` 级别记录完整响应结构（而非 debug），便于生产环境排查。

### Phase 3: 编译验证

运行 `cargo build --release` 和 `cargo clippy --workspace -- -D warnings` 确认无编译/lint 错误。

## 风险评估

- **低风险**：修改仅影响 Sangfor SCP 的指标 API 查询参数，不影响腾讯云/阿里云
- **向后兼容**：即使旧版 SCP 忽略 `start_time`/`end_time` 参数，也不会导致错误
- **可回退**：如果添加时间参数后仍然为空，可以通过日志快速定位实际返回的数据结构
