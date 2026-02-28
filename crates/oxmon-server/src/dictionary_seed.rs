use chrono::Utc;
use oxmon_common::types::{DictionaryItem, DictionaryType};
use oxmon_storage::CertStore;

/// Build the default dictionary seed items (all marked as `is_system = true`).
pub fn default_seed_items() -> Vec<DictionaryItem> {
    let now = Utc::now();
    let mut items = Vec::new();
    let mut order: i32;

    // ---- channel_type: 通知渠道类型 ----
    order = 0;
    for (key, label, desc) in [
        ("email", "邮件", "SMTP 邮件通知"),
        ("webhook", "Webhook", "HTTP Webhook 回调"),
        ("sms_aliyun", "阿里云短信", "阿里云短信服务"),
        ("sms_tencent", "腾讯云短信", "腾讯云短信服务"),
        ("sms_generic", "通用短信", "通用 HTTP 短信网关"),
        ("dingtalk", "钉钉", "钉钉机器人通知"),
        ("weixin", "企业微信", "企业微信机器人通知"),
    ] {
        order += 1;
        items.push(make_system_item(
            "channel_type",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- severity: 告警级别 ----
    order = 0;
    for (key, label, value, desc) in [
        ("info", "信息", "1", "低级别提示"),
        ("warning", "警告", "2", "需要关注的告警"),
        ("critical", "严重", "3", "需要立即处理的告警"),
    ] {
        order += 1;
        items.push(make_system_item(
            "severity",
            key,
            label,
            Some(value),
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- rule_type: 告警规则类型 ----
    order = 0;
    for (key, label, desc) in [
        ("threshold", "阈值规则", "当指标值超过设定阈值时触发"),
        (
            "rate_of_change",
            "变化率规则",
            "当指标变化速率超过阈值时触发",
        ),
        ("trend", "趋势预测规则", "根据趋势预测指标将在未来超过阈值"),
        ("cert_expiration", "证书过期规则", "证书即将过期时触发"),
        (
            "cloud_scale",
            "云实例伸缩规则",
            "云实例 CPU/内存长期过高或过低时推荐扩缩容",
        ),
    ] {
        order += 1;
        items.push(make_system_item(
            "rule_type",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- alert_status: 告警状态 ----
    order = 0;
    for (key, label, value, desc) in [
        ("pending", "未处理", "1", "告警已触发，等待处理"),
        ("acknowledged", "已确认", "2", "告警已被确认"),
        ("resolved", "已处理", "3", "告警已被处理/关闭"),
    ] {
        order += 1;
        items.push(make_system_item(
            "alert_status",
            key,
            label,
            Some(value),
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- agent_status: Agent 状态 ----
    order = 0;
    for (key, label, desc) in [
        ("active", "在线", "Agent 正在正常上报数据"),
        ("inactive", "离线", "Agent 已超时未上报"),
        ("unknown", "未知", "Agent 状态未确定"),
    ] {
        order += 1;
        items.push(make_system_item(
            "agent_status",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- compare_operator: 比较运算符 ----
    order = 0;
    for (key, label, value, desc) in [
        ("gt", "大于", ">", "值大于阈值"),
        ("gte", "大于等于", ">=", "值大于等于阈值"),
        ("lt", "小于", "<", "值小于阈值"),
        ("lte", "小于等于", "<=", "值小于等于阈值"),
        ("eq", "等于", "==", "值等于阈值"),
        ("ne", "不等于", "!=", "值不等于阈值"),
    ] {
        order += 1;
        items.push(make_system_item(
            "compare_operator",
            key,
            label,
            Some(value),
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- metric_name: 系统指标名称（与 oxmon-collector 实际上报一致） ----
    order = 0;
    for (key, label, desc) in [
        ("cpu.usage", "CPU 使用率", "CPU 整体使用百分比"),
        (
            "cpu.core_usage",
            "CPU 核心使用率",
            "单个 CPU 核心使用百分比",
        ),
        ("memory.total", "总内存", "总内存字节数"),
        ("memory.used", "已用内存", "已使用内存字节数"),
        ("memory.available", "可用内存", "可用内存字节数"),
        ("memory.used_percent", "内存使用率", "内存使用百分比"),
        ("memory.swap_total", "交换区总量", "交换区总字节数"),
        ("memory.swap_used", "已用交换区", "已使用交换区字节数"),
        ("memory.swap_percent", "交换区使用率", "交换区使用百分比"),
        ("disk.total", "磁盘总量", "磁盘总容量字节数"),
        ("disk.used", "已用磁盘", "已使用磁盘字节数"),
        ("disk.available", "可用磁盘", "可用磁盘字节数"),
        (
            "disk.used_percent",
            "磁盘使用率",
            "磁盘已用空间占总空间百分比",
        ),
        (
            "network.bytes_recv",
            "网络接收字节数",
            "网络接收字节数(采集间隔内增量)",
        ),
        (
            "network.bytes_sent",
            "网络发送字节数",
            "网络发送字节数(采集间隔内增量)",
        ),
        (
            "network.packets_recv",
            "网络接收包数",
            "网络接收数据包数(采集间隔内增量)",
        ),
        (
            "network.packets_sent",
            "网络发送包数",
            "网络发送数据包数(采集间隔内增量)",
        ),
        ("system.load_1", "1分钟负载", "系统1分钟平均负载"),
        ("system.load_5", "5分钟负载", "系统5分钟平均负载"),
        ("system.load_15", "15分钟负载", "系统15分钟平均负载"),
        ("system.uptime", "系统运行时长", "系统启动后运行秒数"),
        (
            "certificate.days_until_expiry",
            "证书剩余天数",
            "SSL/TLS 证书距离过期的天数",
        ),
        (
            "certificate.is_valid",
            "证书是否有效",
            "SSL/TLS 证书链校验结果，有效为 1.0，无效为 0.0",
        ),
        (
            "cloud.cpu.usage",
            "云主机CPU使用率",
            "云实例 CPU 使用百分比 (0-100)",
        ),
        (
            "cloud.memory.usage",
            "云主机内存使用率",
            "云实例内存使用百分比 (0-100)",
        ),
        (
            "cloud.disk.usage",
            "云主机磁盘使用率",
            "云实例磁盘使用百分比 (0-100)",
        ),
        (
            "cloud.network.in_bytes",
            "云主机入流量",
            "云实例网络入流量速率 (bytes/s)",
        ),
        (
            "cloud.network.out_bytes",
            "云主机出流量",
            "云实例网络出流量速率 (bytes/s)",
        ),
        (
            "cloud.disk.iops_read",
            "云主机磁盘读IOPS",
            "云实例磁盘读取操作次数/秒",
        ),
        (
            "cloud.disk.iops_write",
            "云主机磁盘写IOPS",
            "云实例磁盘写入操作次数/秒",
        ),
        (
            "cloud.connections",
            "云主机TCP连接数",
            "云实例当前 TCP 连接数",
        ),
    ] {
        order += 1;
        items.push(make_system_item(
            "metric_name",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- rule_source: 规则来源 ----
    order = 0;
    for (key, label, desc) in [
        ("api", "API 创建", "通过 REST API 创建"),
        ("seed", "种子数据", "通过 init-rules 命令导入"),
        ("toml", "TOML 迁移", "从 TOML 配置文件迁移"),
    ] {
        order += 1;
        items.push(make_system_item(
            "rule_source",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- recipient_type: 接收人类型 ----
    order = 0;
    for (key, label, desc) in [
        ("email_address", "邮箱地址", "用于邮件通知"),
        ("phone_number", "手机号码", "用于短信通知"),
        ("webhook_url", "Webhook URL", "用于 HTTP 回调通知"),
    ] {
        order += 1;
        items.push(make_system_item(
            "recipient_type",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- system_config_type: 系统配置类型 ----
    order = 0;
    for (key, label, desc) in [
        ("email", "邮件发送配置", "SMTP 邮件发送方配置"),
        ("sms", "短信发送配置", "短信供应商发送方配置"),
    ] {
        order += 1;
        items.push(make_system_item(
            "system_config_type",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- language: 系统语言 ----
    order = 0;
    for (key, label, desc) in [
        ("zh-CN", "简体中文", "Chinese Simplified"),
        ("en", "English", "English"),
    ] {
        order += 1;
        items.push(make_system_item(
            "language",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- cloud_provider: 云服务提供商 ----
    order = 0;
    for (key, label, desc) in [
        ("tencent", "腾讯云", "Tencent Cloud"),
        ("alibaba", "阿里云", "Alibaba Cloud"),
        (
            "aws",
            "亚马逊云",
            "Amazon Web Services (reserved for future use)",
        ),
    ] {
        order += 1;
        items.push(make_system_item(
            "cloud_provider",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- cloud_instance_status: 云实例状态 ----
    order = 0;
    for (key, label, desc) in [
        (
            "PENDING",
            "创建中",
            "Tencent Cloud: Instance is pending/provisioning",
        ),
        ("Pending", "创建中", "Alibaba Cloud: Instance is pending"),
        ("RUNNING", "运行中", "Tencent Cloud: Instance is running"),
        ("Running", "运行中", "Alibaba Cloud: Instance is running"),
        ("STOPPED", "已停止", "Tencent Cloud: Instance is stopped"),
        ("Stopped", "已停止", "Alibaba Cloud: Instance is stopped"),
        ("STARTING", "启动中", "Tencent Cloud: Instance is starting"),
        ("Starting", "启动中", "Alibaba Cloud: Instance is starting"),
        ("STOPPING", "停止中", "Tencent Cloud: Instance is stopping"),
        ("Stopping", "停止中", "Alibaba Cloud: Instance is stopping"),
        (
            "REBOOTING",
            "重启中",
            "Tencent Cloud: Instance is rebooting",
        ),
        (
            "Rebooting",
            "重启中",
            "Alibaba Cloud: Instance is rebooting",
        ),
        (
            "RESETTING",
            "重置中",
            "Tencent Cloud: Instance is resetting",
        ),
        (
            "REINSTALLING",
            "重装中",
            "Tencent Cloud: Instance is reinstalling OS",
        ),
        (
            "MIGRATING",
            "迁移中",
            "Tencent Cloud: Instance is migrating",
        ),
        (
            "LAUNCH_FAILED",
            "启动失败",
            "Tencent Cloud: Instance launch failed",
        ),
        ("FAILED", "失败", "Generic: instance operation failed"),
        ("Error", "异常", "Generic: instance is in error state"),
        ("ERROR", "异常", "Generic: instance is in error state"),
        ("SHUTDOWN", "已关机", "Tencent Cloud: Instance is shutdown"),
        ("Terminated", "已终止", "Generic: instance terminated"),
        ("TERMINATED", "已终止", "Generic: instance terminated"),
    ] {
        order += 1;
        items.push(make_system_item(
            "cloud_instance_status",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- cloud_charge_type: 计费类型 ----
    order = 0;
    for (key, label, desc) in [
        ("PREPAID", "包年包月", "Tencent Cloud: Prepaid billing"),
        ("PrePaid", "包年包月", "Alibaba Cloud: Prepaid billing"),
        (
            "POSTPAID_BY_HOUR",
            "按量计费",
            "Tencent Cloud: Postpaid by hour",
        ),
        ("PostPaid", "按量计费", "Alibaba Cloud: Postpaid billing"),
        ("SPOTPAID", "竞价实例", "Tencent Cloud: Spot instance"),
    ] {
        order += 1;
        items.push(make_system_item(
            "cloud_charge_type",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- cloud_internet_charge_type: 网络计费类型 ----
    order = 0;
    for (key, label, desc) in [
        (
            "TRAFFIC_POSTPAID_BY_HOUR",
            "按流量计费",
            "Tencent Cloud: Pay by traffic usage",
        ),
        (
            "PayByTraffic",
            "按流量计费",
            "Alibaba Cloud: Pay by traffic usage",
        ),
        (
            "BANDWIDTH_POSTPAID_BY_HOUR",
            "按带宽计费",
            "Tencent Cloud: Pay by bandwidth (postpaid hourly)",
        ),
        (
            "PayByBandwidth",
            "按带宽计费",
            "Alibaba Cloud: Pay by bandwidth",
        ),
    ] {
        order += 1;
        items.push(make_system_item(
            "cloud_internet_charge_type",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- cloud_io_optimized: IO优化状态 ----
    order = 0;
    for (key, label, desc) in [
        (
            "optimized",
            "已优化",
            "Alibaba Cloud: IO optimized instance",
        ),
        ("none", "非优化", "Alibaba Cloud: Non-IO optimized instance"),
    ] {
        order += 1;
        items.push(make_system_item(
            "cloud_io_optimized",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- cloud_auto_renew: 自动续费标识 ----
    order = 0;
    for (key, label, desc) in [
        (
            "NOTIFY_AND_AUTO_RENEW",
            "自动续费",
            "Tencent Cloud: Notify and auto-renew",
        ),
        (
            "NOTIFY_AND_MANUAL_RENEW",
            "手动续费",
            "Tencent Cloud: Notify but require manual renewal",
        ),
        (
            "DISABLE_NOTIFY_AND_MANUAL_RENEW",
            "不续费",
            "Tencent Cloud: Do not notify and do not renew",
        ),
        ("enabled", "自动续费", "Alibaba Cloud: Auto-renewal enabled"),
        (
            "disabled",
            "手动续费",
            "Alibaba Cloud: Auto-renewal disabled",
        ),
    ] {
        order += 1;
        items.push(make_system_item(
            "cloud_auto_renew",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- cloud_operation_state: 操作状态 ----
    order = 0;
    for (key, label, value, desc) in [
        ("SUCCESS", "成功", "1", "Operation completed successfully"),
        ("OPERATING", "执行中", "2", "Operation is in progress"),
        ("FAILED", "失败", "3", "Operation failed"),
    ] {
        order += 1;
        items.push(make_system_item(
            "cloud_operation_state",
            key,
            label,
            Some(value),
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- ai_provider: AI 模型提供商 ----
    order = 0;
    for (key, label, desc) in [
        ("zhipu", "智谱AI", "智谱 GLM 系列大模型（默认）"),
        ("kimi", "Kimi", "月之暗面 Moonshot 系列"),
        ("minimax", "MiniMax", "MiniMax 大模型"),
        ("claude", "Claude", "Anthropic Claude 系列"),
        ("codex", "Codex", "OpenAI Codex/GPT 系列"),
        ("custom", "自定义", "用户自定义模型"),
    ] {
        order += 1;
        items.push(make_system_item(
            "ai_provider",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- ai_model: AI 模型名称（预置常用模型）----
    order = 0;
    for (key, label, desc) in [
        ("glm-5", "GLM-5", "智谱 GLM-5 模型（推荐）"),
        ("glm-4", "GLM-4", "智谱 GLM-4 模型"),
        ("moonshot-v1-32k", "Moonshot V1 32K", "Kimi 32K 上下文模型"),
        (
            "moonshot-v1-128k",
            "Moonshot V1 128K",
            "Kimi 128K 上下文模型",
        ),
        ("abab6.5-chat", "ABAB 6.5 Chat", "MiniMax ABAB 6.5 对话模型"),
        (
            "claude-3-5-sonnet-20241022",
            "Claude 3.5 Sonnet",
            "Claude 3.5 Sonnet",
        ),
        ("claude-3-opus-20240229", "Claude 3 Opus", "Claude 3 Opus"),
        ("gpt-4", "GPT-4", "OpenAI GPT-4"),
        ("gpt-4-turbo", "GPT-4 Turbo", "OpenAI GPT-4 Turbo"),
        ("custom", "自定义模型", "用户自定义模型名称"),
    ] {
        order += 1;
        items.push(make_system_item(
            "ai_model",
            key,
            label,
            None,
            order,
            Some(desc),
            &now,
        ));
    }

    // ---- ai_risk_level: AI 分析风险等级 ----
    order = 0;
    for (key, label, value, desc) in [
        ("high", "高风险", "3", "需要立即人工介入处理"),
        ("medium", "中风险", "2", "需要持续关注"),
        ("low", "低风险", "1", "轻微问题，可延后处理"),
        ("normal", "正常", "0", "系统运行状态良好"),
    ] {
        order += 1;
        items.push(make_system_item(
            "ai_risk_level",
            key,
            label,
            Some(value),
            order,
            Some(desc),
            &now,
        ));
    }

    items
}

/// Build the default dictionary type seed items.
pub fn default_type_seed_items() -> Vec<DictionaryType> {
    let now = Utc::now();
    let mut types = Vec::new();

    for (i, (dict_type, label, desc)) in [
        ("channel_type", "通知渠道类型", "通知渠道类型分类"),
        ("severity", "告警级别", "告警严重程度级别"),
        ("rule_type", "告警规则类型", "告警规则的触发类型"),
        ("alert_status", "告警状态", "告警事件的处理状态"),
        ("agent_status", "Agent 状态", "监控 Agent 的在线状态"),
        ("compare_operator", "比较运算符", "告警规则中的比较运算符"),
        ("metric_name", "系统指标名称", "可监控的系统指标"),
        ("rule_source", "规则来源", "告警规则的创建来源"),
        ("recipient_type", "接收人类型", "通知接收人的类型"),
        (
            "system_config_type",
            "系统配置类型",
            "系统级发送方配置的类型",
        ),
        ("language", "系统语言", "系统支持的语言选项"),
        ("cloud_provider", "云服务提供商", "云服务提供商类型"),
        ("cloud_instance_status", "云实例状态", "云实例运行状态"),
        ("cloud_charge_type", "计费类型", "云实例计费模式"),
        (
            "cloud_internet_charge_type",
            "网络计费类型",
            "云实例网络带宽计费类型",
        ),
        ("cloud_io_optimized", "IO优化状态", "云实例 IO 优化状态"),
        ("cloud_auto_renew", "自动续费标识", "云实例自动续费设置"),
        ("cloud_operation_state", "操作状态", "云实例操作执行状态"),
        ("ai_provider", "AI 模型提供商", "AI 大模型提供商类型"),
        ("ai_model", "AI 模型名称", "AI 模型的具体名称"),
        ("ai_risk_level", "AI 风险等级", "AI 分析得出的风险等级"),
    ]
    .into_iter()
    .enumerate()
    {
        types.push(DictionaryType {
            dict_type: dict_type.to_string(),
            dict_type_label: label.to_string(),
            sort_order: (i + 1) as i32,
            description: Some(desc.to_string()),
            created_at: now,
            updated_at: now,
        });
    }

    types
}

fn make_system_item(
    dict_type: &str,
    key: &str,
    label: &str,
    value: Option<&str>,
    sort_order: i32,
    description: Option<&str>,
    now: &chrono::DateTime<Utc>,
) -> DictionaryItem {
    DictionaryItem {
        id: oxmon_common::id::next_id(),
        dict_type: dict_type.to_string(),
        dict_key: key.to_string(),
        dict_label: label.to_string(),
        dict_value: value.map(|v| v.to_string()),
        sort_order,
        enabled: true,
        is_system: true,
        description: description.map(|d| d.to_string()),
        extra_json: None,
        created_at: *now,
        updated_at: *now,
    }
}

/// Sync default system dictionaries on every startup.
///
/// - Dictionary types: upsert all, delete stale types no longer in seed
/// - Dictionary items (is_system=true): upsert all, disable stale items no longer in seed
///
/// This ensures code-level changes to system dictionaries are always reflected in the DB.
pub async fn init_default_dictionaries(cert_store: &CertStore) -> anyhow::Result<usize> {
    // 1. Sync dictionary types
    let type_items = default_type_seed_items();
    let (types_inserted, types_updated) = cert_store
        .upsert_system_dictionary_types(&type_items)
        .await?;
    if types_inserted > 0 || types_updated > 0 {
        tracing::info!(
            types_inserted,
            types_updated,
            "Synced system dictionary types"
        );
    }

    // 2. Sync system dictionary items
    let items = default_seed_items();
    let (items_inserted, items_updated) = cert_store.upsert_system_dictionaries(&items).await?;
    if items_inserted > 0 || items_updated > 0 {
        tracing::info!(
            items_inserted,
            items_updated,
            "Synced system dictionary items"
        );
    }

    // 3. Disable system items that no longer exist in seed data
    let active_keys: Vec<(String, String)> = items
        .iter()
        .map(|i| (i.dict_type.clone(), i.dict_key.clone()))
        .collect();
    let disabled = cert_store
        .disable_stale_system_dictionaries(&active_keys)
        .await?;
    if disabled > 0 {
        tracing::info!(disabled, "Disabled stale system dictionary items");
    }

    // 4. Delete dictionary types that no longer exist in seed data
    let active_types: Vec<String> = type_items.iter().map(|t| t.dict_type.clone()).collect();
    let types_deleted = cert_store
        .delete_stale_dictionary_types(&active_types)
        .await?;
    if types_deleted > 0 {
        tracing::info!(types_deleted, "Deleted stale dictionary types");
    }

    Ok(items_inserted + items_updated + disabled)
}

/// Initialize dictionaries from a JSON seed file.
/// Uses INSERT OR IGNORE to skip duplicates.
pub async fn init_from_seed_file(cert_store: &CertStore, seed_path: &str) -> anyhow::Result<usize> {
    let seed_content = std::fs::read_to_string(seed_path)
        .map_err(|e| anyhow::anyhow!("Failed to read seed file '{}': {}", seed_path, e))?;
    let seed: crate::config::DictionariesSeedFile = serde_json::from_str(&seed_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse seed file '{}': {}", seed_path, e))?;

    let now = Utc::now();

    // Insert dictionary types from seed file if present
    if let Some(seed_types) = seed.dictionary_types {
        let type_items: Vec<DictionaryType> = seed_types
            .into_iter()
            .map(|s| DictionaryType {
                dict_type: s.dict_type,
                dict_type_label: s.dict_type_label,
                sort_order: s.sort_order.unwrap_or(0),
                description: s.description,
                created_at: now,
                updated_at: now,
            })
            .collect();
        let types_inserted = cert_store
            .batch_insert_dictionary_types(&type_items)
            .await?;
        tracing::info!(
            total = type_items.len(),
            types_inserted,
            "init-dictionaries: dictionary types processed"
        );
    }

    let items: Vec<DictionaryItem> = seed
        .dictionaries
        .into_iter()
        .map(|s| DictionaryItem {
            id: oxmon_common::id::next_id(),
            dict_type: s.dict_type,
            dict_key: s.dict_key,
            dict_label: s.dict_label,
            dict_value: s.dict_value,
            sort_order: s.sort_order.unwrap_or(0),
            enabled: s.enabled.unwrap_or(true),
            is_system: s.is_system.unwrap_or(false),
            description: s.description,
            extra_json: s.extra_json,
            created_at: now,
            updated_at: now,
        })
        .collect();

    let inserted = cert_store.batch_insert_dictionaries(&items).await?;
    tracing::info!(
        total = items.len(),
        inserted,
        skipped = items.len() - inserted,
        "init-dictionaries completed"
    );
    Ok(inserted)
}
