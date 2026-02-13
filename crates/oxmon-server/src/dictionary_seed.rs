use chrono::Utc;
use oxmon_common::types::{DictionaryItem, DictionaryType};
use oxmon_storage::cert_store::CertStore;

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
        items.push(make_system_item("channel_type", key, label, None, order, Some(desc), &now));
    }

    // ---- severity: 告警级别 ----
    order = 0;
    for (key, label, value, desc) in [
        ("info", "信息", "1", "低级别提示"),
        ("warning", "警告", "2", "需要关注的告警"),
        ("critical", "严重", "3", "需要立即处理的告警"),
    ] {
        order += 1;
        items.push(make_system_item("severity", key, label, Some(value), order, Some(desc), &now));
    }

    // ---- rule_type: 告警规则类型 ----
    order = 0;
    for (key, label, desc) in [
        ("threshold", "阈值规则", "当指标值超过设定阈值时触发"),
        ("rate_of_change", "变化率规则", "当指标变化速率超过阈值时触发"),
        ("trend", "趋势预测规则", "根据趋势预测指标将在未来超过阈值"),
        ("cert_expiration", "证书过期规则", "证书即将过期时触发"),
    ] {
        order += 1;
        items.push(make_system_item("rule_type", key, label, None, order, Some(desc), &now));
    }

    // ---- alert_status: 告警状态 ----
    order = 0;
    for (key, label, value, desc) in [
        ("pending", "未处理", "1", "告警已触发，等待处理"),
        ("acknowledged", "已确认", "2", "告警已被确认"),
        ("resolved", "已处理", "3", "告警已被处理/关闭"),
    ] {
        order += 1;
        items.push(make_system_item("alert_status", key, label, Some(value), order, Some(desc), &now));
    }

    // ---- agent_status: Agent 状态 ----
    order = 0;
    for (key, label, desc) in [
        ("active", "在线", "Agent 正在正常上报数据"),
        ("inactive", "离线", "Agent 已超时未上报"),
        ("unknown", "未知", "Agent 状态未确定"),
    ] {
        order += 1;
        items.push(make_system_item("agent_status", key, label, None, order, Some(desc), &now));
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
        items.push(make_system_item("compare_operator", key, label, Some(value), order, Some(desc), &now));
    }

    // ---- metric_name: 系统指标名称 ----
    order = 0;
    for (key, label, desc) in [
        ("cpu.usage", "CPU 使用率", "CPU 整体使用百分比"),
        ("cpu.user", "CPU 用户态", "CPU 用户态使用百分比"),
        ("cpu.system", "CPU 系统态", "CPU 系统态使用百分比"),
        ("memory.usage", "内存使用率", "内存使用百分比"),
        ("memory.used_bytes", "已用内存", "已使用内存字节数"),
        ("memory.total_bytes", "总内存", "总内存字节数"),
        ("memory.available_bytes", "可用内存", "可用内存字节数"),
        ("disk.usage", "磁盘使用率", "磁盘使用百分比"),
        ("disk.used_bytes", "已用磁盘", "已使用磁盘字节数"),
        ("disk.total_bytes", "磁盘总量", "磁盘总容量字节数"),
        ("disk.available_bytes", "可用磁盘", "可用磁盘字节数"),
        ("disk.read_bytes_per_sec", "磁盘读速率", "磁盘每秒读取字节数"),
        ("disk.write_bytes_per_sec", "磁盘写速率", "磁盘每秒写入字节数"),
        ("network.rx_bytes_per_sec", "网络接收速率", "网络每秒接收字节数"),
        ("network.tx_bytes_per_sec", "网络发送速率", "网络每秒发送字节数"),
        ("load.load1", "1分钟负载", "系统1分钟平均负载"),
        ("load.load5", "5分钟负载", "系统5分钟平均负载"),
        ("load.load15", "15分钟负载", "系统15分钟平均负载"),
    ] {
        order += 1;
        items.push(make_system_item("metric_name", key, label, None, order, Some(desc), &now));
    }

    // ---- rule_source: 规则来源 ----
    order = 0;
    for (key, label, desc) in [
        ("api", "API 创建", "通过 REST API 创建"),
        ("seed", "种子数据", "通过 init-rules 命令导入"),
        ("toml", "TOML 迁移", "从 TOML 配置文件迁移"),
    ] {
        order += 1;
        items.push(make_system_item("rule_source", key, label, None, order, Some(desc), &now));
    }

    // ---- recipient_type: 接收人类型 ----
    order = 0;
    for (key, label, desc) in [
        ("email_address", "邮箱地址", "用于邮件通知"),
        ("phone_number", "手机号码", "用于短信通知"),
        ("webhook_url", "Webhook URL", "用于 HTTP 回调通知"),
    ] {
        order += 1;
        items.push(make_system_item("recipient_type", key, label, None, order, Some(desc), &now));
    }

    // ---- system_config_type: 系统配置类型 ----
    order = 0;
    for (key, label, desc) in [
        ("email", "邮件发送配置", "SMTP 邮件发送方配置"),
        ("sms", "短信发送配置", "短信供应商发送方配置"),
    ] {
        order += 1;
        items.push(make_system_item("system_config_type", key, label, None, order, Some(desc), &now));
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
        ("system_config_type", "系统配置类型", "系统级发送方配置的类型"),
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

/// Initialize default system dictionaries if the table is empty.
/// Returns the number of items inserted, or 0 if table already has data.
pub fn init_default_dictionaries(cert_store: &CertStore) -> anyhow::Result<usize> {
    // Always seed dictionary types (INSERT OR IGNORE ensures idempotency)
    let type_items = default_type_seed_items();
    let types_inserted = cert_store.batch_insert_dictionary_types(&type_items)?;
    if types_inserted > 0 {
        tracing::info!(types_inserted, "Initialized default dictionary types");
    }

    let count = cert_store.count_dictionaries()?;
    if count > 0 {
        tracing::info!(
            count,
            "System dictionaries already exist, skipping seed initialization"
        );
        return Ok(0);
    }

    let items = default_seed_items();
    let inserted = cert_store.batch_insert_dictionaries(&items)?;
    tracing::info!(inserted, "Initialized default system dictionaries");
    Ok(inserted)
}

/// Initialize dictionaries from a JSON seed file.
/// Uses INSERT OR IGNORE to skip duplicates.
pub fn init_from_seed_file(cert_store: &CertStore, seed_path: &str) -> anyhow::Result<usize> {
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
        let types_inserted = cert_store.batch_insert_dictionary_types(&type_items)?;
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

    let inserted = cert_store.batch_insert_dictionaries(&items)?;
    tracing::info!(
        total = items.len(),
        inserted,
        skipped = items.len() - inserted,
        "init-dictionaries completed"
    );
    Ok(inserted)
}
