use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDataPoint {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub metric_name: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricBatch {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub data_points: Vec<MetricDataPoint>,
}

/// Alert severity level, ordered from lowest to highest.
///
/// # Examples
///
/// ```
/// use oxmon_common::types::Severity;
///
/// let sev: Severity = "warning".parse().unwrap();
/// assert_eq!(sev, Severity::Warning);
/// assert_eq!(sev.to_string(), "warning");
/// assert!(Severity::Critical > Severity::Info);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "warning" => Ok(Severity::Warning),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!("unknown severity: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub id: String,
    pub rule_id: String,
    /// Human-readable rule name (e.g., "生产环境 CPU 过高")
    pub rule_name: String,
    pub agent_id: String,
    pub metric_name: String,
    pub severity: Severity,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
    pub timestamp: DateTime<Utc>,
    /// For trend prediction rules: predicted time to breach
    pub predicted_breach: Option<DateTime<Utc>>,
    /// Status: 1=未处理, 2=已确认, 3=已处理
    pub status: u8,
    /// Labels from the triggering metric data point (e.g., mount=/data, interface=eth0)
    pub labels: HashMap<String, String>,
    /// Timestamp when this alert was first triggered (for recovery tracking)
    pub first_triggered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Format labels map into a human-readable string.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use oxmon_common::types::format_labels;
///
/// let mut labels = HashMap::new();
/// labels.insert("mount".to_string(), "/data".to_string());
/// labels.insert("device".to_string(), "sda1".to_string());
/// let s = format_labels(&labels);
/// // Output contains both key=value pairs separated by ", "
/// assert!(s.contains("mount=/data"));
/// assert!(s.contains("device=sda1"));
/// ```
pub fn format_labels(labels: &HashMap<String, String>) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    pairs.sort();
    pairs.join(", ")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// 数据库 ID（agents 表主键）
    pub id: String,
    pub agent_id: String,
    pub last_seen: DateTime<Utc>,
    pub active: bool,
    pub collection_interval_secs: Option<u64>,
    pub description: Option<String>,
}

/// Agent 完整记录（来自 agents 表）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEntry {
    /// 数据库 ID
    pub id: String,
    /// Agent 唯一标识
    pub agent_id: String,
    /// 首次上报时间
    pub first_seen: DateTime<Utc>,
    /// 最后上报时间
    pub last_seen: DateTime<Utc>,
    /// 采集间隔（秒）
    pub collection_interval_secs: Option<u64>,
    /// 描述信息
    pub description: Option<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

// Certificate domain monitoring types

/// 证书监控域名
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CertDomain {
    /// 域名唯一标识
    pub id: String,
    /// 监控域名（必填，如 example.com）
    pub domain: String,
    /// 端口号
    pub port: i32,
    /// 是否启用监控
    pub enabled: bool,
    /// 检查间隔秒数（可选）
    pub check_interval_secs: Option<u64>,
    /// 备注（可选）
    pub note: Option<String>,
    /// 最后检查时间
    pub last_checked_at: Option<DateTime<Utc>>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

/// 证书检查结果
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CertCheckResult {
    /// 结果唯一标识
    pub id: String,
    /// 关联域名 ID
    pub domain_id: String,
    /// 域名地址
    pub domain: String,
    /// 证书是否有效
    pub is_valid: bool,
    /// 证书链是否有效
    pub chain_valid: bool,
    /// 证书生效时间
    pub not_before: Option<DateTime<Utc>>,
    /// 证书过期时间
    pub not_after: Option<DateTime<Utc>>,
    /// 距离过期天数
    pub days_until_expiry: Option<i64>,
    /// 证书颁发者
    pub issuer: Option<String>,
    /// 证书主体
    pub subject: Option<String>,
    /// 主体备用名称列表（SAN）
    pub san_list: Option<Vec<String>>,
    /// 域名解析 IP 地址列表
    pub resolved_ips: Option<Vec<String>>,
    /// 错误信息
    pub error: Option<String>,
    /// 检查时间
    pub checked_at: DateTime<Utc>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

/// 创建域名请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateDomainRequest {
    /// 监控域名（必填，如 example.com）
    pub domain: String,
    /// 监控端口（可选，默认 443）
    pub port: Option<i32>,
    /// 检查间隔秒数（可选）
    pub check_interval_secs: Option<u64>,
    /// 备注（可选）
    pub note: Option<String>,
}

/// 更新域名请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateDomainRequest {
    /// 监控端口（可选）
    pub port: Option<i32>,
    /// 是否启用监控（可选）
    pub enabled: Option<bool>,
    /// 检查间隔秒数（可选；传 null 清除自定义值）
    pub check_interval_secs: Option<Option<u64>>,
    /// 备注（可选）
    pub note: Option<String>,
}

/// 批量创建域名请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BatchCreateDomainsRequest {
    /// 待新增监控域名列表（必填）
    pub domains: Vec<CreateDomainRequest>,
}

// Agent whitelist types

/// Agent 白名单条目
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AgentWhitelistEntry {
    /// 唯一标识
    pub id: String,
    /// Agent 唯一标识
    pub agent_id: String,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
    /// 描述信息
    pub description: Option<String>,
    /// 认证 Token（用于 Agent gRPC 配置）
    pub token: Option<String>,
    /// 采集间隔（秒），用于判断活跃状态。如果未设置，使用全局配置
    pub collection_interval_secs: Option<u64>,
}

/// 添加 Agent 到白名单请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AddAgentRequest {
    /// Agent ID（必填，需全局唯一）
    pub agent_id: String,
    /// 描述信息（可选）
    pub description: Option<String>,
    /// 采集间隔（秒），用于判断活跃状态。如果未设置，使用服务器全局配置
    pub collection_interval_secs: Option<u64>,
}

/// 添加 Agent 响应（包含生成的 token）
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AddAgentResponse {
    /// 唯一标识
    pub id: String,
    /// Agent 唯一标识
    pub agent_id: String,
    /// 生成的认证 token（仅在创建时返回一次）
    pub token: String,
    /// 创建时间
    pub created_at: DateTime<Utc>,
}

/// 更新 Agent 白名单请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateAgentRequest {
    /// 描述信息（可选）
    pub description: Option<String>,
    /// 采集间隔（秒），用于判断活跃状态。如果未设置，使用服务器全局配置
    pub collection_interval_secs: Option<u64>,
}

/// Agent 白名单详情（包含在线状态）
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AgentWhitelistDetail {
    /// 唯一标识
    pub id: String,
    /// Agent 唯一标识
    pub agent_id: String,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
    /// 描述信息
    pub description: Option<String>,
    /// 认证 Token（用于 Agent gRPC 配置）
    pub token: Option<String>,
    /// 采集间隔（秒），用于判断活跃状态。如果未设置，使用服务器全局配置
    pub collection_interval_secs: Option<u64>,
    /// 最后上报时间
    pub last_seen: Option<DateTime<Utc>>,
    /// 在线状态（active / inactive / unknown）
    pub status: String,
}

/// 重新生成 Token 响应
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RegenerateTokenResponse {
    /// Agent 唯一标识
    pub agent_id: String,
    /// 新生成的认证 token
    pub token: String,
}

// Certificate details types

/// 证书详细信息
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CertificateDetails {
    /// 唯一标识
    pub id: String,
    /// 域名
    pub domain: String,
    /// 证书生效时间
    pub not_before: DateTime<Utc>,
    /// 证书过期时间
    pub not_after: DateTime<Utc>,
    /// IP 地址列表
    pub ip_addresses: Vec<String>,
    /// 颁发者通用名称
    pub issuer_cn: Option<String>,
    /// 颁发者组织
    pub issuer_o: Option<String>,
    /// 颁发者组织单位
    pub issuer_ou: Option<String>,
    /// 颁发者国家
    pub issuer_c: Option<String>,
    /// 主体备用名称列表
    pub subject_alt_names: Vec<String>,
    /// 证书链是否有效
    pub chain_valid: bool,
    /// 证书链错误信息
    pub chain_error: Option<String>,
    /// 最后检查时间
    pub last_checked: DateTime<Utc>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,

    // ---- 新增字段 ----
    /// 证书序列号（十六进制）
    pub serial_number: Option<String>,
    /// 证书 SHA-256 指纹
    pub fingerprint_sha256: Option<String>,
    /// 证书版本（1/2/3）
    pub version: Option<i32>,
    /// 签名算法（如 SHA256withRSA）
    pub signature_algorithm: Option<String>,
    /// 公钥算法（RSA, ECDSA, Ed25519）
    pub public_key_algorithm: Option<String>,
    /// 公钥长度（如 2048, 4096, 256）
    pub public_key_bits: Option<i32>,
    /// 主体通用名称
    pub subject_cn: Option<String>,
    /// 主体组织
    pub subject_o: Option<String>,
    /// 密钥用途（JSON 数组）
    pub key_usage: Option<Vec<String>>,
    /// 扩展密钥用途（JSON 数组）
    pub extended_key_usage: Option<Vec<String>>,
    /// 是否 CA 证书
    pub is_ca: Option<bool>,
    /// 是否通配符证书
    pub is_wildcard: Option<bool>,
    /// OCSP 响应器地址（JSON 数组）
    pub ocsp_urls: Option<Vec<String>>,
    /// CRL 分发点（JSON 数组）
    pub crl_urls: Option<Vec<String>>,
    /// CA 颁发者 URL（JSON 数组）
    pub ca_issuer_urls: Option<Vec<String>>,
    /// Certificate Transparency SCT 数量
    pub sct_count: Option<i32>,
    /// 协商的 TLS 版本
    pub tls_version: Option<String>,
    /// 协商的加密套件
    pub cipher_suite: Option<String>,
    /// 证书链深度
    pub chain_depth: Option<i32>,
}

/// 证书详情查询过滤器
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CertificateDetailsFilter {
    /// 域名包含匹配
    pub domain_contains: Option<String>,
    /// 证书过期时间上界（Unix 秒级时间戳）
    pub not_after_lte: Option<i64>,
    /// 证书过期时间下界（Unix 秒级时间戳）
    pub not_after_gte: Option<i64>,
    /// 证书链是否有效（精确匹配）
    pub chain_valid_eq: Option<bool>,
    /// 证书是否有效（证书列表语义，等价映射到 chain_valid）
    pub is_valid_eq: Option<bool>,
    /// 证书链错误精确匹配
    pub chain_error_eq: Option<String>,
    /// 最后检查时间下界（Unix 秒级时间戳）
    pub last_checked_gte: Option<i64>,
    /// 最后检查时间上界（Unix 秒级时间戳）
    pub last_checked_lte: Option<i64>,
    /// IP 包含匹配
    pub ip_address_contains: Option<String>,
    /// 颁发者包含匹配
    pub issuer_contains: Option<String>,
    /// TLS 版本精确匹配
    pub tls_version_eq: Option<String>,
}

// User & Auth types

/// 用户帐号
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct User {
    /// 唯一标识
    pub id: String,
    /// 登录用户名（必填）
    pub username: String,
    /// 密码哈希（bcrypt）
    #[serde(skip_serializing)]
    pub password_hash: String,
    /// Token 版本（用于密码修改后的 JWT 失效）
    #[serde(skip_serializing)]
    pub token_version: i64,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

/// 登录请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LoginRequest {
    /// 登录用户名（必填）
    pub username: String,
    /// RSA-OAEP 加密后的密码（Base64 编码，必填）
    pub encrypted_password: String,
}

/// 登录响应
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LoginResponse {
    /// JWT Access Token
    pub access_token: String,
    /// Token 有效期（秒）
    pub expires_in: u64,
}

/// 修改密码请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChangePasswordRequest {
    /// RSA-OAEP 加密后的当前密码（Base64 编码，必填）
    pub encrypted_current_password: String,
    /// RSA-OAEP 加密后的新密码（Base64 编码，必填）
    pub encrypted_new_password: String,
}

/// 公钥响应
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PublicKeyResponse {
    /// RSA 公钥（PEM 格式）
    pub public_key: String,
    /// 加密算法标识
    pub algorithm: String,
}

// ---- System dictionary types ----

/// 系统字典条目
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DictionaryItem {
    /// 唯一标识
    pub id: String,
    /// 字典类型（如 channel_type, severity, rule_type 等）
    pub dict_type: String,
    /// 字典键（英文标识，同一 dict_type 下唯一）
    pub dict_key: String,
    /// 显示标签（中文/英文）
    pub dict_label: String,
    /// 字典值（可选，用于存放额外值）
    pub dict_value: Option<String>,
    /// 排序序号
    pub sort_order: i32,
    /// 是否启用
    pub enabled: bool,
    /// 是否系统内置（系统内置项不可删除）
    pub is_system: bool,
    /// 描述信息
    pub description: Option<String>,
    /// 扩展 JSON（可选，用于存放额外配置）
    pub extra_json: Option<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

/// 创建字典条目请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateDictionaryRequest {
    /// 字典类型（必填）
    pub dict_type: String,
    /// 字典键（必填，同一 dict_type 下唯一）
    pub dict_key: String,
    /// 显示标签（必填）
    pub dict_label: String,
    /// 字典值（可选）
    pub dict_value: Option<String>,
    /// 排序序号（可选，默认 0）
    pub sort_order: Option<i32>,
    /// 是否启用（可选，默认 true）
    pub enabled: Option<bool>,
    /// 描述信息（可选）
    pub description: Option<String>,
    /// 扩展 JSON（可选）
    pub extra_json: Option<String>,
}

/// 更新字典条目请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateDictionaryRequest {
    /// 显示标签（可选）
    pub dict_label: Option<String>,
    /// 字典值（可选）
    pub dict_value: Option<Option<String>>,
    /// 排序序号（可选）
    pub sort_order: Option<i32>,
    /// 是否启用（可选）
    pub enabled: Option<bool>,
    /// 描述信息（可选）
    pub description: Option<Option<String>>,
    /// 扩展 JSON（可选）
    pub extra_json: Option<Option<String>>,
}

/// 字典类型摘要
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DictionaryTypeSummary {
    /// 字典类型
    pub dict_type: String,
    /// 字典类型显示标签（中文名称）
    pub dict_type_label: String,
    /// 该类型下的条目数量
    pub count: u64,
}

/// 字典类型元数据
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DictionaryType {
    /// 字典类型标识（主键）
    pub dict_type: String,
    /// 显示标签（中文名称）
    pub dict_type_label: String,
    /// 排序序号
    pub sort_order: i32,
    /// 描述信息
    pub description: Option<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

/// 创建字典类型请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateDictionaryTypeRequest {
    /// 字典类型标识（必填，如 channel_type）
    pub dict_type: String,
    /// 显示标签（必填，如 "通知渠道类型"）
    pub dict_type_label: String,
    /// 排序序号（可选，默认 0）
    pub sort_order: Option<i32>,
    /// 描述信息（可选）
    pub description: Option<String>,
}

/// 更新字典类型请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateDictionaryTypeRequest {
    /// 显示标签（可选）
    pub dict_type_label: Option<String>,
    /// 排序序号（可选）
    pub sort_order: Option<i32>,
    /// 描述信息（可选）
    pub description: Option<Option<String>>,
}

/// 更新告警规则请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateAlertRuleRequest {
    /// 规则名称（可选）
    pub name: Option<String>,
    /// 监控指标（可选）
    pub metric: Option<String>,
    /// Agent匹配模式（可选）
    pub agent_pattern: Option<String>,
    /// 告警级别（可选）
    pub severity: Option<String>,
    /// 是否启用（可选）
    pub enabled: Option<bool>,
    /// 规则配置JSON（可选）
    pub config_json: Option<String>,
    /// 静默时间（秒）（可选）
    pub silence_secs: Option<u64>,
}

/// 更新通知渠道请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateNotificationChannelRequest {
    /// 渠道名称（可选）
    pub name: Option<String>,
    /// 描述信息（可选）
    pub description: Option<String>,
    /// 最小告警级别（可选）
    pub min_severity: Option<String>,
    /// 是否启用（可选）
    pub enabled: Option<bool>,
    /// 渠道配置JSON（可选）
    pub config_json: Option<String>,
    /// 收件人列表（可选，会替换现有收件人）
    pub recipients: Option<Vec<String>>,
}
