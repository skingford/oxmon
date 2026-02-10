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
    pub agent_id: String,
    pub metric_name: String,
    pub severity: Severity,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
    pub timestamp: DateTime<Utc>,
    /// For trend prediction rules: predicted time to breach
    pub predicted_breach: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub last_seen: DateTime<Utc>,
    pub active: bool,
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
}

/// 添加 Agent 到白名单请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AddAgentRequest {
    /// Agent ID（必填，需全局唯一）
    pub agent_id: String,
    /// 描述信息（可选）
    pub description: Option<String>,
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
}

/// 证书详情查询过滤器
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CertificateDetailsFilter {
    /// 证书过期时间上界（Unix 秒级时间戳）
    pub not_after_lte: Option<i64>,
    /// IP 包含匹配
    pub ip_address_contains: Option<String>,
    /// 颁发者包含匹配
    pub issuer_contains: Option<String>,
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
    /// 登录密码（必填）
    pub password: String,
}

/// 登录响应
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LoginResponse {
    /// JWT Token
    pub token: String,
    /// Token 有效期（秒）
    pub expires_in: u64,
}

/// 修改密码请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChangePasswordRequest {
    /// 当前密码（必填）
    pub current_password: String,
    /// 新密码（必填）
    pub new_password: String,
}
