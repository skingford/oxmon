use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDataPoint {
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub metric_name: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricBatch {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub data_points: Vec<MetricDataPoint>,
}

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
    /// 域名地址
    pub domain: String,
    /// 端口号
    pub port: i32,
    /// 是否启用监控
    pub enabled: bool,
    /// 检查间隔（秒）
    pub check_interval_secs: Option<u64>,
    /// 备注
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
    /// 错误信息
    pub error: Option<String>,
    /// 检查时间
    pub checked_at: DateTime<Utc>,
}

/// 创建域名请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateDomainRequest {
    /// 域名地址
    pub domain: String,
    /// 端口号（默认 443）
    pub port: Option<i32>,
    /// 检查间隔（秒）
    pub check_interval_secs: Option<u64>,
    /// 备注
    pub note: Option<String>,
}

/// 更新域名请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateDomainRequest {
    /// 端口号
    pub port: Option<i32>,
    /// 是否启用监控
    pub enabled: Option<bool>,
    /// 检查间隔（秒），传 null 清除自定义间隔
    pub check_interval_secs: Option<Option<u64>>,
    /// 备注
    pub note: Option<String>,
}

/// 批量创建域名请求
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BatchCreateDomainsRequest {
    /// 域名列表
    pub domains: Vec<CreateDomainRequest>,
}
