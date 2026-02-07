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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertDomain {
    pub id: String,
    pub domain: String,
    pub port: i32,
    pub enabled: bool,
    pub check_interval_secs: Option<u64>,
    pub note: Option<String>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertCheckResult {
    pub id: String,
    pub domain_id: String,
    pub domain: String,
    pub is_valid: bool,
    pub chain_valid: bool,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub days_until_expiry: Option<i64>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub san_list: Option<Vec<String>>,
    pub error: Option<String>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
    pub port: Option<i32>,
    pub check_interval_secs: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateDomainRequest {
    pub port: Option<i32>,
    pub enabled: Option<bool>,
    pub check_interval_secs: Option<Option<u64>>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCreateDomainsRequest {
    pub domains: Vec<CreateDomainRequest>,
}
