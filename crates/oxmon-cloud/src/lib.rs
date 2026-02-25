pub mod tencent;
pub mod alibaba;
pub mod collector;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Cloud instance metadata discovered from provider API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudInstance {
    pub instance_id: String,
    pub instance_name: String,
    pub provider: String, // "tencent:acct_name" or "alibaba:acct_name"
    pub region: String,
    pub public_ip: String,
    pub private_ip: String,
    pub os: String,
    pub status: String,
    #[serde(default)]
    pub tags: std::collections::HashMap<String, String>,
    // Hardware specifications
    #[serde(default)]
    pub instance_type: String,   // e.g., "S5.LARGE8", "ecs.c6.xlarge"
    pub cpu_cores: Option<u32>,  // Number of vCPU cores
    pub memory_gb: Option<f64>,  // Memory in GB
    pub disk_gb: Option<f64>,    // Total disk capacity in GB (system + data disks)
}

/// Cloud metrics for a single instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMetrics {
    pub instance_id: String,
    pub instance_name: String,
    pub provider: String,
    pub region: String,
    // Basic metrics
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub disk_usage: Option<f64>,
    // Network metrics (bytes per second)
    pub network_in_bytes: Option<f64>,
    pub network_out_bytes: Option<f64>,
    // Disk I/O metrics (operations per second)
    pub disk_iops_read: Option<f64>,
    pub disk_iops_write: Option<f64>,
    // Connection metrics
    pub connections: Option<f64>,
    pub collected_at: DateTime<Utc>,
    // Hardware specifications
    #[serde(default)]
    pub instance_type: String,   // e.g., "S5.LARGE8", "ecs.c6.xlarge"
    pub cpu_cores: Option<u32>,  // Number of vCPU cores
    pub memory_gb: Option<f64>,  // Memory in GB
    pub disk_gb: Option<f64>,    // Total disk capacity in GB
}

/// Instance filter configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstanceFilter {
    /// Only include instances with these statuses (e.g., ["Running", "RUNNING"])
    /// Empty means all statuses are allowed
    #[serde(default)]
    pub status_whitelist: Vec<String>,
    /// Tag filters: all tags must match (AND logic)
    /// Key-value pairs, e.g., {"env": "prod", "team": "backend"}
    #[serde(default)]
    pub required_tags: std::collections::HashMap<String, String>,
    /// Exclude instances with any of these tags (OR logic)
    #[serde(default)]
    pub excluded_tags: std::collections::HashMap<String, String>,
}

/// Cloud account configuration (deserialized from system_configs.config_json)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAccountConfig {
    pub secret_id: String,
    pub secret_key: String,
    pub regions: Vec<String>,
    #[serde(default = "default_collection_interval")]
    pub collection_interval_secs: u64,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default)]
    pub instance_filter: InstanceFilter,
}

fn default_collection_interval() -> u64 {
    300 // 5 minutes
}

fn default_concurrency() -> usize {
    5
}

/// Cloud provider trait for abstracting different cloud vendors
#[async_trait::async_trait]
pub trait CloudProvider: Send + Sync {
    /// Provider name (e.g., "tencent:myacct", "alibaba:myacct")
    fn name(&self) -> &str;

    /// List all instances across configured regions
    async fn list_instances(&self) -> Result<Vec<CloudInstance>>;

    /// Get metrics for a specific instance
    async fn get_metrics(&self, instance_id: &str, region: &str) -> Result<CloudMetrics>;
}

impl InstanceFilter {
    /// Check if an instance matches this filter
    pub fn matches(&self, instance: &CloudInstance) -> bool {
        // Check status whitelist
        if !self.status_whitelist.is_empty() && !self.status_whitelist.contains(&instance.status) {
            return false;
        }

        // Check required tags (all must match)
        for (key, value) in &self.required_tags {
            match instance.tags.get(key) {
                Some(tag_value) if tag_value == value => continue,
                _ => return false,
            }
        }

        // Check excluded tags (none should match)
        for (key, value) in &self.excluded_tags {
            if let Some(tag_value) = instance.tags.get(key) {
                if tag_value == value {
                    return false;
                }
            }
        }

        true
    }
}

/// Build a cloud provider from account configuration
pub fn build_provider(
    provider_type: &str,
    account_name: &str,
    config: CloudAccountConfig,
) -> Result<Box<dyn CloudProvider>> {
    match provider_type {
        "tencent" => Ok(Box::new(tencent::TencentCloudProvider::new(
            account_name,
            config,
        )?)),
        "alibaba" => Ok(Box::new(alibaba::AlibabaCloudProvider::new(
            account_name,
            config,
        )?)),
        _ => Err(anyhow::anyhow!("Unsupported cloud provider: {}", provider_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_filter_status_whitelist() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("env".to_string(), "prod".to_string());

        let instance = CloudInstance {
            instance_id: "ins-123".to_string(),
            instance_name: "test".to_string(),
            provider: "test".to_string(),
            region: "test".to_string(),
            public_ip: "1.2.3.4".to_string(),
            private_ip: "10.0.0.1".to_string(),
            os: "Linux".to_string(),
            status: "Running".to_string(),
            tags,
            instance_type: "test.large".to_string(),
            cpu_cores: Some(2),
            memory_gb: Some(4.0),
            disk_gb: Some(50.0),
        };

        // Empty whitelist should match all
        let filter = InstanceFilter {
            status_whitelist: vec![],
            ..Default::default()
        };
        assert!(filter.matches(&instance));

        // Matching status
        let filter = InstanceFilter {
            status_whitelist: vec!["Running".to_string(), "RUNNING".to_string()],
            ..Default::default()
        };
        assert!(filter.matches(&instance));

        // Non-matching status
        let filter = InstanceFilter {
            status_whitelist: vec!["Stopped".to_string()],
            ..Default::default()
        };
        assert!(!filter.matches(&instance));
    }

    #[test]
    fn test_instance_filter_required_tags() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        tags.insert("team".to_string(), "backend".to_string());

        let instance = CloudInstance {
            instance_id: "ins-123".to_string(),
            instance_name: "test".to_string(),
            provider: "test".to_string(),
            region: "test".to_string(),
            public_ip: "1.2.3.4".to_string(),
            private_ip: "10.0.0.1".to_string(),
            os: "Linux".to_string(),
            status: "Running".to_string(),
            tags,
            instance_type: "test.large".to_string(),
            cpu_cores: Some(2),
            memory_gb: Some(4.0),
            disk_gb: Some(50.0),
        };

        // Matching required tags
        let mut required_tags = std::collections::HashMap::new();
        required_tags.insert("env".to_string(), "prod".to_string());
        let filter = InstanceFilter {
            required_tags,
            ..Default::default()
        };
        assert!(filter.matches(&instance));

        // Non-matching required tags
        let mut required_tags = std::collections::HashMap::new();
        required_tags.insert("env".to_string(), "dev".to_string());
        let filter = InstanceFilter {
            required_tags,
            ..Default::default()
        };
        assert!(!filter.matches(&instance));

        // Missing required tag
        let mut required_tags = std::collections::HashMap::new();
        required_tags.insert("project".to_string(), "myapp".to_string());
        let filter = InstanceFilter {
            required_tags,
            ..Default::default()
        };
        assert!(!filter.matches(&instance));
    }

    #[test]
    fn test_instance_filter_excluded_tags() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        tags.insert("deprecated".to_string(), "true".to_string());

        let instance = CloudInstance {
            instance_id: "ins-123".to_string(),
            instance_name: "test".to_string(),
            provider: "test".to_string(),
            region: "test".to_string(),
            public_ip: "1.2.3.4".to_string(),
            private_ip: "10.0.0.1".to_string(),
            os: "Linux".to_string(),
            status: "Running".to_string(),
            tags,
            instance_type: "test.large".to_string(),
            cpu_cores: Some(2),
            memory_gb: Some(4.0),
            disk_gb: Some(50.0),
        };

        // Excluded tag present
        let mut excluded_tags = std::collections::HashMap::new();
        excluded_tags.insert("deprecated".to_string(), "true".to_string());
        let filter = InstanceFilter {
            excluded_tags,
            ..Default::default()
        };
        assert!(!filter.matches(&instance));

        // Excluded tag not present
        let mut excluded_tags = std::collections::HashMap::new();
        excluded_tags.insert("test".to_string(), "true".to_string());
        let filter = InstanceFilter {
            excluded_tags,
            ..Default::default()
        };
        assert!(filter.matches(&instance));
    }
}
