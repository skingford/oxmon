pub mod alibaba;
pub mod collector;
pub mod error;
pub mod tencent;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

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
    pub instance_type: String, // e.g., "S5.LARGE8", "ecs.c6.xlarge"
    pub cpu_cores: Option<u32>, // Number of vCPU cores
    pub memory_gb: Option<f64>, // Memory in GB
    pub disk_gb: Option<f64>,   // Total disk capacity in GB (system + data disks)
    // Lifecycle information (Phase 1)
    pub created_time: Option<i64>,   // Unix timestamp
    pub expired_time: Option<i64>,   // Unix timestamp (for PREPAID instances)
    pub charge_type: Option<String>, // "PREPAID", "POSTPAID_BY_HOUR" (Tencent) or "PrePaid", "PostPaid" (Alibaba)
    // Network configuration (Phase 1)
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    #[serde(default)]
    pub security_group_ids: Vec<String>,
    // Location information (Phase 1)
    pub zone: Option<String>, // Availability zone
    // Phase 2: Advanced network features
    pub internet_max_bandwidth: Option<u32>, // Public network bandwidth limit in Mbps
    #[serde(default)]
    pub ipv6_addresses: Vec<String>, // IPv6 addresses
    pub eip_allocation_id: Option<String>,   // Elastic IP allocation ID (Alibaba)
    pub internet_charge_type: Option<String>, // Network billing type
    // Phase 2: System and image information
    pub image_id: Option<String>,    // OS image ID
    pub hostname: Option<String>,    // Hostname (mainly Alibaba)
    pub description: Option<String>, // Instance description (mainly Alibaba)
    // Phase 2: Compute resource extensions
    pub gpu: Option<u32>, // Number of GPU cores (Tencent) or GPU count (Alibaba)
    pub io_optimized: Option<String>, // IO optimization status (Alibaba: "optimized", "none")
    // Phase 2: Operation tracking (Tencent)
    pub latest_operation: Option<String>, // Latest operation performed
    pub latest_operation_state: Option<String>, // Latest operation state (SUCCESS, OPERATING, FAILED)
    // Phase 3: Additional metadata
    pub project_id: Option<String>,        // Project ID (Tencent)
    pub resource_group_id: Option<String>, // Resource group ID (Alibaba)
    pub auto_renew_flag: Option<String>,   // Auto-renewal flag
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
    pub instance_type: String, // e.g., "S5.LARGE8", "ecs.c6.xlarge"
    pub cpu_cores: Option<u32>, // Number of vCPU cores
    pub memory_gb: Option<f64>, // Memory in GB
    pub disk_gb: Option<f64>,   // Total disk capacity in GB
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
    #[serde(
        alias = "region",
        alias = "default_region",
        deserialize_with = "deserialize_regions"
    )]
    pub regions: Vec<String>,
    #[serde(default = "default_collection_interval")]
    pub collection_interval_secs: u64,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default)]
    pub instance_filter: InstanceFilter,
}

fn default_collection_interval() -> u64 {
    3600 // 1 hour
}

fn default_concurrency() -> usize {
    5
}

fn deserialize_regions<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RegionsInput {
        One(String),
        Many(Vec<String>),
    }

    match RegionsInput::deserialize(deserializer)? {
        RegionsInput::One(region) => Ok(vec![region]),
        RegionsInput::Many(regions) => Ok(regions),
    }
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

/// Build a cloud provider from account configuration.
///
/// # Errors
///
/// Returns [`error::CloudProviderError::UnsupportedProvider`] if `provider_type`
/// is not `"tencent"` or `"alibaba"`.
/// Returns [`error::CloudProviderError::ConfigError`] if the account config is invalid.
pub fn build_provider(
    provider_type: &str,
    account_name: &str,
    config: CloudAccountConfig,
) -> error::Result<Box<dyn CloudProvider>> {
    match provider_type {
        "tencent" => Ok(Box::new(
            tencent::TencentCloudProvider::new(account_name, config)
                .map_err(|e| error::CloudProviderError::ConfigError(e.to_string()))?,
        )),
        "alibaba" => Ok(Box::new(
            alibaba::AlibabaCloudProvider::new(account_name, config)
                .map_err(|e| error::CloudProviderError::ConfigError(e.to_string()))?,
        )),
        _ => Err(error::CloudProviderError::UnsupportedProvider(
            provider_type.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_apply_status_whitelist_when_filtering_instances() {
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
            created_time: None,
            expired_time: None,
            charge_type: None,
            vpc_id: None,
            subnet_id: None,
            security_group_ids: vec![],
            zone: None,
            internet_max_bandwidth: None,
            ipv6_addresses: vec![],
            eip_allocation_id: None,
            internet_charge_type: None,
            image_id: None,
            hostname: None,
            description: None,
            gpu: None,
            io_optimized: None,
            latest_operation: None,
            latest_operation_state: None,
            project_id: None,
            resource_group_id: None,
            auto_renew_flag: None,
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
    fn should_match_instances_with_all_required_tags_present() {
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
            created_time: None,
            expired_time: None,
            charge_type: None,
            vpc_id: None,
            subnet_id: None,
            security_group_ids: vec![],
            zone: None,
            internet_max_bandwidth: None,
            ipv6_addresses: vec![],
            eip_allocation_id: None,
            internet_charge_type: None,
            image_id: None,
            hostname: None,
            description: None,
            gpu: None,
            io_optimized: None,
            latest_operation: None,
            latest_operation_state: None,
            project_id: None,
            resource_group_id: None,
            auto_renew_flag: None,
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
    fn should_exclude_instances_when_excluded_tag_is_present() {
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
            created_time: None,
            expired_time: None,
            charge_type: None,
            vpc_id: None,
            subnet_id: None,
            security_group_ids: vec![],
            zone: None,
            internet_max_bandwidth: None,
            ipv6_addresses: vec![],
            eip_allocation_id: None,
            internet_charge_type: None,
            image_id: None,
            hostname: None,
            description: None,
            gpu: None,
            io_optimized: None,
            latest_operation: None,
            latest_operation_state: None,
            project_id: None,
            resource_group_id: None,
            auto_renew_flag: None,
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

    #[test]
    fn should_deserialize_regions_from_array_field() {
        let cfg: CloudAccountConfig = serde_json::from_value(serde_json::json!({
            "secret_id": "sid",
            "secret_key": "skey",
            "regions": ["ap-guangzhou", "ap-shanghai"]
        }))
        .expect("config should parse");

        assert_eq!(cfg.regions, vec!["ap-guangzhou", "ap-shanghai"]);
    }

    #[test]
    fn should_deserialize_regions_from_default_region_string_alias() {
        let cfg: CloudAccountConfig = serde_json::from_value(serde_json::json!({
            "secret_id": "sid",
            "secret_key": "skey",
            "default_region": "ap-guangzhou"
        }))
        .expect("config should parse");

        assert_eq!(cfg.regions, vec!["ap-guangzhou"]);
    }
}
