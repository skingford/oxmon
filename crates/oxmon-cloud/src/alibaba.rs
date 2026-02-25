use crate::{CloudAccountConfig, CloudInstance, CloudMetrics, CloudProvider};
use anyhow::{Context, Result};
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha1::Sha1;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::sleep;

type HmacSha1 = Hmac<Sha1>;

const ECS_ENDPOINT_TEMPLATE: &str = "ecs.{region}.aliyuncs.com";
const CMS_ENDPOINT: &str = "metrics.aliyuncs.com";

pub struct AlibabaCloudProvider {
    account_name: String,
    access_key_id: String,
    access_key_secret: String,
    regions: Vec<String>,
    client: Client,
    rate_limiter: Arc<Semaphore>,
    instance_filter: crate::InstanceFilter,
}

impl AlibabaCloudProvider {
    pub fn new(account_name: &str, config: CloudAccountConfig) -> Result<Self> {
        let client = Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        // Rate limiter: 10 req/s with burst of 20
        let rate_limiter = Arc::new(Semaphore::new(20));

        Ok(Self {
            account_name: account_name.to_string(),
            access_key_id: config.secret_id,
            access_key_secret: config.secret_key,
            regions: config.regions,
            client,
            rate_limiter,
            instance_filter: config.instance_filter,
        })
    }

    /// ACS v1 signature algorithm
    fn sign_acs_v1(&self, params: &BTreeMap<String, String>) -> Result<String> {
        // Step 1: Sort parameters and build canonical query string
        let canonical_query_string = params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Step 2: Build string to sign
        let string_to_sign = format!(
            "GET&{}&{}",
            percent_encode("/"),
            percent_encode(&canonical_query_string)
        );

        // Step 3: HMAC-SHA1 signature
        let key = format!("{}&", self.access_key_secret);
        let mut mac = HmacSha1::new_from_slice(key.as_bytes())
            .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
        mac.update(string_to_sign.as_bytes());
        let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        Ok(signature)
    }

    /// Call Alibaba Cloud API with ACS v1 signature and retry logic
    async fn call_api_with_retry(
        &self,
        endpoint: &str,
        action: &str,
        version: &str,
        region: Option<&str>,
        extra_params: BTreeMap<String, String>,
        max_retries: usize,
    ) -> Result<serde_json::Value> {
        let mut last_error = None;
        let base_delay = Duration::from_millis(200);

        for attempt in 0..=max_retries {
            // Rate limiting
            let _permit = self.rate_limiter.acquire().await.unwrap();
            tokio::spawn({
                let limiter = Arc::clone(&self.rate_limiter);
                async move {
                    sleep(Duration::from_millis(100)).await;
                    limiter.add_permits(1);
                }
            });

            match self
                .call_api(endpoint, action, version, region, extra_params.clone())
                .await
            {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e);

                    // Check if it's a throttling error
                    if let Some(ref err) = last_error {
                        let err_str = err.to_string().to_lowercase();
                        let is_throttling = err_str.contains("throttling")
                            || err_str.contains("flow control")
                            || err_str.contains("request was denied");

                        if is_throttling && attempt < max_retries {
                            // Exponential backoff: 200ms, 400ms, 800ms, 1600ms...
                            let delay = base_delay * 2_u32.pow(attempt as u32);
                            let delay = if delay > Duration::from_secs(5) {
                                Duration::from_secs(5)
                            } else {
                                delay
                            };

                            tracing::warn!(
                                "Alibaba Cloud API throttling error, retrying after {:?} (attempt {}/{})",
                                delay,
                                attempt + 1,
                                max_retries
                            );
                            sleep(delay).await;
                            continue;
                        } else if !is_throttling {
                            // Non-throttling error, return immediately
                            return Err(anyhow::anyhow!("{}", err));
                        }
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    /// Call Alibaba Cloud API with ACS v1 signature
    async fn call_api(
        &self,
        endpoint: &str,
        action: &str,
        version: &str,
        region: Option<&str>,
        extra_params: BTreeMap<String, String>,
    ) -> Result<serde_json::Value> {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = uuid::Uuid::new_v4().to_string();

        let mut params = BTreeMap::new();
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("Version".to_string(), version.to_string());
        params.insert("AccessKeyId".to_string(), self.access_key_id.clone());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("Timestamp".to_string(), timestamp);
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("SignatureNonce".to_string(), nonce);
        params.insert("Action".to_string(), action.to_string());

        if let Some(r) = region {
            params.insert("RegionId".to_string(), r.to_string());
        }

        // Add extra params
        for (k, v) in extra_params {
            params.insert(k, v);
        }

        // Sign the request
        let signature = self.sign_acs_v1(&params)?;
        params.insert("Signature".to_string(), signature);

        // Build URL
        let query_string = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let url = format!("https://{}/?{}", endpoint, query_string);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to Alibaba Cloud API")?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("Failed to read response body")?;

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Alibaba Cloud API error: status={}, body={}",
                status,
                body
            ));
        }

        let json: serde_json::Value =
            serde_json::from_str(&body).context("Failed to parse response as JSON")?;

        // Check for API error in response
        if let Some(code) = json.get("Code") {
            if code.as_str() != Some("200") {
                let message = json
                    .get("Message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown");
                return Err(anyhow::anyhow!(
                    "Alibaba Cloud API error: code={}, message={}",
                    code,
                    message
                ));
            }
        }

        Ok(json)
    }

    /// List ECS instances in a specific region
    async fn list_instances_in_region(&self, region: &str) -> Result<Vec<CloudInstance>> {
        let mut all_instances = Vec::new();
        let mut page_number = 1;
        let page_size = 100;

        loop {
            let mut params = BTreeMap::new();
            params.insert("PageNumber".to_string(), page_number.to_string());
            params.insert("PageSize".to_string(), page_size.to_string());

            let endpoint = ECS_ENDPOINT_TEMPLATE.replace("{region}", region);
            let response = self
                .call_api_with_retry(&endpoint, "DescribeInstances", "2014-05-26", Some(region), params, 5)
                .await?;

            let total_count = response
                .get("TotalCount")
                .and_then(|v| v.as_i64())
                .context("Missing TotalCount")?;

            if let Some(instances) = response
                .get("Instances")
                .and_then(|v| v.get("Instance"))
                .and_then(|v| v.as_array())
            {
                for inst in instances {
                    let instance_id = inst
                        .get("InstanceId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let instance_name = inst
                        .get("InstanceName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let os = inst
                        .get("OSName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let status = inst
                        .get("Status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Public IP
                    let mut public_ip = String::new();
                    if let Some(public_ip_arr) = inst
                        .get("PublicIpAddress")
                        .and_then(|v| v.get("IpAddress"))
                        .and_then(|v| v.as_array())
                    {
                        if let Some(first_ip) = public_ip_arr.first().and_then(|v| v.as_str()) {
                            public_ip = first_ip.to_string();
                        }
                    }
                    // EIP address
                    if public_ip.is_empty() {
                        if let Some(eip_addr) = inst
                            .get("EipAddress")
                            .and_then(|v| v.get("IpAddress"))
                            .and_then(|v| v.as_str())
                        {
                            public_ip = eip_addr.to_string();
                        }
                    }

                    // Private IP
                    let mut private_ip = String::new();
                    if let Some(vpc_attrs) = inst.get("VpcAttributes") {
                        if let Some(private_ip_arr) = vpc_attrs
                            .get("PrivateIpAddress")
                            .and_then(|v| v.get("IpAddress"))
                            .and_then(|v| v.as_array())
                        {
                            if let Some(first_ip) = private_ip_arr.first().and_then(|v| v.as_str()) {
                                private_ip = first_ip.to_string();
                            }
                        }
                    }

                    // Parse tags
                    let mut tags = std::collections::HashMap::new();
                    if let Some(tag_list) = inst.get("Tags").and_then(|v| v.get("Tag")).and_then(|v| v.as_array()) {
                        for tag in tag_list {
                            if let (Some(key), Some(value)) = (
                                tag.get("TagKey").and_then(|v| v.as_str()),
                                tag.get("TagValue").and_then(|v| v.as_str()),
                            ) {
                                tags.insert(key.to_string(), value.to_string());
                            }
                        }
                    }

                    // Parse hardware specifications
                    let instance_type = inst
                        .get("InstanceType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let cpu_cores = inst
                        .get("Cpu")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);

                    // Memory is in MB, convert to GB
                    let memory_gb = inst
                        .get("Memory")
                        .and_then(|v| v.as_u64())
                        .map(|v| (v as f64) / 1024.0);

                    // Disk capacity will be populated later by calling DescribeDisks API
                    let disk_gb: Option<f64> = None;

                    let instance = CloudInstance {
                        instance_id,
                        instance_name,
                        provider: format!("alibaba:{}", self.account_name),
                        region: region.to_string(),
                        public_ip,
                        private_ip,
                        os,
                        status,
                        tags,
                        instance_type,
                        cpu_cores,
                        memory_gb,
                        disk_gb,
                    };

                    // Apply instance filter
                    if self.instance_filter.matches(&instance) {
                        all_instances.push(instance);
                    }
                }
            }

            if (page_number * page_size) as i64 >= total_count {
                break;
            }
            page_number += 1;
        }

        // Query disk information for all instances in this region
        if !all_instances.is_empty() {
            self.populate_disk_info(region, &mut all_instances).await?;
        }

        Ok(all_instances)
    }

    /// Populate disk information for instances by calling DescribeDisks API
    async fn populate_disk_info(&self, region: &str, instances: &mut [CloudInstance]) -> Result<()> {
        if instances.is_empty() {
            return Ok(());
        }

        // Build map of instance_id -> instance for quick lookup
        let mut instance_map: std::collections::HashMap<String, &mut CloudInstance> =
            std::collections::HashMap::new();

        for instance in instances.iter_mut() {
            instance_map.insert(instance.instance_id.clone(), instance);
        }

        // Query all disks in this region (DescribeDisks supports querying all disks at once)
        let mut page_number = 1;
        let page_size = 100;

        loop {
            let mut params = BTreeMap::new();
            params.insert("PageNumber".to_string(), page_number.to_string());
            params.insert("PageSize".to_string(), page_size.to_string());

            let endpoint = ECS_ENDPOINT_TEMPLATE.replace("{region}", region);
            let response = match self
                .call_api_with_retry(&endpoint, "DescribeDisks", "2014-05-26", Some(region), params, 3)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Failed to describe disks in region {}: {}", region, e);
                    return Ok(()); // Non-fatal error, continue without disk info
                }
            };

            let total_count = response
                .get("TotalCount")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            if let Some(disks) = response
                .get("Disks")
                .and_then(|v| v.get("Disk"))
                .and_then(|v| v.as_array())
            {
                for disk in disks {
                    // Get the instance ID this disk belongs to
                    let instance_id = match disk.get("InstanceId").and_then(|v| v.as_str()) {
                        Some(id) => id,
                        None => continue, // Skip disks not attached to any instance
                    };

                    // Get disk size (in GB)
                    let disk_size = match disk.get("Size").and_then(|v| v.as_u64()) {
                        Some(size) => size as f64,
                        None => continue,
                    };

                    // Add to the instance's total disk capacity
                    if let Some(instance) = instance_map.get_mut(instance_id) {
                        match &mut instance.disk_gb {
                            Some(total) => *total += disk_size,
                            None => instance.disk_gb = Some(disk_size),
                        }
                    }
                }
            }

            if (page_number * page_size) as i64 >= total_count {
                break;
            }
            page_number += 1;
        }

        tracing::debug!(
            "Populated disk info for {} instances in region {}",
            instances.len(),
            region
        );

        Ok(())
    }

    /// Get CMS metric for a specific instance
    async fn get_cms_metric(
        &self,
        namespace: &str,
        metric_name: &str,
        instance_id: &str,
    ) -> Result<Option<f64>> {
        let now = Utc::now();
        let start_time = (now - chrono::Duration::minutes(30)).timestamp_millis().to_string();
        let end_time = now.timestamp_millis().to_string();
        let dimensions = format!(r#"[{{"instanceId":"{}"}}]"#, instance_id);

        let mut params = BTreeMap::new();
        params.insert("Namespace".to_string(), namespace.to_string());
        params.insert("MetricName".to_string(), metric_name.to_string());
        params.insert("Dimensions".to_string(), dimensions);
        params.insert("Period".to_string(), "300".to_string());
        params.insert("StartTime".to_string(), start_time);
        params.insert("EndTime".to_string(), end_time);

        let response = self
            .call_api_with_retry(CMS_ENDPOINT, "DescribeMetricLast", "2019-01-01", None, params, 5)
            .await?;

        let datapoints_str = response
            .get("Datapoints")
            .and_then(|v| v.as_str())
            .unwrap_or("[]");

        if datapoints_str.is_empty() || datapoints_str == "[]" {
            return Ok(None);
        }

        let datapoints: Vec<serde_json::Value> = serde_json::from_str(datapoints_str)
            .context("Failed to parse datapoints JSON")?;

        if datapoints.is_empty() {
            return Ok(None);
        }

        // Get the last data point
        let last_point = &datapoints[datapoints.len() - 1];
        if let Some(avg) = last_point.get("Average") {
            if let Some(val) = avg.as_f64() {
                return Ok(Some(val));
            } else if let Some(val_str) = avg.as_str() {
                if let Ok(val) = val_str.parse::<f64>() {
                    return Ok(Some(val));
                }
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl CloudProvider for AlibabaCloudProvider {
    fn name(&self) -> &str {
        &self.account_name
    }

    async fn list_instances(&self) -> Result<Vec<CloudInstance>> {
        let mut all_instances = Vec::new();

        for region in &self.regions {
            match self.list_instances_in_region(region).await {
                Ok(instances) => {
                    all_instances.extend(instances);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to list Alibaba Cloud instances in region {}: {}",
                        region,
                        e
                    );
                }
            }
        }

        Ok(all_instances)
    }

    async fn get_metrics(&self, instance_id: &str, region: &str) -> Result<CloudMetrics> {
        let now = Utc::now();

        // Get CPU usage
        let cpu_usage = self
            .get_cms_metric("acs_ecs_dashboard", "cpu_total", instance_id)
            .await
            .ok()
            .flatten();

        // Get memory usage
        let memory_usage = self
            .get_cms_metric("acs_ecs_dashboard", "memory_usedutilization", instance_id)
            .await
            .ok()
            .flatten();

        // Get disk usage
        let disk_usage = self
            .get_cms_metric("acs_ecs_dashboard", "diskusage_utilization", instance_id)
            .await
            .ok()
            .flatten();

        // Get network in traffic (bytes per second)
        let network_in_bytes = self
            .get_cms_metric("acs_ecs_dashboard", "networkin_rate", instance_id)
            .await
            .ok()
            .flatten();

        // Get network out traffic (bytes per second)
        let network_out_bytes = self
            .get_cms_metric("acs_ecs_dashboard", "networkout_rate", instance_id)
            .await
            .ok()
            .flatten();

        // Get disk read IOPS
        let disk_iops_read = self
            .get_cms_metric("acs_ecs_dashboard", "disk_readiops", instance_id)
            .await
            .ok()
            .flatten();

        // Get disk write IOPS
        let disk_iops_write = self
            .get_cms_metric("acs_ecs_dashboard", "disk_writeiops", instance_id)
            .await
            .ok()
            .flatten();

        // Get TCP connection count
        let connections = self
            .get_cms_metric("acs_ecs_dashboard", "tcp_total", instance_id)
            .await
            .ok()
            .flatten();

        Ok(CloudMetrics {
            instance_id: instance_id.to_string(),
            instance_name: String::new(), // Will be filled by caller
            provider: format!("alibaba:{}", self.account_name),
            region: region.to_string(),
            cpu_usage,
            memory_usage,
            disk_usage,
            network_in_bytes,
            network_out_bytes,
            disk_iops_read,
            disk_iops_write,
            connections,
            collected_at: now,
            // Hardware specs are not available in metrics API
            // They will be filled from CloudInstance data by the scheduler
            instance_type: String::new(),
            cpu_cores: None,
            memory_gb: None,
            disk_gb: None,
        })
    }
}

/// Percent-encode for ACS v1 signature
fn percent_encode(s: &str) -> String {
    urlencoding::encode(s)
        .replace("+", "%20")
        .replace("*", "%2A")
        .replace("%7E", "~")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percent_encode() {
        assert_eq!(percent_encode("test"), "test");
        assert_eq!(percent_encode("hello world"), "hello%20world");
        assert_eq!(percent_encode("a+b"), "a%2Bb");
    }

    #[test]
    fn test_percent_encode_special_chars() {
        // Test special characters encoding
        assert_eq!(percent_encode("="), "%3D");
        assert_eq!(percent_encode("&"), "%26");
        assert_eq!(percent_encode("/"), "%2F");
        assert_eq!(percent_encode(":"), "%3A");

        // Test mixed content
        assert_eq!(percent_encode("key=value&foo=bar"), "key%3Dvalue%26foo%3Dbar");
    }

    #[test]
    fn test_canonicalized_query_string() {
        // Test query string canonicalization for ACS v1 signature
        let mut params = std::collections::BTreeMap::new();
        params.insert("Action".to_string(), "DescribeInstances".to_string());
        params.insert("Version".to_string(), "2014-05-26".to_string());
        params.insert("RegionId".to_string(), "cn-hangzhou".to_string());

        let mut sorted_keys: Vec<_> = params.keys().collect();
        sorted_keys.sort();

        let mut pairs = Vec::new();
        for key in sorted_keys {
            pairs.push(format!("{}={}", percent_encode(key), percent_encode(&params[key])));
        }
        let canonical_query = pairs.join("&");

        // Verify alphabetical sorting
        assert!(canonical_query.starts_with("Action"));
        assert!(canonical_query.contains("RegionId"));
        assert!(canonical_query.contains("Version"));
    }

    #[tokio::test]
    async fn test_alibaba_provider_creation() {
        use crate::CloudAccountConfig;

        // Test provider initialization
        let config = CloudAccountConfig {
            secret_id: "test_id".to_string(),
            secret_key: "test_secret".to_string(),
            regions: vec!["cn-hangzhou".to_string(), "cn-beijing".to_string()],
            collection_interval_secs: 300,
            concurrency: 5,
            instance_filter: Default::default(),
        };

        let provider = AlibabaCloudProvider::new("test_acct", config);

        assert!(provider.is_ok());
        let provider = provider.unwrap();
        assert_eq!(provider.name(), "test_acct");
    }

    #[test]
    fn test_cloud_instance_from_alibaba() {
        use std::collections::HashMap;

        // Test CloudInstance construction from Alibaba ECS data
        let mut tags = HashMap::new();
        tags.insert("env".to_string(), "prod".to_string());

        let instance = CloudInstance {
            instance_id: "i-bp1abc123".to_string(),
            instance_name: "test-ecs".to_string(),
            provider: "alibaba:test_acct".to_string(),
            region: "cn-hangzhou".to_string(),
            status: "Running".to_string(),
            public_ip: "47.1.2.3".to_string(),
            private_ip: "172.16.0.1".to_string(),
            os: "CentOS 7.9".to_string(),
            tags,
            instance_type: "ecs.c6.xlarge".to_string(),
            cpu_cores: Some(4),
            memory_gb: Some(8.0),
            disk_gb: None,
        };

        assert_eq!(instance.instance_id, "i-bp1abc123");
        assert_eq!(instance.provider, "alibaba:test_acct");
        assert!(!instance.private_ip.is_empty());
        assert_eq!(instance.tags.get("env").unwrap(), "prod");
    }
}
