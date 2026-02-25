use crate::{CloudAccountConfig, CloudInstance, CloudMetrics, CloudProvider};
use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const CVM_ENDPOINT: &str = "cvm.tencentcloudapi.com";
const MONITOR_ENDPOINT: &str = "monitor.tencentcloudapi.com";
const CVM_VERSION: &str = "2017-03-12";
const MONITOR_VERSION: &str = "2018-07-24";

pub struct TencentCloudProvider {
    account_name: String,
    secret_id: String,
    secret_key: String,
    regions: Vec<String>,
    client: Client,
    instance_filter: crate::InstanceFilter,
}

impl TencentCloudProvider {
    pub fn new(account_name: &str, config: CloudAccountConfig) -> Result<Self> {
        let client = Client::builder()
            .use_rustls_tls()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            account_name: account_name.to_string(),
            secret_id: config.secret_id,
            secret_key: config.secret_key,
            regions: config.regions,
            client,
            instance_filter: config.instance_filter,
        })
    }

    /// TC3-HMAC-SHA256 signature algorithm
    fn sign_tc3(
        &self,
        service: &str,
        host: &str,
        action: &str,
        _version: &str,
        payload: &str,
        timestamp: i64,
    ) -> Result<String> {
        let date = DateTime::from_timestamp(timestamp, 0)
            .context("Invalid timestamp")?
            .format("%Y-%m-%d")
            .to_string();

        // Step 1: Build canonical request
        let canonical_uri = "/";
        let canonical_querystring = "";
        let canonical_headers = format!("content-type:application/json\nhost:{}\nx-tc-action:{}\n", host, action.to_lowercase());
        let signed_headers = "content-type;host;x-tc-action";

        let hashed_payload = format!("{:x}", Sha256::digest(payload.as_bytes()));
        let canonical_request = format!(
            "POST\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_querystring, canonical_headers, signed_headers, hashed_payload
        );
        let hashed_canonical_request = format!("{:x}", Sha256::digest(canonical_request.as_bytes()));

        // Step 2: Build string to sign
        let credential_scope = format!("{}/{}/tc3_request", date, service);
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{}\n{}\n{}",
            timestamp, credential_scope, hashed_canonical_request
        );

        // Step 3: Calculate signature
        let secret_date = hmac_sha256(format!("TC3{}", self.secret_key).as_bytes(), date.as_bytes())?;
        let secret_service = hmac_sha256(&secret_date, service.as_bytes())?;
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request")?;
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes())?);

        // Step 4: Build authorization header
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.secret_id, credential_scope, signed_headers, signature
        );

        Ok(authorization)
    }

    /// Call Tencent Cloud API with TC3 signature
    async fn call_api(
        &self,
        service: &str,
        host: &str,
        action: &str,
        version: &str,
        region: &str,
        payload: &str,
    ) -> Result<serde_json::Value> {
        let timestamp = Utc::now().timestamp();
        let authorization = self.sign_tc3(service, host, action, version, payload, timestamp)?;

        let url = format!("https://{}/", host);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Host", host)
            .header("X-TC-Action", action)
            .header("X-TC-Version", version)
            .header("X-TC-Timestamp", timestamp.to_string())
            .header("X-TC-Region", region)
            .header("Authorization", authorization)
            .body(payload.to_string())
            .send()
            .await
            .context("Failed to send request to Tencent Cloud API")?;

        let status = response.status();
        let body = response.text().await.context("Failed to read response body")?;

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Tencent Cloud API error: status={}, body={}",
                status,
                body
            ));
        }

        let json: serde_json::Value = serde_json::from_str(&body)
            .context("Failed to parse response as JSON")?;

        // Check for API error in response
        if let Some(response_obj) = json.get("Response") {
            if let Some(error) = response_obj.get("Error") {
                let code = error.get("Code").and_then(|c| c.as_str()).unwrap_or("Unknown");
                let message = error.get("Message").and_then(|m| m.as_str()).unwrap_or("Unknown");
                return Err(anyhow::anyhow!(
                    "Tencent Cloud API error: code={}, message={}",
                    code,
                    message
                ));
            }
        }

        Ok(json)
    }

    /// List CVM instances in a specific region
    async fn list_instances_in_region(&self, region: &str) -> Result<Vec<CloudInstance>> {
        let mut all_instances = Vec::new();
        let mut offset = 0;
        let limit = 100;

        loop {
            let payload = serde_json::json!({
                "Offset": offset,
                "Limit": limit,
            });

            let response = self
                .call_api(
                    "cvm",
                    CVM_ENDPOINT,
                    "DescribeInstances",
                    CVM_VERSION,
                    region,
                    &payload.to_string(),
                )
                .await?;

            let response_obj = response
                .get("Response")
                .context("Missing Response field")?;

            let total_count = response_obj
                .get("TotalCount")
                .and_then(|v| v.as_i64())
                .context("Missing TotalCount")?;

            if let Some(instance_set) = response_obj.get("InstanceSet").and_then(|v| v.as_array()) {
                for inst in instance_set {
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
                        .get("OsName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let status = inst
                        .get("InstanceState")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let public_ip = inst
                        .get("PublicIpAddresses")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let private_ip = inst
                        .get("PrivateIpAddresses")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Parse tags
                    let mut tags = std::collections::HashMap::new();
                    if let Some(tag_list) = inst.get("Tags").and_then(|v| v.as_array()) {
                        for tag in tag_list {
                            if let (Some(key), Some(value)) = (
                                tag.get("Key").and_then(|v| v.as_str()),
                                tag.get("Value").and_then(|v| v.as_str()),
                            ) {
                                tags.insert(key.to_string(), value.to_string());
                            }
                        }
                    }

                    let instance = CloudInstance {
                        instance_id,
                        instance_name,
                        provider: format!("tencent:{}", self.account_name),
                        region: region.to_string(),
                        public_ip,
                        private_ip,
                        os,
                        status,
                        tags,
                    };

                    // Apply instance filter
                    if self.instance_filter.matches(&instance) {
                        all_instances.push(instance);
                    }
                }
            }

            offset += limit;
            if offset >= total_count {
                break;
            }
        }

        Ok(all_instances)
    }

    /// Get monitor data for a specific metric
    async fn get_monitor_data(
        &self,
        region: &str,
        namespace: &str,
        metric_name: &str,
        instance_id: &str,
    ) -> Result<Option<f64>> {
        let now = Utc::now();
        let start_time = (now - chrono::Duration::minutes(10))
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        let end_time = now.to_rfc3339_opts(SecondsFormat::Secs, true);

        let payload = serde_json::json!({
            "Namespace": namespace,
            "MetricName": metric_name,
            "Period": 300,
            "StartTime": start_time,
            "EndTime": end_time,
            "Instances": [{
                "Dimensions": [{
                    "Name": "InstanceId",
                    "Value": instance_id,
                }]
            }]
        });

        let response = self
            .call_api(
                "monitor",
                MONITOR_ENDPOINT,
                "GetMonitorData",
                MONITOR_VERSION,
                region,
                &payload.to_string(),
            )
            .await?;

        let response_obj = response
            .get("Response")
            .context("Missing Response field")?;

        if let Some(data_points) = response_obj.get("DataPoints").and_then(|v| v.as_array()) {
            if let Some(first_point) = data_points.first() {
                if let Some(values) = first_point.get("Values").and_then(|v| v.as_array()) {
                    if let Some(last_value) = values.last() {
                        if let Some(val) = last_value.as_f64() {
                            return Ok(Some(val));
                        }
                    }
                }
            }
        }

        Ok(None)
    }
}

#[async_trait::async_trait]
impl CloudProvider for TencentCloudProvider {
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
                        "Failed to list Tencent Cloud instances in region {}: {}",
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
            .get_monitor_data(region, "QCE/CVM", "CPUUsage", instance_id)
            .await
            .ok()
            .flatten();

        // Get memory usage
        let memory_usage = self
            .get_monitor_data(region, "QCE/CVM", "MemUsage", instance_id)
            .await
            .ok()
            .flatten();

        // Get disk usage
        let disk_usage = self
            .get_monitor_data(region, "QCE/CVM", "CvmDiskUsage", instance_id)
            .await
            .ok()
            .flatten();

        // Get network in traffic (WAN inbound, bytes per second)
        let network_in_bytes = self
            .get_monitor_data(region, "QCE/CVM", "WanIntraffic", instance_id)
            .await
            .ok()
            .flatten();

        // Get network out traffic (WAN outbound, bytes per second)
        let network_out_bytes = self
            .get_monitor_data(region, "QCE/CVM", "WanOuttraffic", instance_id)
            .await
            .ok()
            .flatten();

        // Get disk read IOPS
        let disk_iops_read = self
            .get_monitor_data(region, "QCE/CVM", "DiskReadIops", instance_id)
            .await
            .ok()
            .flatten();

        // Get disk write IOPS
        let disk_iops_write = self
            .get_monitor_data(region, "QCE/CVM", "DiskWriteIops", instance_id)
            .await
            .ok()
            .flatten();

        // Get TCP connection count
        let connections = self
            .get_monitor_data(region, "QCE/CVM", "TcpCurrEstab", instance_id)
            .await
            .ok()
            .flatten();

        Ok(CloudMetrics {
            instance_id: instance_id.to_string(),
            instance_name: String::new(), // Will be filled by caller
            provider: format!("tencent:{}", self.account_name),
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
        })
    }
}

/// HMAC-SHA256 helper function
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let result = hmac_sha256(key, data).unwrap();
        let hex_result = hex::encode(result);
        // This is a known test vector
        assert_eq!(
            hex_result,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_tc3_signature_components() {
        // Test TC3 signature generation with known inputs
        use crate::CloudAccountConfig;

        let config = CloudAccountConfig {
            secret_id: "test_id".to_string(),
            secret_key: "test_key".to_string(),
            regions: vec!["ap-guangzhou".to_string()],
            collection_interval_secs: 300,
            concurrency: 5,
            instance_filter: Default::default(),
        };

        let provider = TencentCloudProvider::new("test_acct", config).unwrap();

        let timestamp = 1551113065i64;
        let payload = "{}";

        // Test signature generation (this will fail with real API but tests the logic)
        let result = provider.sign_tc3("cvm", CVM_ENDPOINT, "DescribeInstances", CVM_VERSION, payload, timestamp);

        // Just ensure it doesn't panic and returns a signature
        assert!(result.is_ok());
        let auth_header = result.unwrap();
        assert!(auth_header.contains("TC3-HMAC-SHA256"));
        assert!(auth_header.contains("Credential="));
        assert!(auth_header.contains("SignedHeaders="));
        assert!(auth_header.contains("Signature="));
    }

    #[test]
    fn test_cloud_instance_from_tencent() {
        use std::collections::HashMap;

        // Test CloudInstance construction from Tencent CVM data
        let mut tags = HashMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        tags.insert("team".to_string(), "backend".to_string());

        let instance = CloudInstance {
            instance_id: "ins-abc123".to_string(),
            instance_name: "test-server".to_string(),
            provider: "tencent:test_acct".to_string(),
            region: "ap-guangzhou".to_string(),
            status: "RUNNING".to_string(),
            public_ip: "1.2.3.4".to_string(),
            private_ip: "10.0.0.1".to_string(),
            os: "Ubuntu 20.04".to_string(),
            tags,
        };

        assert_eq!(instance.instance_id, "ins-abc123");
        assert_eq!(instance.provider, "tencent:test_acct");
        assert!(!instance.public_ip.is_empty());
        assert_eq!(instance.tags.get("env").unwrap(), "prod");
    }

    #[test]
    fn test_cloud_metrics_creation() {
        use chrono::Utc;

        // Test CloudMetrics structure
        let metrics = CloudMetrics {
            instance_id: "ins-abc123".to_string(),
            instance_name: "test-server".to_string(),
            provider: "tencent:test_acct".to_string(),
            region: "ap-guangzhou".to_string(),
            cpu_usage: Some(45.5),
            memory_usage: Some(62.3),
            disk_usage: Some(78.9),
            network_in_bytes: Some(1024.0),
            network_out_bytes: Some(2048.0),
            disk_iops_read: Some(100.0),
            disk_iops_write: Some(50.0),
            connections: Some(200.0),
            collected_at: Utc::now(),
        };

        assert_eq!(metrics.cpu_usage.unwrap(), 45.5);
        assert_eq!(metrics.memory_usage.unwrap(), 62.3);
        assert_eq!(metrics.disk_usage.unwrap(), 78.9);
        assert_eq!(metrics.network_in_bytes.unwrap(), 1024.0);
        assert_eq!(metrics.disk_iops_read.unwrap(), 100.0);
        assert_eq!(metrics.connections.unwrap(), 200.0);
    }
}
