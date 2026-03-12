use crate::{CloudAccountConfig, CloudInstance, CloudMetrics, CloudProvider};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

const API_VERSION: &str = "20180725";
const DEFAULT_REGION_FOR_SIGN: &str = "cn-south-1";
const SCP_SERVICE: &str = "open-api";

pub struct SangforCloudProvider {
    account_name: String,
    secret_id: String,
    secret_key: String,
    /// 私有云所在的资源池 ID 列表（对应 SCP 中的 az_id 或 zone）
    regions: Vec<String>,
    /// 私有云访问地址，如 "192.168.1.100" 或 "scp.example.com:8443"
    endpoint: String,
    /// AWS4 签名使用的 region，默认 "cn-south-1"
    region_for_sign: String,
    client: Client,
    instance_filter: crate::InstanceFilter,
}

impl SangforCloudProvider {
    pub fn new(account_name: &str, config: CloudAccountConfig) -> Result<Self> {
        let endpoint = config.endpoint.clone().unwrap_or_default();
        if endpoint.is_empty() {
            bail!("Sangfor SCP provider requires 'endpoint' (private cloud host)");
        }

        let region_for_sign = config
            .region_for_sign
            .clone()
            .unwrap_or_else(|| DEFAULT_REGION_FOR_SIGN.to_string());

        // SCP 使用自签名证书，必须关闭 TLS 证书校验
        let client = Client::builder()
            .use_rustls_tls()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to build HTTP client for Sangfor SCP")?;

        Ok(Self {
            account_name: account_name.to_string(),
            secret_id: config.secret_id,
            secret_key: config.secret_key,
            regions: config.regions,
            endpoint,
            region_for_sign,
            client,
            instance_filter: config.instance_filter,
        })
    }

    /// 构造 SCP API 的 base URL
    fn base_url(&self) -> String {
        let host = &self.endpoint;
        if host.starts_with("http://") || host.starts_with("https://") {
            format!("{}/janus/{}", host.trim_end_matches('/'), API_VERSION)
        } else {
            format!("https://{}/janus/{}", host, API_VERSION)
        }
    }

    /// 提取 host（不含协议前缀）用于签名
    fn host_for_sign(&self) -> String {
        let h = &self.endpoint;
        if let Some(stripped) = h.strip_prefix("https://") {
            stripped.trim_end_matches('/').to_string()
        } else if let Some(stripped) = h.strip_prefix("http://") {
            stripped.trim_end_matches('/').to_string()
        } else {
            h.trim_end_matches('/').to_string()
        }
    }

    /// AWS4-HMAC-SHA256 签名，用于深信服 SCP Open API
    fn sign_aws4(
        &self,
        method: &str,
        uri: &str,
        query_string: &str,
        now: &DateTime<Utc>,
    ) -> String {
        let date_str = now.format("%Y%m%d").to_string();
        let datetime_str = now.format("%Y%m%dT%H%M%SZ").to_string();
        let host = self.host_for_sign();

        // Step 1: canonical request
        let canonical_headers = format!("host:{}\nx-amz-date:{}\n", host, datetime_str);
        let signed_headers = "host;x-amz-date";
        let hashed_payload = format!("{:x}", Sha256::digest(b""));
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method, uri, query_string, canonical_headers, signed_headers, hashed_payload
        );
        let hashed_canonical = format!("{:x}", Sha256::digest(canonical_request.as_bytes()));

        // Step 2: string to sign
        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            date_str, self.region_for_sign, SCP_SERVICE
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            datetime_str, credential_scope, hashed_canonical
        );

        // Step 3: signing key
        let k_secret = format!("AWS4{}", self.secret_key);
        let k_date = hmac_sha256(k_secret.as_bytes(), date_str.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region_for_sign.as_bytes());
        let k_service = hmac_sha256(&k_region, SCP_SERVICE.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        // Step 4: authorization header
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.secret_id, credential_scope, signed_headers, signature
        )
    }

    /// 发起已签名的 GET 请求
    async fn signed_get(&self, path: &str, query_string: &str) -> Result<serde_json::Value> {
        let now = Utc::now();
        let datetime_str = now.format("%Y%m%dT%H%M%SZ").to_string();

        let uri = format!("/janus/{}{}", API_VERSION, path);
        let authorization = self.sign_aws4("GET", &uri, query_string, &now);

        let base = self.base_url();
        let url = if query_string.is_empty() {
            format!("{}{}", base, path)
        } else {
            format!("{}{}?{}", base, path, query_string)
        };

        tracing::debug!(
            account = %self.account_name,
            url = %url,
            host_for_sign = %self.host_for_sign(),
            uri_for_sign = %uri,
            query_string = %query_string,
            x_amz_date = %datetime_str,
            region_for_sign = %self.region_for_sign,
            service = %SCP_SERVICE,
            authorization = %authorization,
            "Sangfor SCP request details"
        );

        let resp = self
            .client
            .get(&url)
            .header("x-amz-date", &datetime_str)
            .header("Authorization", &authorization)
            .header("Host", self.host_for_sign())
            .send()
            .await
            .with_context(|| format!("GET {} failed", url))?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            tracing::debug!(
                account = %self.account_name,
                status = %status,
                response_body = %text,
                "Sangfor SCP error response"
            );
            bail!("SCP API error ({}): {}", status, text);
        }

        let val: serde_json::Value =
            serde_json::from_str(&text).context("Failed to parse SCP response JSON")?;

        let code = val.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
        if code != 0 {
            let msg = val
                .get("message")
                .or_else(|| val.get("msg"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            bail!("SCP API returned error code {}: {}", code, msg);
        }

        Ok(val)
    }

    /// 列出指定 az_id（region）下所有服务器，处理分页
    async fn list_servers_in_region(&self, az_id: &str) -> Result<Vec<serde_json::Value>> {
        let mut servers = Vec::new();
        let mut page_num = 0u32;
        let page_size = 100u32;

        loop {
            let qs = format!(
                "az_id={}&page_num={}&page_size={}",
                az_id, page_num, page_size
            );
            let val = self.signed_get("/servers", &qs).await?;

            let data = val.get("data").unwrap_or(&serde_json::Value::Null);
            let items = data
                .get("data")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let total = data.get("total_size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

            let count = items.len();
            servers.extend(items);

            if servers.len() >= total || count < page_size as usize {
                break;
            }
            page_num += 1;
        }

        Ok(servers)
    }

    /// 获取单台服务器的最新指标（取最后一个数据点）
    async fn fetch_metrics_for_server(&self, server_id: &str) -> Result<HashMap<String, f64>> {
        let metric_names = "cpu.util,memory.util,io.read.iops,io.write.iops,net.in.bps,net.out.bps";
        let qs = format!(
            "object_type=server&metric_names={}&timegap=1h",
            metric_names
        );
        let path = format!("/metrics/{}", server_id);

        let val = self.signed_get(&path, &qs).await?;
        let data = val.get("data").unwrap_or(&serde_json::Value::Null);

        let mut result = HashMap::new();
        for name in metric_names.split(',') {
            if let Some(metric_obj) = data.get(name) {
                if let Some(datapoints) = metric_obj.get("datapoints").and_then(|v| v.as_array()) {
                    if let Some(last) = datapoints.last() {
                        // datapoints format: [[timestamp, value], ...]
                        let val = last
                            .as_array()
                            .and_then(|arr| arr.get(1))
                            .and_then(|v| v.as_f64());
                        if let Some(v) = val {
                            result.insert(name.to_string(), v);
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is valid");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[async_trait::async_trait]
impl CloudProvider for SangforCloudProvider {
    fn name(&self) -> &str {
        &self.account_name
    }

    async fn list_instances(&self) -> Result<Vec<CloudInstance>> {
        let mut instances = Vec::new();

        // 当 regions 为空时，尝试不带 az_id 列出所有服务器
        let regions_to_query: Vec<String> = if self.regions.is_empty() {
            vec![String::new()]
        } else {
            self.regions.clone()
        };

        for az_id in &regions_to_query {
            let servers = match self.list_servers_in_region(az_id).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        account = self.account_name,
                        az_id = az_id,
                        error = %e,
                        "Failed to list Sangfor SCP servers"
                    );
                    continue;
                }
            };

            for s in servers {
                let instance_id = s
                    .get("id")
                    .or_else(|| s.get("server_id"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if instance_id.is_empty() {
                    continue;
                }

                let instance_name = s
                    .get("name")
                    .or_else(|| s.get("server_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&instance_id)
                    .to_string();

                let status = s
                    .get("status")
                    .or_else(|| s.get("state"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let public_ip = s
                    .get("public_ip")
                    .or_else(|| s.get("float_ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let private_ip = s
                    .get("private_ip")
                    .or_else(|| s.get("ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let os = s
                    .get("os_type")
                    .or_else(|| s.get("os"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let cpu_cores = s
                    .get("vcpu")
                    .or_else(|| s.get("cpu"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);

                let memory_gb = s
                    .get("memory")
                    .and_then(|v| v.as_f64())
                    .map(|mb| mb / 1024.0);

                let disk_gb = s
                    .get("disk_size")
                    .or_else(|| s.get("system_disk_size"))
                    .and_then(|v| v.as_f64());

                let region = if az_id.is_empty() {
                    s.get("az_id")
                        .or_else(|| s.get("zone"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("default")
                        .to_string()
                } else {
                    az_id.clone()
                };

                let zone = s
                    .get("zone")
                    .or_else(|| s.get("az_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let instance = CloudInstance {
                    instance_id,
                    instance_name,
                    provider: format!("sangfor:{}", self.account_name),
                    region,
                    public_ip,
                    private_ip,
                    os,
                    status,
                    tags: HashMap::new(),
                    instance_type: String::new(),
                    cpu_cores,
                    memory_gb,
                    disk_gb,
                    created_time: None,
                    expired_time: None,
                    charge_type: None,
                    vpc_id: s
                        .get("vpc_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    subnet_id: None,
                    security_group_ids: vec![],
                    zone,
                    internet_max_bandwidth: None,
                    ipv6_addresses: vec![],
                    eip_allocation_id: None,
                    internet_charge_type: None,
                    image_id: s
                        .get("image_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    hostname: s
                        .get("hostname")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    description: None,
                    gpu: None,
                    io_optimized: None,
                    latest_operation: None,
                    latest_operation_state: None,
                    project_id: None,
                    resource_group_id: None,
                    auto_renew_flag: None,
                };

                if self.instance_filter.matches(&instance) {
                    instances.push(instance);
                }
            }
        }

        tracing::info!(
            account = self.account_name,
            count = instances.len(),
            "Listed Sangfor SCP instances"
        );

        Ok(instances)
    }

    async fn get_metrics(&self, instance_id: &str, region: &str) -> Result<CloudMetrics> {
        let metrics_map = self
            .fetch_metrics_for_server(instance_id)
            .await
            .with_context(|| format!("Failed to get metrics for server {}", instance_id))?;

        Ok(CloudMetrics {
            instance_id: instance_id.to_string(),
            instance_name: String::new(),
            provider: format!("sangfor:{}", self.account_name),
            region: region.to_string(),
            cpu_usage: metrics_map.get("cpu.util").copied(),
            memory_usage: metrics_map.get("memory.util").copied(),
            disk_usage: None,
            network_in_bytes: metrics_map.get("net.in.bps").copied(),
            network_out_bytes: metrics_map.get("net.out.bps").copied(),
            disk_iops_read: metrics_map.get("io.read.iops").copied(),
            disk_iops_write: metrics_map.get("io.write.iops").copied(),
            connections: None,
            collected_at: Utc::now(),
            instance_type: String::new(),
            cpu_cores: None,
            memory_gb: None,
            disk_gb: None,
        })
    }
}
