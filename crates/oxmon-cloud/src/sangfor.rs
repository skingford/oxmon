use crate::{CloudAccountConfig, CloudInstance, CloudMetrics, CloudProvider};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const API_VERSION: &str = "20180725";
const DEFAULT_REGION_FOR_SIGN: &str = "regionOne";
const SCP_SERVICE: &str = "sdk-api";
const REQUEST_TIMEOUT_SECS: u64 = 30;

// ── 原始 HTTPS 客户端（保留 header 大小写）────────────────────────────────────
// 深信服 SCP 服务端对 HTTP header 名称大小写敏感（如 X-Amz-Date、Cookie）
// reqwest/hyper 会将所有 header 名强制转为小写，导致 401 签名验证失败
// 因此 Sangfor 模块不使用 reqwest，直接通过 tokio + rustls 发送原始 HTTP/1.1 请求

/// rustls 自定义证书验证器：接受任何证书（SCP 使用自签名证书）
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

/// 发送原始 HTTP/1.1 HTTPS GET 请求，完整保留 header 名称的大小写
///
/// 返回 (status_code, body_string)
async fn raw_https_get(
    endpoint: &str,
    path_and_query: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let timeout = std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS);

    // 构建 TLS 配置（跳过证书验证）
    let tls_config = rustls::ClientConfig::builder_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .with_safe_default_protocol_versions()
    .context("TLS protocol config failed")?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerifier))
    .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

    // 解析 endpoint 中的 hostname 和 port
    let raw_host = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let (hostname, port): (&str, u16) = if let Some((h, p)) = raw_host.rsplit_once(':') {
        (h, p.parse().unwrap_or(443))
    } else {
        (raw_host, 443)
    };

    // TCP 连接
    let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect((hostname, port)))
        .await
        .context("TCP connect timeout")?
        .with_context(|| format!("TCP connect to {}:{} failed", hostname, port))?;

    // TLS 握手
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .context("Invalid TLS server name")?;
    let mut tls = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .context("TLS handshake timeout")?
        .context("TLS handshake failed")?;

    // 构建原始 HTTP/1.1 请求（header 名称保留原始大小写）
    let mut req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path_and_query, hostname);
    for (name, value) in headers {
        req.push_str(&format!("{}: {}\r\n", name, value));
    }
    req.push_str("Connection: close\r\n\r\n");

    // 发送请求
    tokio::time::timeout(timeout, tls.write_all(req.as_bytes()))
        .await
        .context("request write timeout")?
        .context("request write failed")?;

    // 读取完整响应（Connection: close 保证服务端关闭连接后 read_to_end 返回）
    let mut buf = Vec::with_capacity(16384);
    tokio::time::timeout(timeout, tls.read_to_end(&mut buf))
        .await
        .context("response read timeout")?
        .context("response read failed")?;

    let response = String::from_utf8_lossy(&buf);

    // 分割 header 和 body
    let sep = response.find("\r\n\r\n").unwrap_or(response.len());
    let header_section = &response[..sep];
    let body_raw = response
        .get(sep + 4..)
        .unwrap_or("");

    // 解析状态码
    let status: u16 = header_section
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // 判断是否分块传输
    let is_chunked = header_section.lines().any(|l| {
        let ll = l.to_lowercase();
        ll.starts_with("transfer-encoding:") && ll.contains("chunked")
    });

    let body = if is_chunked {
        decode_chunked(body_raw).unwrap_or_else(|_| body_raw.to_string())
    } else {
        body_raw.to_string()
    };

    Ok((status, body))
}

/// 解码 HTTP/1.1 分块传输编码（Transfer-Encoding: chunked）
fn decode_chunked(input: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = input;
    loop {
        let crlf = rest
            .find("\r\n")
            .ok_or_else(|| anyhow::anyhow!("chunked: missing size line"))?;
        let size_str = rest[..crlf].split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_str, 16).context("chunked: invalid chunk size hex")?;
        rest = &rest[crlf + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            bail!("chunked: chunk data truncated");
        }
        out.push_str(&rest[..size]);
        rest = &rest[size + 2..]; // skip chunk data + trailing CRLF
    }
    Ok(out)
}
// ── /原始 HTTPS 客户端 ────────────────────────────────────────────────────────

pub struct SangforCloudProvider {
    account_name: String,
    secret_id: String,
    secret_key: String,
    /// 私有云所在的资源池 ID 列表（对应 SCP 中的 az_id 或 zone）
    regions: Vec<String>,
    /// 私有云访问地址，如 "192.168.1.100" 或 "scp.example.com:8443"
    endpoint: String,
    /// AWS4 签名使用的 region，默认 "regionOne"
    region_for_sign: String,
    /// SCP 6.3.0 及更早版本需要的 Cookie 认证 Token，SCP 6.3.70+ 无需
    scp_auth_token: Option<String>,
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

        Ok(Self {
            account_name: account_name.to_string(),
            secret_id: config.secret_id,
            secret_key: config.secret_key,
            regions: config.regions,
            endpoint,
            region_for_sign,
            scp_auth_token: config.scp_auth_token,
            instance_filter: config.instance_filter,
        })
    }

    /// AWS4-HMAC-SHA256 签名，用于深信服 SCP Open API
    ///
    /// 签名规范参考官方 Python SDK（sdk_py3）：
    ///   - signed_headers = "cookie;x-amz-date"（深信服自定义变体）
    ///   - canonical query string 始终为空字符串（SDK 中 params={} 始终为空，
    ///     查询参数仅出现在 URL 中，不参与签名）
    ///   - 当携带 Cookie 时，canonical_headers 包含 cookie 和 x-amz-date 两行
    ///   - 当不携带 Cookie 时，canonical_headers 只包含 x-amz-date 一行
    ///     但 Authorization 中 SignedHeaders 仍声明 "cookie;x-amz-date"（与 SDK 行为一致）
    ///
    /// 返回 (Authorization, datetime_str, canonical_request, string_to_sign)
    fn sign_aws4(
        &self,
        method: &str,
        uri: &str,
        now: &DateTime<Utc>,
        cookie_value: Option<&str>,
    ) -> (String, String, String, String) {
        let date_str = now.format("%Y%m%d").to_string();
        let datetime_str = now.format("%Y%m%dT%H%M%SZ").to_string();

        // signed_headers 固定为 "cookie;x-amz-date"（与官方 Python SDK 一致）
        let signed_headers = "cookie;x-amz-date";

        // canonical_headers 包含实际存在的头部，按字母序排列
        // cookie 在 x-amz-date 之前（c < x）
        let canonical_headers = match cookie_value {
            Some(cookie) => format!("cookie:{}\nx-amz-date:{}\n", cookie, datetime_str),
            None => format!("x-amz-date:{}\n", datetime_str),
        };

        let hashed_payload = format!("{:x}", Sha256::digest(b""));
        // 注意：canonical query string 始终为空（与 Python SDK 一致，查询参数不参与签名）
        let canonical_request = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            method, uri, canonical_headers, signed_headers, hashed_payload
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
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.secret_id, credential_scope, signed_headers, signature
        );
        (authorization, datetime_str, canonical_request, string_to_sign)
    }

    /// 发起已签名的 GET 请求（使用原始 TCP+TLS，保留 header 大小写）
    async fn signed_get(&self, path: &str, query_string: &str) -> Result<serde_json::Value> {
        let now = Utc::now();

        let uri = format!("/janus/{}{}", API_VERSION, path);

        // 构造 Cookie 值：Python SDK 始终携带 Cookie: aCMPAuthToken=<uuid>
        // 若配置了 scp_auth_token（SCP 6.3.0 及更早版本），使用配置值；否则生成随机 UUID
        let cookie_token = self
            .scp_auth_token
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
        let cookie_header_value = format!("aCMPAuthToken={}", cookie_token);

        let (authorization, datetime_str, canonical_request, string_to_sign) =
            self.sign_aws4("GET", &uri, &now, Some(&cookie_header_value));

        // path_and_query 用于原始 HTTP 请求行（含查询参数）
        let path_and_query = if query_string.is_empty() {
            format!("/janus/{}{}", API_VERSION, path)
        } else {
            format!("/janus/{}{}?{}", API_VERSION, path, query_string)
        };

        // 使用原始 HTTPS 客户端，保留 header 名称大小写（X-Amz-Date、Authorization、Cookie）
        // SCP 服务端对 header 名称大小写敏感，reqwest/hyper 发送小写 header 会导致 401
        let req_headers: &[(&str, &str)] = &[
            ("X-Amz-Date", &datetime_str),
            ("Authorization", &authorization),
            ("Cookie", &cookie_header_value),
        ];

        let (status, text) =
            raw_https_get(&self.endpoint, &path_and_query, req_headers)
                .await
                .with_context(|| format!("raw HTTPS GET {}{} failed", self.endpoint, path_and_query))?;

        if status < 200 || status >= 300 {
            tracing::error!(
                account = %self.account_name,
                http_status = %status,
                response_body = %text,
                uri_for_sign = %uri,
                canonical_request = %canonical_request,
                string_to_sign = %string_to_sign,
                "Sangfor SCP request failed"
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
            // az_id 为空时不传该参数，否则服务器返回 "az_id输入错误：值必须是UUID格式"
            let qs = if az_id.is_empty() {
                format!("page_num={}&page_size={}", page_num, page_size)
            } else {
                format!("az_id={}&page_num={}&page_size={}", az_id, page_num, page_size)
            };
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

                // SCP IP 地址在 networks 数组中，ip_address 字段
                let networks = s
                    .get("networks")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let first_net = networks.first();

                let private_ip = first_net
                    .and_then(|n| n.get("ip_address"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // SCP 浮动 IP（公网 IP）可能在其他网络接口中，暂时留空
                let public_ip = s
                    .get("public_ip")
                    .or_else(|| s.get("float_ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let os = s
                    .get("os_type")
                    .or_else(|| s.get("os"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // SCP 用 "cores" 字段表示 vCPU 数量
                let cpu_cores = s
                    .get("cores")
                    .or_else(|| s.get("vcpu"))
                    .or_else(|| s.get("cpu"))
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);

                // SCP 用 "memory_mb" 字段（单位 MB），转换为 GB
                let memory_gb = s
                    .get("memory_mb")
                    .or_else(|| s.get("memory"))
                    .and_then(|v| v.as_f64())
                    .map(|mb| mb / 1024.0);

                // SCP 用 "storage_mb" 字段（单位 MB），转换为 GB
                let disk_gb = s
                    .get("storage_mb")
                    .or_else(|| s.get("disk_size"))
                    .or_else(|| s.get("system_disk_size"))
                    .and_then(|v| v.as_f64())
                    .map(|mb| mb / 1024.0);

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
                    // vpc_id 在 networks 数组中
                    vpc_id: first_net
                        .and_then(|n| n.get("vpc_id"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_matches_python() {
        let secret_key = "0c345d26da5046d6a015df07e2b621bb";
        let _secret_id = "febd45a7154f43c294947c2c47004cad"; // test.py access_key
        let region = "regionOne";
        let date_str = "20240101";
        let datetime_str = "20240101T120000Z";
        let cookie_value = "aCMPAuthToken=testtoken1234567890abcdef";
        let method = "GET";
        let uri = "/janus/20180725/azs";
        let signed_headers = "cookie;x-amz-date";
        let hashed_payload = format!("{:x}", Sha256::digest(b""));

        let canonical_headers = format!("cookie:{}\nx-amz-date:{}\n", cookie_value, datetime_str);
        let canonical_request = format!(
            "{}\n{}\n\n{}\n{}\n{}",
            method, uri, canonical_headers, signed_headers, hashed_payload
        );
        eprintln!("canonical_headers: {:?}", canonical_headers);
        eprintln!("canonical_request: {:?}", canonical_request);

        let hashed_canonical = format!("{:x}", Sha256::digest(canonical_request.as_bytes()));
        let credential_scope = format!("{}/{}/{}/aws4_request", date_str, region, SCP_SERVICE);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            datetime_str, credential_scope, hashed_canonical
        );
        eprintln!("string_to_sign: {:?}", string_to_sign);

        let k_secret = format!("AWS4{}", secret_key);
        let k_date = hmac_sha256(k_secret.as_bytes(), date_str.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, SCP_SERVICE.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
        eprintln!("signature: {}", signature);

        // Expected from Python
        assert_eq!(
            signature,
            "7f57de3c0021c7ce673be411a9a1eb58761fce2867a84cbea0605fc2c92808fa",
            "Signature should match Python output"
        );
    }
}
