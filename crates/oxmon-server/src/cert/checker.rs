use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::CertCheckResult;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::ClientConfig;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

pub async fn check_certificate(
    domain: &str,
    port: i32,
    domain_id: &str,
    timeout_secs: u64,
) -> CertCheckResult {
    let now = Utc::now();

    // 解析域名 IP 地址
    let resolved_ips = resolve_ips(domain, port).await;
    let ips_field = if resolved_ips.is_empty() {
        None
    } else {
        Some(resolved_ips)
    };

    match do_check(domain, port, timeout_secs).await {
        Ok(result) => CertCheckResult {
            id: oxmon_common::id::next_id(),
            domain_id: domain_id.to_string(),
            domain: domain.to_string(),
            is_valid: result.is_valid,
            chain_valid: result.chain_valid,
            not_before: result.not_before,
            not_after: result.not_after,
            days_until_expiry: result.days_until_expiry,
            issuer: result.issuer,
            subject: result.subject,
            san_list: result.san_list,
            resolved_ips: ips_field,
            error: result.error,
            checked_at: now,
            created_at: now,
            updated_at: now,
        },
        Err(e) => CertCheckResult {
            id: oxmon_common::id::next_id(),
            domain_id: domain_id.to_string(),
            domain: domain.to_string(),
            is_valid: false,
            chain_valid: false,
            not_before: None,
            not_after: None,
            days_until_expiry: None,
            issuer: None,
            subject: None,
            san_list: None,
            resolved_ips: ips_field,
            error: Some(e.to_string()),
            checked_at: now,
            created_at: now,
            updated_at: now,
        },
    }
}

/// 解析域名对应的 IP 地址列表
async fn resolve_ips(domain: &str, port: i32) -> Vec<String> {
    let addr = format!("{domain}:{port}");
    let result = tokio::net::lookup_host(&addr).await;
    match result {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(e) => {
            tracing::debug!(domain, error = %e, "DNS resolution failed");
            Vec::new()
        }
    }
}

struct CertInfo {
    is_valid: bool,
    chain_valid: bool,
    not_before: Option<chrono::DateTime<Utc>>,
    not_after: Option<chrono::DateTime<Utc>>,
    days_until_expiry: Option<i64>,
    issuer: Option<String>,
    subject: Option<String>,
    san_list: Option<Vec<String>>,
    error: Option<String>,
}

/// 捕获验证结果但不中断握手的自定义验证器。
/// 包装真实的 WebPKI 验证器，将验证错误存入共享状态，但始终返回 Ok 以保证握手完成。
#[derive(Debug)]
struct CaptureVerifier {
    inner: Arc<rustls::crypto::CryptoProvider>,
    root_store: Arc<rustls::RootCertStore>,
    verify_error: Arc<Mutex<Option<String>>>,
}

impl CaptureVerifier {
    fn new(root_store: rustls::RootCertStore) -> (Arc<Self>, Arc<Mutex<Option<String>>>) {
        let verify_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(Self {
            inner: provider,
            root_store: Arc::new(root_store),
            verify_error: Arc::clone(&verify_error),
        });
        (verifier, verify_error)
    }
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // 用真实的 WebPKI 验证器执行验证
        let real_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::clone(&self.root_store),
            Arc::clone(&self.inner),
        )
        .build()
        .map_err(|e| rustls::Error::General(format!("Failed to build verifier: {e}")))?;

        match real_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => {
                // 验证通过，清除错误
                if let Ok(mut err) = self.verify_error.lock() {
                    *err = None;
                }
                Ok(verified)
            }
            Err(e) => {
                // 验证失败，捕获错误但允许握手继续
                if let Ok(mut err) = self.verify_error.lock() {
                    *err = Some(format!("{e}"));
                }
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.inner.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.inner.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn do_check(domain: &str, port: i32, timeout_secs: u64) -> Result<CertInfo> {
    let addr = format!("{domain}:{port}");
    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid domain name: {e}"))?;

    // 构建捕获验证结果的验证器：只需一次 TLS 握手即可同时获取证书信息和验证状态
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let (capture_verifier, verify_error) = CaptureVerifier::new(root_store);

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(capture_verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    // TCP 连接
    let tcp = tokio::time::timeout(Duration::from_secs(timeout_secs), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("Connection timed out after {timeout_secs}s"))?
        .map_err(|e| anyhow::anyhow!("TCP connection failed: {e}"))?;

    // TLS 握手（验证失败不会中断，错误被捕获到 verify_error 中）
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))?
    .map_err(|e| anyhow::anyhow!("TLS handshake failed: {e}"))?;

    // 提取验证结果
    let captured_error = verify_error.lock().ok().and_then(|guard| guard.clone());

    let chain_valid = captured_error.is_none();
    let error = captured_error.map(|e| format!("TLS verification failed: {e}"));

    let (_io, conn) = tls_stream.into_inner();
    extract_cert_info_from_conn(&conn, chain_valid, error)
}

/// 从 TLS 连接中提取证书信息
fn extract_cert_info_from_conn(
    conn: &rustls::ClientConnection,
    chain_valid: bool,
    error: Option<String>,
) -> Result<CertInfo> {
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("No peer certificates"))?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!("Empty certificate chain"));
    }

    // Parse the leaf certificate
    let leaf_der = &certs[0];
    let (_, cert) = X509Certificate::from_der(leaf_der.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {e}"))?;

    let now = Utc::now();
    let not_before_time = cert.validity().not_before.to_datetime();
    let not_after_time = cert.validity().not_after.to_datetime();
    let not_before =
        DateTime::from_timestamp(not_before_time.unix_timestamp(), 0).unwrap_or_default();
    let not_after =
        DateTime::from_timestamp(not_after_time.unix_timestamp(), 0).unwrap_or_default();
    let days_until_expiry = (not_after - now).num_days();
    let is_valid = now >= not_before && now <= not_after && chain_valid;

    let issuer = Some(cert.issuer().to_string());
    let subject = Some(cert.subject().to_string());

    // Extract SANs
    let san_list: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some(dns.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(CertInfo {
        is_valid,
        chain_valid,
        not_before: Some(not_before),
        not_after: Some(not_after),
        days_until_expiry: Some(days_until_expiry),
        issuer,
        subject,
        san_list: if san_list.is_empty() {
            None
        } else {
            Some(san_list)
        },
        error,
    })
}
