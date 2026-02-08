use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::CertCheckResult;
use rustls::ClientConfig;
use std::sync::Arc;
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
            error: None,
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
}

async fn do_check(domain: &str, port: i32, timeout_secs: u64) -> Result<CertInfo> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Build config that captures certificates but still verifies
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let addr = format!("{domain}:{port}");
    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid domain name: {e}"))?;

    // Connect with timeout
    let tcp = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timed out after {timeout_secs}s"))?
    .map_err(|e| anyhow::anyhow!("TCP connection failed: {e}"))?;

    // TLS handshake - if chain is invalid, rustls will return an error
    let tls_stream = match tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        connector.connect(server_name, tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => {
            // TLS error - might be invalid chain, expired cert, etc.
            return Ok(CertInfo {
                is_valid: false,
                chain_valid: false,
                not_before: None,
                not_after: None,
                days_until_expiry: None,
                issuer: None,
                subject: None,
                san_list: None,
            });
        }
        Err(_) => {
            return Err(anyhow::anyhow!("TLS handshake timed out"));
        }
    };

    // Extract peer certificates
    let (_io, conn) = tls_stream.into_inner();
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
    let not_before = DateTime::from_timestamp(not_before_time.unix_timestamp(), 0).unwrap_or_default();
    let not_after = DateTime::from_timestamp(not_after_time.unix_timestamp(), 0).unwrap_or_default();
    let days_until_expiry = (not_after - now).num_days();
    let is_valid = now >= not_before && now <= not_after;

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
        chain_valid: true,
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
    })
}
