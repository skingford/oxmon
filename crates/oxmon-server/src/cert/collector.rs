use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use oxmon_common::types::CertificateDetails;
use rustls::pki_types::ServerName;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use trust_dns_resolver::TokioAsyncResolver;
use x509_parser::prelude::*;

/// 证书收集器
pub struct CertificateCollector {
    resolver: TokioAsyncResolver,
    timeout_secs: u64,
}

impl CertificateCollector {
    pub async fn new(timeout_secs: u64) -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .context("Failed to create DNS resolver")?;
        Ok(Self {
            resolver,
            timeout_secs,
        })
    }

    /// 收集域名的证书详细信息
    pub async fn collect(&self, domain: &str, port: u16) -> Result<CertificateDetails> {
        // 1. DNS 解析获取 IP 地址
        let ip_addresses = self.resolve_domain(domain).await?;

        if ip_addresses.is_empty() {
            anyhow::bail!("No IP addresses found for domain: {}", domain);
        }

        // 2. 连接到第一个 IP 并获取证书
        let mut last_error = None;
        for ip in &ip_addresses {
            match self.fetch_certificate(domain, *ip, port).await {
                Ok(details) => {
                    // 成功获取证书，返回结果（包含所有解析的 IP）
                    return Ok(CertificateDetails {
                        id: String::new(), // upsert 时由存储层生成
                        domain: domain.to_string(),
                        not_before: details.not_before,
                        not_after: details.not_after,
                        ip_addresses: ip_addresses.iter().map(|ip| ip.to_string()).collect(),
                        issuer_cn: details.issuer_cn,
                        issuer_o: details.issuer_o,
                        issuer_ou: details.issuer_ou,
                        issuer_c: details.issuer_c,
                        subject_alt_names: details.subject_alt_names,
                        chain_valid: details.chain_valid,
                        chain_error: details.chain_error,
                        last_checked: Utc::now(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    });
                }
                Err(e) => {
                    tracing::warn!(ip = %ip, error = %e, "Failed to fetch certificate from IP");
                    last_error = Some(e);
                }
            }
        }

        // 所有 IP 都失败了
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Failed to fetch certificate")))
    }

    /// DNS 解析域名获取 IP 地址
    async fn resolve_domain(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // 查询 A 记录 (IPv4)
        match timeout(
            Duration::from_secs(self.timeout_secs),
            self.resolver.ipv4_lookup(domain),
        )
        .await
        {
            Ok(Ok(response)) => {
                for ip in response.iter() {
                    ips.push(IpAddr::V4(ip.0));
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "IPv4 lookup failed");
            }
            Err(_) => {
                tracing::warn!("IPv4 lookup timeout");
            }
        }

        // 查询 AAAA 记录 (IPv6)
        match timeout(
            Duration::from_secs(self.timeout_secs),
            self.resolver.ipv6_lookup(domain),
        )
        .await
        {
            Ok(Ok(response)) => {
                for ip in response.iter() {
                    ips.push(IpAddr::V6(ip.0));
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "IPv6 lookup failed");
            }
            Err(_) => {
                tracing::warn!("IPv6 lookup timeout");
            }
        }

        Ok(ips)
    }

    /// 从指定 IP 获取证书
    async fn fetch_certificate(
        &self,
        domain: &str,
        ip: IpAddr,
        port: u16,
    ) -> Result<CertificateDetails> {
        // 连接到服务器
        let addr = format!("{}:{}", ip, port);
        let stream = timeout(
            Duration::from_secs(self.timeout_secs),
            TcpStream::connect(&addr),
        )
        .await
        .context("Connection timeout")?
        .context("Failed to connect")?;

        // TLS 配置
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(domain.to_string())
            .context("Invalid server name")?;

        // TLS 握手
        let tls_stream = timeout(
            Duration::from_secs(self.timeout_secs),
            connector.connect(server_name, stream),
        )
        .await
        .context("TLS handshake timeout")?
        .context("TLS handshake failed")?;

        // 获取证书链
        let (_, connection) = tls_stream.get_ref();
        let certs = connection
            .peer_certificates()
            .context("No peer certificates")?;

        if certs.is_empty() {
            anyhow::bail!("Empty certificate chain");
        }

        // 解析第一个证书（服务器证书）
        let cert_der = &certs[0];
        let (_, cert) = X509Certificate::from_der(cert_der)
            .context("Failed to parse certificate")?;

        // 提取证书信息
        let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_default();
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_default();

        // 提取颁发者信息
        let issuer = cert.issuer();
        let issuer_cn = issuer
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());
        let issuer_o = issuer
            .iter_organization()
            .next()
            .and_then(|o| o.as_str().ok())
            .map(|s| s.to_string());
        let issuer_ou = issuer
            .iter_organizational_unit()
            .next()
            .and_then(|ou| ou.as_str().ok())
            .map(|s| s.to_string());
        let issuer_c = issuer
            .iter_country()
            .next()
            .and_then(|c| c.as_str().ok())
            .map(|s| s.to_string());

        // 提取 SAN (Subject Alternative Names)
        let mut subject_alt_names = Vec::new();
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => {
                        subject_alt_names.push(dns.to_string());
                    }
                    GeneralName::IPAddress(ip_bytes) => {
                        if ip_bytes.len() == 4 {
                            let ip = IpAddr::from([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);
                            subject_alt_names.push(ip.to_string());
                        } else if ip_bytes.len() == 16 {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(ip_bytes);
                            let ip = IpAddr::from(octets);
                            subject_alt_names.push(ip.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        // 证书链验证（简化版本 - 实际上 rustls 已经验证过了）
        let chain_valid = certs.len() > 1; // 简单检查是否有完整链
        let chain_error = if !chain_valid {
            Some("Incomplete certificate chain".to_string())
        } else {
            None
        };

        Ok(CertificateDetails {
            id: String::new(), // upsert 时由存储层生成
            domain: domain.to_string(),
            not_before,
            not_after,
            ip_addresses: vec![ip.to_string()],
            issuer_cn,
            issuer_o,
            issuer_ou,
            issuer_c,
            subject_alt_names,
            chain_valid,
            chain_error,
            last_checked: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // 需要网络连接
    async fn test_collect_certificate() {
        let collector = CertificateCollector::new(10).await.unwrap();
        let result = collector.collect("example.com", 443).await;
        assert!(result.is_ok());
        let details = result.unwrap();
        assert_eq!(details.domain, "example.com");
        assert!(!details.ip_addresses.is_empty());
    }
}
