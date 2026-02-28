use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use hickory_resolver::TokioResolver;
use oxmon_common::types::CertificateDetails;
use rustls::pki_types::ServerName;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::oid_registry;
use x509_parser::prelude::*;

/// 证书收集器
pub struct CertificateCollector {
    resolver: TokioResolver,
    timeout_secs: u64,
}

impl CertificateCollector {
    pub async fn new(timeout_secs: u64) -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .context("Failed to create DNS resolver")?
            .build();
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
                Ok(mut details) => {
                    // 成功获取证书，填充所有解析的 IP
                    details.ip_addresses = ip_addresses.iter().map(|ip| ip.to_string()).collect();
                    return Ok(details);
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
        let server_name =
            ServerName::try_from(domain.to_string()).context("Invalid server name")?;

        // TLS 握手
        let tls_stream = timeout(
            Duration::from_secs(self.timeout_secs),
            connector.connect(server_name, stream),
        )
        .await
        .context("TLS handshake timeout")?
        .context("TLS handshake failed")?;

        // 获取 TLS 连接信息
        let (_, connection) = tls_stream.get_ref();

        let tls_version = connection.protocol_version().map(|v| format!("{v:?}"));
        let cipher_suite = connection
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()));

        let certs = connection
            .peer_certificates()
            .context("No peer certificates")?;

        if certs.is_empty() {
            anyhow::bail!("Empty certificate chain");
        }

        let chain_depth = certs.len() as i32;

        // 解析第一个证书（服务器证书）
        let cert_der = &certs[0];
        let (_, cert) =
            X509Certificate::from_der(cert_der).context("Failed to parse certificate")?;

        // 提取证书信息
        let not_before =
            DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0).unwrap_or_default();
        let not_after =
            DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0).unwrap_or_default();

        // 序列号
        let serial_number = Some(cert.raw_serial_as_string());

        // SHA-256 指纹
        let fingerprint_sha256 = Some(hex_encode(&Sha256::digest(cert_der.as_ref())));

        // 证书版本 (X.509 v1=0, v2=1, v3=2, 返回 1/2/3)
        let version = Some(cert.version().0 as i32 + 1);

        // 签名算法
        let signature_algorithm = Some(oid_to_sig_name(&cert.signature_algorithm.algorithm));

        // 公钥算法和长度
        let pk = cert.public_key();
        let public_key_algorithm = Some(oid_to_pk_name(&pk.algorithm.algorithm));
        let public_key_bits = estimate_key_bits(&cert);

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

        // 提取主体信息
        let subject = cert.subject();
        let subject_cn = subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(|s| s.to_string());
        let subject_o = subject
            .iter_organization()
            .next()
            .and_then(|o| o.as_str().ok())
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
                            let ip =
                                IpAddr::from([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);
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

        // 是否通配符证书
        let is_wildcard = Some(subject_alt_names.iter().any(|s| s.starts_with("*.")));

        // Key Usage
        let key_usage = extract_key_usage(&cert);

        // Extended Key Usage
        let extended_key_usage = extract_extended_key_usage(&cert);

        // Basic Constraints - is_ca
        let is_ca = Some(cert.is_ca());

        // AIA (Authority Information Access) - OCSP 和 CA Issuers
        let (ocsp_urls, ca_issuer_urls) = extract_authority_info_access(&cert);

        // CRL Distribution Points
        let crl_urls = extract_crl_distribution_points(&cert);

        // SCT count
        let sct_count = extract_sct_count(&cert);

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
            serial_number,
            fingerprint_sha256,
            version,
            signature_algorithm,
            public_key_algorithm,
            public_key_bits,
            subject_cn,
            subject_o,
            key_usage,
            extended_key_usage,
            is_ca,
            is_wildcard,
            ocsp_urls,
            crl_urls,
            ca_issuer_urls,
            sct_count,
            tls_version,
            cipher_suite,
            chain_depth: Some(chain_depth),
        })
    }
}

/// 将字节序列编码为十六进制字符串，冒号分隔
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// 将签名算法 OID 映射为可读名称
fn oid_to_sig_name(oid: &asn1_rs::Oid) -> String {
    // 常见的签名算法 OID
    let known = [
        (oid_registry::OID_PKCS1_SHA256WITHRSA, "SHA256withRSA"),
        (oid_registry::OID_PKCS1_SHA384WITHRSA, "SHA384withRSA"),
        (oid_registry::OID_PKCS1_SHA512WITHRSA, "SHA512withRSA"),
        (oid_registry::OID_PKCS1_SHA1WITHRSA, "SHA1withRSA"),
        (oid_registry::OID_SIG_ECDSA_WITH_SHA256, "ECDSAwithSHA256"),
        (oid_registry::OID_SIG_ECDSA_WITH_SHA384, "ECDSAwithSHA384"),
        (oid_registry::OID_SIG_ECDSA_WITH_SHA512, "ECDSAwithSHA512"),
        (oid_registry::OID_SIG_ED25519, "Ed25519"),
    ];
    for (known_oid, name) in &known {
        if oid == known_oid {
            return name.to_string();
        }
    }
    format!("{oid}")
}

/// 将公钥算法 OID 映射为可读名称
fn oid_to_pk_name(oid: &asn1_rs::Oid) -> String {
    let known = [
        (oid_registry::OID_PKCS1_RSAENCRYPTION, "RSA"),
        (oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY, "ECDSA"),
        (oid_registry::OID_SIG_ED25519, "Ed25519"),
    ];
    for (known_oid, name) in &known {
        if oid == known_oid {
            return name.to_string();
        }
    }
    format!("{oid}")
}

/// 估算公钥位数
fn estimate_key_bits(cert: &X509Certificate) -> Option<i32> {
    let pk = cert.public_key();
    let alg = &pk.algorithm.algorithm;

    if *alg == oid_registry::OID_PKCS1_RSAENCRYPTION {
        // RSA: 解析 SubjectPublicKeyInfo 中的 modulus 长度
        // DER 编码的 bit string 内容，跳过 padding byte
        let key_data = &pk.subject_public_key.data;
        // RSA public key 是一个 SEQUENCE { modulus INTEGER, exponent INTEGER }
        if let Ok((_, seq)) = x509_parser::der_parser::parse_der(key_data) {
            if let Ok(items) = seq.as_sequence() {
                if let Some(modulus) = items.first() {
                    if let Ok(big) = modulus.as_biguint() {
                        return Some(big.bits() as i32);
                    }
                }
            }
        }
        None
    } else if *alg == oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
        // EC: 根据曲线 OID 判断
        if let Some(params) = &pk.algorithm.parameters {
            if let Ok(oid) = params.as_oid() {
                // P-256 = 256 bits, P-384 = 384 bits, P-521 = 521 bits
                if oid == oid_registry::OID_EC_P256 {
                    return Some(256);
                } else if oid == oid_registry::OID_NIST_EC_P384 {
                    return Some(384);
                } else if oid == oid_registry::OID_NIST_EC_P521 {
                    return Some(521);
                }
            }
        }
        None
    } else if *alg == oid_registry::OID_SIG_ED25519 {
        Some(256)
    } else {
        None
    }
}

/// 提取 Key Usage 扩展
fn extract_key_usage(cert: &X509Certificate) -> Option<Vec<String>> {
    let ku = match cert.key_usage() {
        Ok(Some(ku)) => ku,
        _ => return None,
    };

    let mut usages = Vec::new();
    let flags = &ku.value;
    if flags.digital_signature() {
        usages.push("digital_signature".to_string());
    }
    if flags.non_repudiation() {
        usages.push("non_repudiation".to_string());
    }
    if flags.key_encipherment() {
        usages.push("key_encipherment".to_string());
    }
    if flags.data_encipherment() {
        usages.push("data_encipherment".to_string());
    }
    if flags.key_agreement() {
        usages.push("key_agreement".to_string());
    }
    if flags.key_cert_sign() {
        usages.push("key_cert_sign".to_string());
    }
    if flags.crl_sign() {
        usages.push("crl_sign".to_string());
    }
    if flags.encipher_only() {
        usages.push("encipher_only".to_string());
    }
    if flags.decipher_only() {
        usages.push("decipher_only".to_string());
    }

    if usages.is_empty() {
        None
    } else {
        Some(usages)
    }
}

/// 提取 Extended Key Usage 扩展
fn extract_extended_key_usage(cert: &X509Certificate) -> Option<Vec<String>> {
    let eku = match cert.extended_key_usage() {
        Ok(Some(eku)) => eku,
        _ => return None,
    };

    let mut usages = Vec::new();
    let value = &eku.value;
    if value.server_auth {
        usages.push("server_auth".to_string());
    }
    if value.client_auth {
        usages.push("client_auth".to_string());
    }
    if value.code_signing {
        usages.push("code_signing".to_string());
    }
    if value.email_protection {
        usages.push("email_protection".to_string());
    }
    if value.time_stamping {
        usages.push("time_stamping".to_string());
    }
    if value.ocsp_signing {
        usages.push("ocsp_signing".to_string());
    }
    // any 和其他未知用途
    if value.any {
        usages.push("any".to_string());
    }
    for oid in &value.other {
        usages.push(format!("{oid}"));
    }

    if usages.is_empty() {
        None
    } else {
        Some(usages)
    }
}

/// 提取 Authority Information Access 扩展 (OCSP URLs 和 CA Issuer URLs)
fn extract_authority_info_access(
    cert: &X509Certificate,
) -> (Option<Vec<String>>, Option<Vec<String>>) {
    let aia_oid = oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS;

    let ext = match cert.get_extension_unique(&aia_oid) {
        Ok(Some(ext)) => ext,
        _ => return (None, None),
    };

    if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
        let mut ocsp_urls = Vec::new();
        let mut ca_issuer_urls = Vec::new();

        // OCSP OID: 1.3.6.1.5.5.7.48.1
        let ocsp_oid = oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP;
        // CA Issuers OID: 1.3.6.1.5.5.7.48.2
        let ca_issuers_oid = oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS;

        for desc in &aia.accessdescs {
            if let GeneralName::URI(uri) = &desc.access_location {
                if desc.access_method == ocsp_oid {
                    ocsp_urls.push(uri.to_string());
                } else if desc.access_method == ca_issuers_oid {
                    ca_issuer_urls.push(uri.to_string());
                }
            }
        }

        let ocsp = if ocsp_urls.is_empty() {
            None
        } else {
            Some(ocsp_urls)
        };
        let ca_issuers = if ca_issuer_urls.is_empty() {
            None
        } else {
            Some(ca_issuer_urls)
        };

        (ocsp, ca_issuers)
    } else {
        (None, None)
    }
}

/// 提取 CRL Distribution Points 扩展
fn extract_crl_distribution_points(cert: &X509Certificate) -> Option<Vec<String>> {
    let crl_oid = oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;

    let ext = match cert.get_extension_unique(&crl_oid) {
        Ok(Some(ext)) => ext,
        _ => return None,
    };

    if let ParsedExtension::CRLDistributionPoints(cdp) = ext.parsed_extension() {
        let mut urls = Vec::new();
        for point in &cdp.points {
            if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                for name in names {
                    if let GeneralName::URI(uri) = name {
                        urls.push(uri.to_string());
                    }
                }
            }
        }

        if urls.is_empty() {
            None
        } else {
            Some(urls)
        }
    } else {
        None
    }
}

/// 提取 SCT (Signed Certificate Timestamp) 数量
fn extract_sct_count(cert: &X509Certificate) -> Option<i32> {
    // SCT List OID: 1.3.6.1.4.1.11129.2.4.2
    let sct_oid = asn1_rs::oid!(1.3.6 .1 .4 .1 .11129 .2 .4 .2);

    let ext = match cert.get_extension_unique(&sct_oid) {
        Ok(Some(ext)) => ext,
        _ => return None,
    };

    // SCT list 是 DER 编码的 OCTET STRING，内部为 TLS 编码：
    // 2-byte 总长度, 然后每个 SCT 有 2-byte 长度前缀
    let data = ext.value;
    if data.len() < 2 {
        return Some(0);
    }

    let total_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + total_len {
        return Some(0);
    }

    let mut count = 0;
    let mut offset = 2;
    while offset + 2 <= 2 + total_len {
        let sct_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + sct_len;
        count += 1;
    }

    Some(count)
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
        // 验证新字段已填充
        assert!(details.serial_number.is_some());
        assert!(details.fingerprint_sha256.is_some());
        assert!(details.version.is_some());
        assert!(details.signature_algorithm.is_some());
        assert!(details.public_key_algorithm.is_some());
        assert!(details.tls_version.is_some());
        assert!(details.cipher_suite.is_some());
        assert!(details.chain_depth.is_some());
    }
}
