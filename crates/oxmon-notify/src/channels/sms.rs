use crate::plugin::ChannelPlugin;
use crate::{NotificationChannel, SendResponse};
use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, Mac};
use oxmon_common::types::AlertEvent;
use serde::Deserialize;
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tracing;

// ── Provider configs ──

#[derive(Deserialize)]
struct GenericSmsConfig {
    gateway_url: String,
    api_key: String,
}

#[derive(Deserialize)]
struct AliyunSmsConfig {
    access_key_id: String,
    access_key_secret: String,
    sign_name: String,
    template_code: String,
    #[serde(default)]
    template_param: Option<String>,
    #[serde(default = "default_aliyun_endpoint")]
    endpoint: String,
}

fn default_aliyun_endpoint() -> String {
    "dysmsapi.aliyuncs.com".to_string()
}

#[derive(Deserialize)]
struct TencentSmsConfig {
    secret_id: String,
    secret_key: String,
    sdk_app_id: String,
    sign_name: String,
    template_id: String,
    #[serde(default)]
    template_params: Vec<String>,
    #[serde(default = "default_tencent_endpoint")]
    endpoint: String,
    #[serde(default = "default_tencent_region")]
    region: String,
}

fn default_tencent_endpoint() -> String {
    "sms.tencentcloudapi.com".to_string()
}

fn default_tencent_region() -> String {
    "ap-guangzhou".to_string()
}

// ── Provider enum ──

enum SmsProvider {
    Generic {
        gateway_url: String,
        api_key: String,
    },
    Aliyun {
        access_key_id: String,
        access_key_secret: String,
        sign_name: String,
        template_code: String,
        template_param: Option<String>,
        endpoint: String,
    },
    Tencent {
        secret_id: String,
        secret_key: String,
        sdk_app_id: String,
        sign_name: String,
        template_id: String,
        template_params: Vec<String>,
        endpoint: String,
        region: String,
    },
}

// ── Channel ──

pub struct SmsChannel {
    instance_id: String,
    client: reqwest::Client,
    provider: SmsProvider,
}

impl SmsChannel {
    fn format_message(alert: &AlertEvent) -> String {
        let status_tag = if alert.status == 3 { "[RECOVERED]" } else { "" };
        let rule_display = if alert.rule_name.is_empty() {
            String::new()
        } else {
            format!(" {}", alert.rule_name)
        };
        format!(
            "[oxmon][{severity}]{status_tag}{rule_display} {agent}: {message}",
            severity = alert.severity,
            status_tag = status_tag,
            rule_display = rule_display,
            agent = alert.agent_id,
            message = alert.message,
        )
    }

    // ── Generic ──

    async fn send_generic(
        &self,
        gateway_url: &str,
        api_key: &str,
        alert: &AlertEvent,
        recipients: &[String],
    ) -> Result<()> {
        let message = Self::format_message(alert);

        for phone in recipients {
            let payload = serde_json::json!({
                "to": phone,
                "message": message,
            });

            let mut last_err = None;
            for attempt in 0..3u32 {
                match self
                    .client
                    .post(gateway_url)
                    .header("Authorization", format!("Bearer {}", api_key))
                    .json(&payload)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        last_err = None;
                        break;
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        tracing::warn!(attempt = attempt + 1, phone = %phone, status = %status, "SMS gateway returned error, retrying");
                        last_err = Some(anyhow::anyhow!("HTTP {status}"));
                    }
                    Err(e) => {
                        tracing::warn!(attempt = attempt + 1, phone = %phone, error = %e, "SMS send failed, retrying");
                        last_err = Some(e.into());
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt)))
                    .await;
            }

            if let Some(e) = last_err {
                tracing::error!(phone = %phone, error = %e, "SMS failed after 3 retries");
            }
        }
        Ok(())
    }

    // ── Aliyun ──

    /// Percent-encode per Aliyun POP API spec (RFC 3986 strict).
    pub(crate) fn aliyun_percent_encode(s: &str) -> String {
        let mut result = String::new();
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        result
    }

    /// Compute Aliyun POP v1 HMAC-SHA1 signature.
    pub(crate) fn aliyun_sign(params: &[(String, String)], access_key_secret: &str) -> String {
        let mut sorted = params.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        let query_string: String = sorted
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    Self::aliyun_percent_encode(k),
                    Self::aliyun_percent_encode(v)
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        let string_to_sign = format!(
            "GET&{}&{}",
            Self::aliyun_percent_encode("/"),
            Self::aliyun_percent_encode(&query_string)
        );

        let signing_key = format!("{}&", access_key_secret);
        type HmacSha1 = Hmac<Sha1>;
        let mut mac =
            HmacSha1::new_from_slice(signing_key.as_bytes()).expect("HMAC can take key of any size");
        mac.update(string_to_sign.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_aliyun(
        &self,
        access_key_id: &str,
        access_key_secret: &str,
        sign_name: &str,
        template_code: &str,
        template_param: Option<&str>,
        endpoint: &str,
        alert: &AlertEvent,
        recipients: &[String],
    ) -> Result<()> {
        let message = Self::format_message(alert);

        for phone in recipients {
            let nonce = format!("{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
            let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

            let tpl_param = template_param
                .map(|s| s.to_string())
                .unwrap_or_else(|| serde_json::json!({"msg": message}).to_string());

            let mut params = vec![
                ("AccessKeyId".to_string(), access_key_id.to_string()),
                ("Action".to_string(), "SendSms".to_string()),
                ("Format".to_string(), "JSON".to_string()),
                ("PhoneNumbers".to_string(), phone.clone()),
                ("SignName".to_string(), sign_name.to_string()),
                ("SignatureMethod".to_string(), "HMAC-SHA1".to_string()),
                ("SignatureNonce".to_string(), nonce),
                ("SignatureVersion".to_string(), "1.0".to_string()),
                ("TemplateCode".to_string(), template_code.to_string()),
                ("TemplateParam".to_string(), tpl_param),
                ("Timestamp".to_string(), timestamp),
                ("Version".to_string(), "2017-05-25".to_string()),
            ];

            let signature = Self::aliyun_sign(&params, access_key_secret);
            params.push(("Signature".to_string(), signature));

            // Build query string manually
            let qs: String = params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            let url = format!("https://{}/?{}", endpoint, qs);

            let mut last_err = None;
            for attempt in 0..3u32 {
                match self.client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<serde_json::Value>().await {
                            Ok(body) => {
                                if body.get("Code").and_then(|v: &Value| v.as_str()) == Some("OK") {
                                    last_err = None;
                                    break;
                                }
                                let errmsg = body
                                    .get("Message")
                                    .and_then(|v: &Value| v.as_str())
                                    .unwrap_or("unknown");
                                tracing::warn!(attempt = attempt + 1, phone = %phone, error = errmsg, "Aliyun SMS API error, retrying");
                                last_err = Some(anyhow::anyhow!("Aliyun SMS error: {errmsg}"));
                            }
                            Err(e) => {
                                last_err = Some(anyhow::anyhow!("Aliyun SMS response parse error: {e}"));
                            }
                        }
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        tracing::warn!(attempt = attempt + 1, phone = %phone, status = %status, "Aliyun SMS HTTP error, retrying");
                        last_err = Some(anyhow::anyhow!("HTTP {status}"));
                    }
                    Err(e) => {
                        tracing::warn!(attempt = attempt + 1, phone = %phone, error = %e, "Aliyun SMS request failed, retrying");
                        last_err = Some(anyhow::anyhow!("Aliyun SMS request error: {e}"));
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt)))
                    .await;
            }

            if let Some(e) = last_err {
                tracing::error!(phone = %phone, error = %e, "Aliyun SMS failed after 3 retries");
            }
        }
        Ok(())
    }

    // ── Tencent ──

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Self::hex_encode(&hasher.finalize())
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Compute Tencent Cloud TC3-HMAC-SHA256 authorization header.
    pub(crate) fn tencent_sign(
        secret_id: &str,
        secret_key: &str,
        service: &str,
        host: &str,
        payload: &str,
        timestamp: i64,
    ) -> String {
        let date = chrono::DateTime::from_timestamp(timestamp, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d")
            .to_string();

        let credential_scope = format!("{}/{}/tc3_request", date, service);

        // Step 1: CanonicalRequest
        let hashed_payload = Self::sha256_hex(payload.as_bytes());
        let canonical_request = format!(
            "POST\n/\n\ncontent-type:application/json\nhost:{}\n\ncontent-type;host\n{}",
            host, hashed_payload
        );

        // Step 2: StringToSign
        let hashed_canonical = Self::sha256_hex(canonical_request.as_bytes());
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{}\n{}\n{}",
            timestamp, credential_scope, hashed_canonical
        );

        // Step 3: Signing key chain
        let secret_date =
            Self::hmac_sha256(format!("TC3{}", secret_key).as_bytes(), date.as_bytes());
        let secret_service = Self::hmac_sha256(&secret_date, service.as_bytes());
        let secret_signing = Self::hmac_sha256(&secret_service, b"tc3_request");

        // Step 4: Signature
        let signature =
            Self::hex_encode(&Self::hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        format!(
            "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders=content-type;host, Signature={}",
            secret_id, credential_scope, signature
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_tencent(
        &self,
        secret_id: &str,
        secret_key: &str,
        sdk_app_id: &str,
        sign_name: &str,
        template_id: &str,
        template_params: &[String],
        endpoint: &str,
        region: &str,
        alert: &AlertEvent,
        recipients: &[String],
    ) -> Result<()> {
        // Build template params: if user provided custom ones, use them; otherwise use alert message
        let tpl_params = if template_params.is_empty() {
            let msg = Self::format_message(alert);
            vec![msg]
        } else {
            template_params.to_vec()
        };

        // Tencent Cloud supports batch sending (up to 200 numbers)
        let phone_numbers: Vec<String> = recipients
            .iter()
            .map(|p| {
                if p.starts_with('+') {
                    p.clone()
                } else {
                    format!("+86{}", p)
                }
            })
            .collect();

        let payload = serde_json::json!({
            "SmsSdkAppId": sdk_app_id,
            "SignName": sign_name,
            "TemplateId": template_id,
            "TemplateParamSet": tpl_params,
            "PhoneNumberSet": phone_numbers,
        });
        let payload_str = payload.to_string();

        let timestamp = chrono::Utc::now().timestamp();
        let authorization =
            Self::tencent_sign(secret_id, secret_key, "sms", endpoint, &payload_str, timestamp);

        let url = format!("https://{}", endpoint);

        let mut last_err = None;
        for attempt in 0..3u32 {
            match self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Host", endpoint)
                .header("Authorization", &authorization)
                .header("X-TC-Action", "SendSms")
                .header("X-TC-Version", "2021-01-11")
                .header("X-TC-Timestamp", timestamp.to_string())
                .header("X-TC-Region", region)
                .body(payload_str.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(body) => {
                            if body.pointer("/Response/Error").is_none() {
                                last_err = None;
                                break;
                            }
                            let errmsg = body
                                .pointer("/Response/Error/Message")
                                .and_then(|v: &Value| v.as_str())
                                .unwrap_or("unknown");
                            tracing::warn!(attempt = attempt + 1, error = errmsg, "Tencent SMS API error, retrying");
                            last_err = Some(anyhow::anyhow!("Tencent SMS error: {errmsg}"));
                        }
                        Err(e) => {
                            last_err = Some(anyhow::anyhow!("Tencent SMS response parse error: {e}"));
                        }
                    }
                }
                Ok(resp) => {
                    let status = resp.status();
                    tracing::warn!(attempt = attempt + 1, status = %status, "Tencent SMS HTTP error, retrying");
                    last_err = Some(anyhow::anyhow!("HTTP {status}"));
                }
                Err(e) => {
                    tracing::warn!(attempt = attempt + 1, error = %e, "Tencent SMS request failed, retrying");
                    last_err = Some(anyhow::anyhow!("Tencent SMS request error: {e}"));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100 * 2u64.pow(attempt))).await;
        }

        if let Some(e) = last_err {
            tracing::error!(error = %e, "Tencent SMS failed after 3 retries");
        }
        Ok(())
    }
}

// ── NotificationChannel impl ──

#[async_trait]
impl NotificationChannel for SmsChannel {
    async fn send(&self, alert: &AlertEvent, recipients: &[String]) -> Result<SendResponse> {
        // TODO: 完善 SMS 渠道的详细响应记录
        let response = SendResponse::default();

        if recipients.is_empty() {
            return Ok(response);
        }

        match &self.provider {
            SmsProvider::Generic {
                gateway_url,
                api_key,
            } => self.send_generic(gateway_url, api_key, alert, recipients).await,
            SmsProvider::Aliyun {
                access_key_id,
                access_key_secret,
                sign_name,
                template_code,
                template_param,
                endpoint,
            } => {
                self.send_aliyun(
                    access_key_id,
                    access_key_secret,
                    sign_name,
                    template_code,
                    template_param.as_deref(),
                    endpoint,
                    alert,
                    recipients,
                )
                .await
            }
            SmsProvider::Tencent {
                secret_id,
                secret_key,
                sdk_app_id,
                sign_name,
                template_id,
                template_params,
                endpoint,
                region,
            } => {
                self.send_tencent(
                    secret_id,
                    secret_key,
                    sdk_app_id,
                    sign_name,
                    template_id,
                    template_params,
                    endpoint,
                    region,
                    alert,
                    recipients,
                )
                .await
            }
        }?;

        Ok(response)
    }

    fn channel_type(&self) -> &str {
        "sms"
    }

    fn instance_id(&self) -> &str {
        &self.instance_id
    }
}

// ── Plugin ──

pub struct SmsPlugin;

impl SmsPlugin {
    fn get_provider(config: &Value) -> &str {
        config
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("generic")
    }
}

impl ChannelPlugin for SmsPlugin {
    fn name(&self) -> &str {
        "sms"
    }

    fn recipient_type(&self) -> &str {
        "phone"
    }

    fn validate_config(&self, config: &Value) -> Result<()> {
        match Self::get_provider(config) {
            "generic" => {
                serde_json::from_value::<GenericSmsConfig>(config.clone())
                    .map_err(|e| anyhow::anyhow!("Invalid sms(generic) config: {e}"))?;
            }
            "aliyun" => {
                serde_json::from_value::<AliyunSmsConfig>(config.clone())
                    .map_err(|e| anyhow::anyhow!("Invalid sms(aliyun) config: {e}"))?;
            }
            "tencent" => {
                serde_json::from_value::<TencentSmsConfig>(config.clone())
                    .map_err(|e| anyhow::anyhow!("Invalid sms(tencent) config: {e}"))?;
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown sms provider: {other}. Supported: generic, aliyun, tencent"
                ));
            }
        }
        Ok(())
    }

    fn create_channel(
        &self,
        instance_id: &str,
        config: &Value,
    ) -> Result<Box<dyn NotificationChannel>> {
        let provider = match Self::get_provider(config) {
            "generic" => {
                let cfg: GenericSmsConfig = serde_json::from_value(config.clone())
                    .map_err(|e| anyhow::anyhow!("Invalid sms(generic) config: {e}"))?;
                SmsProvider::Generic {
                    gateway_url: cfg.gateway_url,
                    api_key: cfg.api_key,
                }
            }
            "aliyun" => {
                let cfg: AliyunSmsConfig = serde_json::from_value(config.clone())
                    .map_err(|e| anyhow::anyhow!("Invalid sms(aliyun) config: {e}"))?;
                SmsProvider::Aliyun {
                    access_key_id: cfg.access_key_id,
                    access_key_secret: cfg.access_key_secret,
                    sign_name: cfg.sign_name,
                    template_code: cfg.template_code,
                    template_param: cfg.template_param,
                    endpoint: cfg.endpoint,
                }
            }
            "tencent" => {
                let cfg: TencentSmsConfig = serde_json::from_value(config.clone())
                    .map_err(|e| anyhow::anyhow!("Invalid sms(tencent) config: {e}"))?;
                SmsProvider::Tencent {
                    secret_id: cfg.secret_id,
                    secret_key: cfg.secret_key,
                    sdk_app_id: cfg.sdk_app_id,
                    sign_name: cfg.sign_name,
                    template_id: cfg.template_id,
                    template_params: cfg.template_params,
                    endpoint: cfg.endpoint,
                    region: cfg.region,
                }
            }
            other => {
                return Err(anyhow::anyhow!("Unknown sms provider: {other}"));
            }
        };

        Ok(Box::new(SmsChannel {
            instance_id: instance_id.to_string(),
            client: reqwest::Client::new(),
            provider,
        }))
    }

    fn redact_config(&self, config: &Value) -> Value {
        let mut redacted = config.clone();
        if let Some(obj) = redacted.as_object_mut() {
            if obj.contains_key("api_key") {
                obj.insert("api_key".to_string(), Value::String("***".to_string()));
            }
            if obj.contains_key("access_key_secret") {
                obj.insert(
                    "access_key_secret".to_string(),
                    Value::String("***".to_string()),
                );
            }
            if obj.contains_key("secret_key") {
                obj.insert("secret_key".to_string(), Value::String("***".to_string()));
            }
        }
        redacted
    }
}
