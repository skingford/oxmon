#![allow(dead_code)]

use anyhow::Result;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_alert::rules::threshold::{CompareOp, ThresholdRule};
use oxmon_common::proto::metric_service_server::MetricService;
use oxmon_common::proto::{MetricBatchProto, MetricDataPointProto, ReportResponse};
use oxmon_common::types::{AddAgentRequest, LoginRequest};
use oxmon_notify::manager::NotificationManager;
use oxmon_notify::plugin::ChannelRegistry;
use oxmon_server::app;
use oxmon_server::config::ServerConfig;
use oxmon_server::grpc;
use oxmon_server::state::{AgentRegistry, AppState};
use oxmon_storage::auth::{hash_token, PasswordEncryptor};
use oxmon_storage::engine::SqliteStorageEngine;
use oxmon_storage::CertStore;
use rsa::{Oaep, RsaPublicKey};
use serde::de::DeserializeOwned;
use serde_json::Value;
use rsa::sha2::Sha256;
use std::fmt::Display;
use std::sync::{Arc, Mutex, OnceLock};
use tempfile::TempDir;
use tonic::metadata::MetadataValue;
use tower::util::ServiceExt;

pub struct TestContext {
    pub temp_dir: TempDir,
    pub state: AppState,
    pub app: axum::Router,
}

fn ensure_rustls_provider() {
    static RUSTLS_PROVIDER_INIT: OnceLock<()> = OnceLock::new();
    RUSTLS_PROVIDER_INIT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub fn must_ok<T, E: Display>(result: std::result::Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{context}: {err}"),
    }
}

pub fn must_some<T>(value: Option<T>, context: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{context}"),
    }
}

pub async fn build_test_context() -> Result<TestContext> {
    oxmon_common::id::init(1, 1);
    ensure_rustls_provider();

    let temp_dir = tempfile::tempdir()?;
    let storage = Arc::new(SqliteStorageEngine::new(temp_dir.path())?);
    let data_dir_str = temp_dir.path().to_string_lossy().to_string();
    let mut db_cfg = oxmon_server::config::DatabaseConfig::default();
    db_cfg.data_dir = data_dir_str;
    let db_url = db_cfg.connection_url();
    let cert_store = Arc::new(CertStore::new(&db_url, temp_dir.path()).await?);

    let password_hash = hash_token("changeme")?;
    let _ = cert_store.create_user("admin", &password_hash).await?;

    let rules: Vec<Box<dyn oxmon_alert::AlertRule>> = vec![Box::new(ThresholdRule {
        id: "test-threshold".to_string(),
        name: "Test Threshold".to_string(),
        metric: "cpu.usage".to_string(),
        agent_pattern: "*".to_string(),
        severity: must_ok("warning".parse(), "warning should parse"),
        operator: CompareOp::GreaterThan,
        value: 9999.0,
        duration_secs: 60,
        silence_secs: 0,
    })];
    let alert_engine = Arc::new(Mutex::new(AlertEngine::new(rules)));
    let notifier = Arc::new(NotificationManager::new(
        ChannelRegistry::default(),
        cert_store.clone(),
        0,
    ));
    let agent_registry = Arc::new(Mutex::new(AgentRegistry::new(10)));

    let config = ServerConfig {
        grpc_port: 9090,
        http_port: 8080,
        retention_days: 7,
        require_agent_auth: false,
        agent_collection_interval_secs: 10,
        cors_allowed_origins: Vec::new(),
        rate_limit_enabled: false,
        database: db_cfg,
        cert_check: Default::default(),
        cloud_check: Default::default(),
        ai_check: Default::default(),
        auth: Default::default(),
        app_id: Default::default(),
    };

    let password_encryptor = Arc::new(PasswordEncryptor::load_or_create(temp_dir.path())?);

    let state = AppState {
        storage,
        alert_engine,
        notifier,
        agent_registry,
        cert_store,
        connect_timeout_secs: 1,
        start_time: Utc::now(),
        jwt_secret: Arc::new("test-secret".to_string()),
        token_expire_secs: 3600,
        password_encryptor,
        config: Arc::new(config),
    };

    let app = app::build_http_app(state.clone());

    Ok(TestContext {
        temp_dir,
        state,
        app,
    })
}

pub async fn request_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    builder = builder.header("Content-Type", "application/json");

    let req_body = body.unwrap_or(Value::Null).to_string();
    let req = must_ok(builder.body(Body::from(req_body)), "request should build");

    let resp = must_ok(app.clone().oneshot(req).await, "request should be handled");

    let status = resp.status();
    let trace_id = resp
        .headers()
        .get("x-trace-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let bytes = must_ok(
        to_bytes(resp.into_body(), usize::MAX).await,
        "body should read",
    );
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice::<Value>(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()))
    };

    (status, json, trace_id)
}

pub async fn request_no_body(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }

    let req = must_ok(builder.body(Body::empty()), "request should build");

    let resp = must_ok(app.clone().oneshot(req).await, "request should be handled");
    let status = resp.status();
    let trace_id = resp
        .headers()
        .get("x-trace-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let bytes = must_ok(
        to_bytes(resp.into_body(), usize::MAX).await,
        "body should read",
    );
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice::<Value>(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()))
    };

    (status, json, trace_id)
}

/// 用 RSA-OAEP 公钥加密密码（测试辅助）
pub fn encrypt_password(public_key: &RsaPublicKey, password: &str) -> String {
    let payload = serde_json::json!({
        "password": password,
        "timestamp": Utc::now().timestamp(),
    });
    let padding = Oaep::<Sha256>::new();
    let mut rng = rand::rng();
    let ciphertext = must_ok(
        public_key.encrypt(&mut rng, padding, payload.to_string().as_bytes()),
        "RSA encryption should succeed",
    );
    general_purpose::STANDARD.encode(&ciphertext)
}

/// 从测试上下文中获取公钥加密密码
pub fn encrypt_password_with_state(state: &AppState, password: &str) -> String {
    encrypt_password(&state.password_encryptor.public_key(), password)
}

pub async fn login_and_get_token(app: &axum::Router) -> String {
    // First get the public key
    let (status, pk_body, _) = request_no_body(app, "GET", "/v1/auth/public-key", None).await;
    assert_eq!(status, StatusCode::OK);
    let pem = must_some(
        pk_body["data"]["public_key"].as_str(),
        "public_key should exist",
    );
    let public_key = must_ok(
        rsa::pkcs8::DecodePublicKey::from_public_key_pem(pem),
        "PEM should parse",
    );

    let encrypted = encrypt_password(&public_key, "changeme");

    let (status, body, _) = request_json(
        app,
        "POST",
        "/v1/auth/login",
        None,
        Some(must_ok(
            serde_json::to_value(LoginRequest {
                username: "admin".to_string(),
                encrypted_password: encrypted,
            }),
            "login request should serialize",
        )),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["err_code"], 0);
    must_some(
        body["data"]["access_token"].as_str(),
        "access_token should exist",
    )
    .to_string()
}

pub async fn add_whitelist_agent(app: &axum::Router, token: &str, agent_id: &str) -> String {
    let (status, body, _) = request_json(
        app,
        "POST",
        "/v1/agents/whitelist",
        Some(token),
        Some(must_ok(
            serde_json::to_value(AddAgentRequest {
                agent_id: agent_id.to_string(),
                description: Some("test agent".to_string()),
                collection_interval_secs: None,
            }),
            "add agent request should serialize",
        )),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    must_some(
        body["data"]["token"].as_str(),
        "whitelist token should exist",
    )
    .to_string()
}

pub fn assert_ok_envelope(json: &Value) {
    assert_eq!(json["err_code"], 0);
    assert!(json["err_msg"].is_string());
    assert!(json.get("trace_id").is_some());
}

pub fn assert_err_envelope(json: &Value, err_code: i32) {
    assert_eq!(json["err_code"], err_code);
    assert!(json["err_msg"].is_string());
    assert!(json.get("trace_id").is_some());
    assert!(json.get("data").is_some());
    assert!(json["data"].is_null());
}

pub fn decode_data<T: DeserializeOwned>(json: &Value) -> T {
    must_ok(
        serde_json::from_value(json["data"].clone()),
        "data should decode",
    )
}

pub async fn grpc_report_direct(
    service: &grpc::MetricServiceImpl,
    agent_id: &str,
    token: Option<&str>,
    metadata_agent_id: Option<&str>,
    metric_name: &str,
    value: f64,
) -> Result<tonic::Response<ReportResponse>, tonic::Status> {
    let mut req = tonic::Request::new(MetricBatchProto {
        agent_id: agent_id.to_string(),
        timestamp_ms: Utc::now().timestamp_millis(),
        data_points: vec![MetricDataPointProto {
            timestamp_ms: Utc::now().timestamp_millis(),
            agent_id: agent_id.to_string(),
            metric_name: metric_name.to_string(),
            value,
            labels: std::collections::HashMap::from([("k".to_string(), "v".to_string())]),
        }],
    });

    if let Some(token) = token {
        let value = must_ok(
            format!("Bearer {token}").parse::<MetadataValue<_>>(),
            "authorization metadata should parse",
        );
        req.metadata_mut().insert("authorization", value);
    }

    if let Some(meta_agent_id) = metadata_agent_id {
        let value = must_ok(
            meta_agent_id.parse::<MetadataValue<_>>(),
            "agent-id metadata should parse",
        );
        req.metadata_mut().insert("agent-id", value);
    }

    MetricService::report_metrics(service, req).await
}

pub fn sample_cert_check_result(
    domain_id: &str,
    domain: &str,
) -> oxmon_common::types::CertCheckResult {
    let now = Utc::now();
    oxmon_common::types::CertCheckResult {
        id: oxmon_common::id::next_id(),
        domain_id: domain_id.to_string(),
        domain: domain.to_string(),
        is_valid: true,
        chain_valid: true,
        not_before: Some(now - chrono::Duration::days(1)),
        not_after: Some(now + chrono::Duration::days(30)),
        days_until_expiry: Some(30),
        issuer: Some("CN=Test Issuer".to_string()),
        subject: Some("CN=Test Subject".to_string()),
        san_list: Some(vec![domain.to_string()]),
        resolved_ips: Some(vec!["127.0.0.1".to_string()]),
        error: None,
        checked_at: now,
        created_at: now,
        updated_at: now,
    }
}

pub async fn ensure_cert_domain_with_result(ctx: &TestContext, domain: &str) -> (String, String) {
    let created = must_ok(
        ctx.state
            .cert_store
            .insert_domain(&oxmon_common::types::CreateDomainRequest {
                domain: domain.to_string(),
                port: Some(443),
                check_interval_secs: Some(3600),
                note: Some("seed".to_string()),
            })
            .await,
        "insert domain should succeed",
    );

    let result = sample_cert_check_result(&created.id, domain);
    let _ = must_ok(
        ctx.state.cert_store.insert_check_result(&result).await,
        "insert check result should succeed",
    );

    let details = oxmon_common::types::CertificateDetails {
        id: oxmon_common::id::next_id(),
        domain: domain.to_string(),
        not_before: Utc::now() - chrono::Duration::days(10),
        not_after: Utc::now() + chrono::Duration::days(20),
        ip_addresses: vec!["127.0.0.1".to_string()],
        issuer_cn: Some("Test CA".to_string()),
        issuer_o: Some("Test Org".to_string()),
        issuer_ou: None,
        issuer_c: None,
        subject_alt_names: vec![domain.to_string()],
        chain_valid: true,
        chain_error: None,
        last_checked: Utc::now(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        serial_number: None,
        fingerprint_sha256: None,
        version: None,
        signature_algorithm: None,
        public_key_algorithm: None,
        public_key_bits: None,
        subject_cn: None,
        subject_o: None,
        key_usage: None,
        extended_key_usage: None,
        is_ca: None,
        is_wildcard: None,
        ocsp_urls: None,
        crl_urls: None,
        ca_issuer_urls: None,
        sct_count: None,
        tls_version: None,
        cipher_suite: None,
        chain_depth: None,
    };
    let _ = must_ok(
        ctx.state
            .cert_store
            .upsert_certificate_details(&details)
            .await,
        "upsert cert details should succeed",
    );

    let details = must_some(
        must_ok(
            ctx.state.cert_store.get_certificate_details(domain).await,
            "query cert details should succeed",
        ),
        "cert details should exist",
    );

    (created.id, details.id)
}

pub fn make_json_body<T: serde::Serialize>(v: &T) -> Value {
    must_ok(serde_json::to_value(v), "json encode should succeed")
}
