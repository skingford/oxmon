#![allow(dead_code)]

use anyhow::Result;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_alert::rules::threshold::{CompareOp, ThresholdRule};
use oxmon_common::proto::metric_service_server::MetricService;
use oxmon_common::proto::{MetricBatchProto, MetricDataPointProto, ReportResponse};
use oxmon_common::types::{AddAgentRequest, LoginRequest};
use oxmon_notify::manager::NotificationManager;
use oxmon_server::app;
use oxmon_server::config::ServerConfig;
use oxmon_server::grpc;
use oxmon_server::state::{AgentRegistry, AppState};
use oxmon_storage::auth::hash_token;
use oxmon_storage::cert_store::CertStore;
use oxmon_storage::engine::SqliteStorageEngine;
use serde::de::DeserializeOwned;
use serde_json::Value;
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

pub fn build_test_context() -> Result<TestContext> {
    oxmon_common::id::init(1, 1);
    ensure_rustls_provider();

    let temp_dir = tempfile::tempdir()?;
    let storage = Arc::new(SqliteStorageEngine::new(temp_dir.path())?);
    let cert_store = Arc::new(CertStore::new(temp_dir.path())?);

    let password_hash = hash_token("changeme")?;
    let _ = cert_store.create_user("admin", &password_hash)?;

    let rules: Vec<Box<dyn oxmon_alert::AlertRule>> = vec![Box::new(ThresholdRule {
        id: "test-threshold".to_string(),
        metric: "cpu.usage".to_string(),
        agent_pattern: "*".to_string(),
        severity: "warning".parse().expect("warning should parse"),
        operator: CompareOp::GreaterThan,
        value: 9999.0,
        duration_secs: 60,
        silence_secs: 0,
    })];
    let alert_engine = Arc::new(Mutex::new(AlertEngine::new(rules)));
    let notifier = Arc::new(NotificationManager::new(vec![], vec![], vec![], 0));
    let agent_registry = Arc::new(Mutex::new(AgentRegistry::new(10)));

    let config = ServerConfig {
        grpc_port: 9090,
        http_port: 8080,
        data_dir: temp_dir.path().to_string_lossy().to_string(),
        retention_days: 7,
        require_agent_auth: false,
        alert: Default::default(),
        notification: Default::default(),
        cert_check: Default::default(),
        auth: Default::default(),
    };

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
    let req = builder
        .body(Body::from(req_body))
        .expect("request should build");

    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("request should be handled");

    let status = resp.status();
    let trace_id = resp
        .headers()
        .get("x-trace-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body should read");
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

    let req = builder.body(Body::empty()).expect("request should build");

    let resp = app
        .clone()
        .oneshot(req)
        .await
        .expect("request should be handled");
    let status = resp.status();
    let trace_id = resp
        .headers()
        .get("x-trace-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body should read");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice::<Value>(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()))
    };

    (status, json, trace_id)
}

pub async fn login_and_get_token(app: &axum::Router) -> String {
    let (status, body, _) = request_json(
        app,
        "POST",
        "/v1/auth/login",
        None,
        Some(
            serde_json::to_value(LoginRequest {
                username: "admin".to_string(),
                password: "changeme".to_string(),
            })
            .expect("login request should serialize"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["err_code"], 0);
    body["data"]["token"]
        .as_str()
        .expect("token should exist")
        .to_string()
}

pub async fn add_whitelist_agent(app: &axum::Router, token: &str, agent_id: &str) -> String {
    let (status, body, _) = request_json(
        app,
        "POST",
        "/v1/agents/whitelist",
        Some(token),
        Some(
            serde_json::to_value(AddAgentRequest {
                agent_id: agent_id.to_string(),
                description: Some("test agent".to_string()),
            })
            .expect("add agent request should serialize"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    body["data"]["token"]
        .as_str()
        .expect("whitelist token should exist")
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
    serde_json::from_value(json["data"].clone()).expect("data should decode")
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
        let value = format!("Bearer {token}")
            .parse::<MetadataValue<_>>()
            .expect("authorization metadata should parse");
        req.metadata_mut().insert("authorization", value);
    }

    if let Some(meta_agent_id) = metadata_agent_id {
        let value = meta_agent_id
            .parse::<MetadataValue<_>>()
            .expect("agent-id metadata should parse");
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
    let created = ctx
        .state
        .cert_store
        .insert_domain(&oxmon_common::types::CreateDomainRequest {
            domain: domain.to_string(),
            port: Some(443),
            check_interval_secs: Some(3600),
            note: Some("seed".to_string()),
        })
        .expect("insert domain should succeed");

    let result = sample_cert_check_result(&created.id, domain);
    ctx.state
        .cert_store
        .insert_check_result(&result)
        .expect("insert check result should succeed");

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
    };
    ctx.state
        .cert_store
        .upsert_certificate_details(&details)
        .expect("upsert cert details should succeed");

    let details = ctx
        .state
        .cert_store
        .get_certificate_details(domain)
        .expect("query cert details should succeed")
        .expect("cert details should exist");

    (created.id, details.id)
}

pub fn make_json_body<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("json encode should succeed")
}
