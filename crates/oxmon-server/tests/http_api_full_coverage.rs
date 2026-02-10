mod common;

use axum::http::StatusCode;
use common::{
    add_whitelist_agent, assert_err_envelope, assert_ok_envelope, build_test_context, decode_data,
    ensure_cert_domain_with_result, login_and_get_token, make_json_body, request_json,
    request_no_body,
};
use oxmon_storage::StorageEngine;
use serde_json::json;

#[tokio::test]
async fn health_should_return_ok_envelope() {
    let ctx = build_test_context().expect("test context should build");
    let (status, body, trace) = request_no_body(&ctx.app, "GET", "/v1/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert!(body["data"]["version"].is_string());
    assert!(body["trace_id"].as_str().is_some());
    assert!(trace.is_some());
}

#[tokio::test]
async fn auth_login_success_and_failure_cases() {
    let ctx = build_test_context().expect("test context should build");

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"admin","password":"changeme"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert!(body["data"]["token"].is_string());

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"admin","password":"wrong"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_err_envelope(&body, 1002);

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"","password":""})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_err_envelope(&body, 1001);
}

#[tokio::test]
async fn auth_change_password_success_and_revocation() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/password",
        Some(&token),
        Some(json!({
            "current_password":"changeme",
            "new_password":"new-secret"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert!(body["err_msg"]
        .as_str()
        .unwrap_or_default()
        .contains("login"));

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/agents", Some(&token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_err_envelope(&body, 1002);

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"admin","password":"new-secret"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
}

#[tokio::test]
async fn agents_and_latest_should_cover_auth_and_not_found() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/agents", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_err_envelope(&body, 1002);

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/agents", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/agents/non-existent/latest",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);
}

#[tokio::test]
async fn metrics_alerts_and_history_should_return_paginated_data() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let _whitelist_token = add_whitelist_agent(&ctx.app, &token, "agent-metrics-1").await;

    let now = chrono::Utc::now();
    let batch = oxmon_common::types::MetricBatch {
        agent_id: "agent-metrics-1".to_string(),
        timestamp: now,
        data_points: vec![oxmon_common::types::MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now,
            agent_id: "agent-metrics-1".to_string(),
            metric_name: "cpu.usage".to_string(),
            value: 42.0,
            labels: std::collections::HashMap::from([("core".to_string(), "0".to_string())]),
            created_at: now,
            updated_at: now,
        }],
    };
    ctx.state
        .storage
        .write_batch(&batch)
        .expect("write metric batch should succeed");
    ctx.state
        .agent_registry
        .lock()
        .expect("registry lock should succeed")
        .update_agent("agent-metrics-1");

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/metrics?agent_id__eq=agent-metrics-1&metric_name__eq=cpu.usage&limit=10&offset=0",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let rows: Vec<serde_json::Value> = decode_data(&body);
    assert!(!rows.is_empty());
    assert!(rows[0]["labels"].is_object());

    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/alerts/rules", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/alerts/history", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
}

#[tokio::test]
async fn whitelist_endpoints_should_cover_sensitive_field_and_crud_paths() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/agents/whitelist",
        Some(&token),
        Some(make_json_body(&oxmon_common::types::AddAgentRequest {
            agent_id: "agent-wl-1".to_string(),
            description: Some("wl".to_string()),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let id = body["data"]["id"]
        .as_str()
        .expect("id should exist")
        .to_string();

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/agents/whitelist",
        Some(&token),
        Some(json!({"agent_id":"agent-wl-1","description":"dup"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_err_envelope(&body, 1005);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/agents/whitelist?limit=20&offset=0",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let items: Vec<serde_json::Value> = decode_data(&body);
    assert!(!items.is_empty());
    assert!(items[0].get("token").is_some());
    assert!(items[0]["token"].is_null());

    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        &format!("/v1/agents/whitelist/{id}"),
        Some(&token),
        Some(json!({"description":"updated"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "POST",
        &format!("/v1/agents/whitelist/{id}/token"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert!(body["data"]["token"].is_string());

    let (status, body, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/agents/whitelist/{id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/agents/whitelist/{id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);
}

#[tokio::test]
async fn certificate_endpoints_should_cover_query_and_crud_paths() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let (domain_id, cert_id) = ensure_cert_domain_with_result(&ctx, "seed.example.com").await;

    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/certificates", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/certificates/{cert_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/certificates/{cert_id}/chain"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/certs/domains",
        Some(&token),
        Some(json!({"domain":"new.example.com","port":443,"note":"n"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);
    let created_id = body["data"]["id"]
        .as_str()
        .expect("id should exist")
        .to_string();

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/certs/domains/batch",
        Some(&token),
        Some(json!({"domains":[{"domain":"batch1.example.com"},{"domain":"batch2.example.com","port":8443}]})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/certs/domains?enabled__eq=true&domain__contains=example&limit=20&offset=0",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/certs/domains/{created_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        &format!("/v1/certs/domains/{created_id}"),
        Some(&token),
        Some(json!({"enabled":true,"check_interval_secs":3600,"port":443,"note":"u"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/certs/status?limit=20&offset=0",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/certs/status/seed.example.com",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "POST",
        &format!("/v1/certs/domains/{domain_id}/check"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) =
        request_no_body(&ctx.app, "POST", "/v1/certs/check", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/certs/domains/{created_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/certs/domains/{created_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);
}

#[tokio::test]
async fn certificate_list_should_default_to_20_when_pagination_missing() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    for index in 0..25 {
        ensure_cert_domain_with_result(&ctx, &format!("default-limit-{index}.example.com")).await;
    }

    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/certificates", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let rows: Vec<serde_json::Value> = decode_data(&body);
    assert_eq!(rows.len(), 20);
}

#[tokio::test]
async fn openapi_endpoints_should_be_accessible() {
    let ctx = build_test_context().expect("test context should build");

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["paths"].is_object());

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.yaml", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_null() || body.is_object() || body.is_string());
    if let Some(raw) = body.as_str() {
        assert!(raw.contains("openapi:"));
    }
}
