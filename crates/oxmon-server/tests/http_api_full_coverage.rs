mod common;

use axum::http::StatusCode;
use common::{
    add_whitelist_agent, assert_err_envelope, assert_ok_envelope, build_test_context,
    encrypt_password_with_state, ensure_cert_domain_with_result, login_and_get_token,
    make_json_body, request_json, request_no_body,
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

    // Success case
    let encrypted = encrypt_password_with_state(&ctx.state, "changeme");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"admin","encrypted_password": encrypted})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert!(body["data"]["access_token"].is_string());

    // Wrong password
    let encrypted_wrong = encrypt_password_with_state(&ctx.state, "wrong");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_err_envelope(&body, 1002);

    // Empty fields
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"","encrypted_password":""})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_err_envelope(&body, 1001);
}

#[tokio::test]
async fn auth_change_password_success_and_revocation() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let encrypted_current = encrypt_password_with_state(&ctx.state, "changeme");
    let encrypted_new = encrypt_password_with_state(&ctx.state, "new-secret");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/password",
        Some(&token),
        Some(json!({
            "encrypted_current_password": encrypted_current,
            "encrypted_new_password": encrypted_new
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

    let encrypted_new_login = encrypt_password_with_state(&ctx.state, "new-secret");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"admin","encrypted_password": encrypted_new_login})),
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
    let items = body["data"]["items"].as_array().expect("data.items should be array");
    assert!(!items.is_empty());
    assert!(items[0]["labels"].is_object());

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
            collection_interval_secs: None,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
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
    let items = body["data"]["items"].as_array().expect("data.items should be array");
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
    let items = body["data"]["items"].as_array().expect("items should be array");
    assert_eq!(items.len(), 20);
}

#[tokio::test]
async fn dictionary_endpoints_should_cover_crud_paths() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    // List types (initially empty)
    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/dictionaries/types", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let types = body["data"]["items"].as_array().expect("items should be array");
    assert!(types.is_empty());

    // Create a dictionary item
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/dictionaries",
        Some(&token),
        Some(json!({
            "dict_type": "channel_type",
            "dict_key": "email",
            "dict_label": "邮件",
            "description": "邮件通知"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);
    let item_id = body["data"]["id"]
        .as_str()
        .expect("id should exist")
        .to_string();
    // 注意：创建操作现在只返回ID，完整数据需要通过GET获取

    // Create second item of same type
    let (status, _, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/dictionaries",
        Some(&token),
        Some(json!({
            "dict_type": "channel_type",
            "dict_key": "webhook",
            "dict_label": "Webhook",
            "sort_order": 2
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Create duplicate should fail
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/dictionaries",
        Some(&token),
        Some(json!({
            "dict_type": "channel_type",
            "dict_key": "email",
            "dict_label": "重复"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_err_envelope(&body, 1005);

    // Get by id
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/dictionaries/{item_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["dict_key"], "email");

    // Get non-existent
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/dictionaries/nonexistent",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);

    // List by type
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/dictionaries/type/channel_type",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let items = body["data"]["items"].as_array().expect("items should be array");
    assert_eq!(items.len(), 2);

    // List types again (should have 1 type, with auto-created dict_type_label)
    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/dictionaries/types", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let types = body["data"]["items"].as_array().expect("items should be array");
    assert_eq!(types.len(), 1);
    assert_eq!(types[0]["dict_type"], "channel_type");
    assert_eq!(types[0]["dict_type_label"], "channel_type"); // auto-ensured, label defaults to dict_type
    assert_eq!(types[0]["count"], 2);

    // Update
    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        &format!("/v1/dictionaries/{item_id}"),
        Some(&token),
        Some(json!({
            "dict_label": "电子邮件",
            "enabled": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    // 注意：更新操作现在只返回ID，完整数据需要通过GET获取

    // Update non-existent
    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        "/v1/dictionaries/nonexistent",
        Some(&token),
        Some(json!({"dict_label": "test"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);

    // Delete
    let (status, _, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/dictionaries/{item_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Delete again should 404
    let (status, body, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/dictionaries/{item_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);

    // Auth required
    let (status, _, _) = request_no_body(&ctx.app, "GET", "/v1/dictionaries/types", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // ---- Dictionary types CRUD ----

    // Create a dictionary type
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/dictionaries/types",
        Some(&token),
        Some(json!({
            "dict_type": "severity",
            "dict_type_label": "告警级别",
            "sort_order": 1,
            "description": "告警严重程度级别"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);
    // 注意：创建操作现在只返回ID (此处为dict_type)，完整数据需要通过GET获取

    // Create duplicate should fail
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/dictionaries/types",
        Some(&token),
        Some(json!({
            "dict_type": "severity",
            "dict_type_label": "重复"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_err_envelope(&body, 1005);

    // Update dictionary type
    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        "/v1/dictionaries/types/severity",
        Some(&token),
        Some(json!({
            "dict_type_label": "严重程度",
            "sort_order": 2
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    // 注意：更新操作现在只返回ID，完整数据需要通过GET获取

    // Update non-existent dictionary type
    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        "/v1/dictionaries/types/nonexistent",
        Some(&token),
        Some(json!({"dict_type_label": "test"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);

    // Delete dictionary type
    let (status, _, _) = request_no_body(
        &ctx.app,
        "DELETE",
        "/v1/dictionaries/types/severity",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Delete again should 404
    let (status, body, _) = request_no_body(
        &ctx.app,
        "DELETE",
        "/v1/dictionaries/types/severity",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);
}

#[tokio::test]
async fn system_config_endpoints_should_cover_crud_paths() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    // List (initially empty)
    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/system/configs", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let items = body["data"]["items"].as_array().expect("items should be array");
    assert!(items.is_empty());

    // Create a runtime system config
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/system/configs",
        Some(&token),
        Some(json!({
            "config_key": "test_runtime_setting",
            "config_type": "runtime",
            "display_name": "测试运行时参数",
            "description": "用于测试的运行时参数",
            "config_json": "{\"value\":120}"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);
    let config_id = body["data"]["id"]
        .as_str()
        .expect("id should exist")
        .to_string();
    // 注意：创建操作现在只返回ID，完整数据需要通过GET获取

    // Create duplicate config_key should fail
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/system/configs",
        Some(&token),
        Some(json!({
            "config_key": "test_runtime_setting",
            "config_type": "runtime",
            "display_name": "重复",
            "config_json": "{\"value\":200}"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_err_envelope(&body, 1005);

    // Create with invalid JSON should fail
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/system/configs",
        Some(&token),
        Some(json!({
            "config_key": "bad_json",
            "config_type": "runtime",
            "display_name": "Bad",
            "config_json": "not-json"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_err_envelope(&body, 1001);

    // Create email config (non-runtime) should fail
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/system/configs",
        Some(&token),
        Some(json!({
            "config_key": "email_rejected",
            "config_type": "email",
            "display_name": "Should Fail",
            "config_json": "{\"smtp_host\":\"smtp.example.com\"}"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_err_envelope(&body, 1001);

    // Get by id
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/system/configs/{config_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["config_key"], "test_runtime_setting");
    assert_eq!(body["data"]["config_json"]["value"], 120);

    // Get non-existent
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/system/configs/nonexistent",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);

    // Update
    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        &format!("/v1/system/configs/{config_id}"),
        Some(&token),
        Some(json!({
            "display_name": "更新后的运行时参数",
            "enabled": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    // 注意：更新操作现在只返回ID，完整数据需要通过GET获取

    // Update non-existent
    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        "/v1/system/configs/nonexistent",
        Some(&token),
        Some(json!({"display_name": "test"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);

    // Create another runtime config
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/system/configs",
        Some(&token),
        Some(json!({
            "config_key": "another_runtime",
            "config_type": "runtime",
            "display_name": "另一个运行时参数",
            "config_json": "{\"value\":999}"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);
    let sms_id = body["data"]["id"]
        .as_str()
        .expect("id should exist")
        .to_string();
    // 注意：创建操作现在只返回ID，完整数据需要通过GET获取

    // Delete
    let (status, _, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/system/configs/{config_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Delete again should 404
    let (status, body, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/system/configs/{config_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);

    // Delete SMS config too
    let (status, _, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/system/configs/{sms_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Auth required
    let (status, _, _) = request_no_body(&ctx.app, "GET", "/v1/system/configs", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn notification_log_endpoints_should_support_query_and_summary() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    // Empty result
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/notifications/logs?limit=10&offset=0",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["total"], 0);
    let items: Vec<serde_json::Value> =
        serde_json::from_value(body["data"]["items"].clone()).unwrap();
    assert!(items.is_empty());

    // Insert test logs directly via cert_store
    let now = chrono::Utc::now();
    let log1 = oxmon_storage::cert_store::NotificationLogRow {
        id: oxmon_common::id::next_id(),
        alert_event_id: "evt-1".to_string(),
        rule_id: "rule-1".to_string(),
        rule_name: "Test Rule".to_string(),
        agent_id: "agent-1".to_string(),
        channel_id: "ch-1".to_string(),
        channel_name: "Email Channel".to_string(),
        channel_type: "email".to_string(),
        status: "success".to_string(),
        error_message: None,
        duration_ms: 120,
        recipient_count: 2,
        severity: "warning".to_string(),
        created_at: now,
        http_status_code: None,
        response_body: None,
        request_body: None,
        retry_count: 0,
        recipient_details: None,
        api_message_id: None,
        api_error_code: None,
    };
    ctx.state.cert_store.insert_notification_log(&log1).unwrap();

    let log2 = oxmon_storage::cert_store::NotificationLogRow {
        id: oxmon_common::id::next_id(),
        alert_event_id: "evt-2".to_string(),
        rule_id: "rule-1".to_string(),
        rule_name: "Test Rule".to_string(),
        agent_id: "agent-1".to_string(),
        channel_id: "ch-2".to_string(),
        channel_name: "Webhook Channel".to_string(),
        channel_type: "webhook".to_string(),
        status: "failed".to_string(),
        error_message: Some("connection timeout".to_string()),
        duration_ms: 5000,
        recipient_count: 1,
        severity: "critical".to_string(),
        created_at: now,
        http_status_code: Some(500),
        response_body: Some("Internal Server Error".to_string()),
        request_body: Some("{\"test\":\"data\"}".to_string()),
        retry_count: 2,
        recipient_details: Some(
            "[{\"recipient\":\"https://example.com\",\"status\":\"failed\"}]".to_string(),
        ),
        api_message_id: None,
        api_error_code: None,
    };
    ctx.state.cert_store.insert_notification_log(&log2).unwrap();

    // Query all
    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/notifications/logs", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["total"], 2);

    // Filter by channel_type
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/notifications/logs?channel_type=email",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], 1);
    let items: Vec<serde_json::Value> =
        serde_json::from_value(body["data"]["items"].clone()).unwrap();
    assert_eq!(items[0]["channel_type"], "email");

    // Filter by status
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/notifications/logs?status=failed",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], 1);
    let items: Vec<serde_json::Value> =
        serde_json::from_value(body["data"]["items"].clone()).unwrap();
    assert_eq!(items[0]["status"], "failed");
    assert_eq!(items[0]["error_message"], "connection timeout");

    // Filter by channel_id
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/notifications/logs?channel_id=ch-1",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], 1);

    // Filter by time range
    let ts = now.timestamp();
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!(
            "/v1/notifications/logs?start_time={}&end_time={}",
            ts - 60,
            ts + 60
        ),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], 2);

    // Summary
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/notifications/logs/summary",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["total"], 2);
    assert_eq!(body["data"]["success"], 1);
    assert_eq!(body["data"]["failed"], 1);

    // Summary filtered by channel_type
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/notifications/logs/summary?channel_type=email",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["total"], 1);
    assert_eq!(body["data"]["success"], 1);
    assert_eq!(body["data"]["failed"], 0);

    // Auth required
    let (status, _, _) = request_no_body(&ctx.app, "GET", "/v1/notifications/logs", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn notification_channel_config_get_by_id_should_work() {
    let ctx = build_test_context().expect("test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let now = chrono::Utc::now();
    let row = oxmon_storage::cert_store::NotificationChannelRow {
        id: oxmon_common::id::next_id(),
        name: "Email Channel".to_string(),
        channel_type: "email".to_string(),
        description: Some("for get-by-id test".to_string()),
        min_severity: "warning".to_string(),
        enabled: true,
        config_json: "{\"smtp_host\":\"smtp.example.com\"}".to_string(),
        created_at: now,
        updated_at: now,
    };
    let inserted = ctx
        .state
        .cert_store
        .insert_notification_channel(&row)
        .expect("insert notification channel should succeed");

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/notifications/channels/{}", inserted.id),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["id"], inserted.id);
    assert_eq!(body["data"]["name"], "Email Channel");
    assert_eq!(body["data"]["channel_type"], "email");
    assert!(body["data"]["recipients"].is_array());

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/notifications/channels/nonexistent",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_err_envelope(&body, 1004);

    // Phase 3: 使用合并后的端点 /v1/notifications/channels/{id}
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/notifications/channels/{}", inserted.id),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["id"], inserted.id);
    assert_eq!(body["data"]["name"], "Email Channel");
    assert_eq!(body["data"]["channel_type"], "email");
    assert_eq!(body["data"]["min_severity"], "warning");
    // 验证返回包含收件人和配置信息
    assert!(body["data"]["recipients"].is_array());
    assert!(body["data"]["config_json"].is_string());
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
