mod common;

use axum::http::StatusCode;
use common::{
    add_whitelist_agent, assert_err_envelope, assert_ok_envelope, build_test_context,
    encrypt_password_with_state, ensure_cert_domain_with_result, login_and_get_token,
    make_json_body, must_ok, must_some, request_json, request_json_with_headers, request_no_body,
};
use oxmon_storage::{AuditLogFilter, StorageEngine};
use serde_json::json;

#[tokio::test]
async fn health_should_return_ok_envelope() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let (status, body, trace) = request_no_body(&ctx.app, "GET", "/v1/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert!(body["data"]["version"].is_string());
    assert!(body["trace_id"].as_str().is_some());
    assert!(trace.is_some());
}

#[tokio::test]
async fn auth_login_success_and_failure_cases() {
    let ctx = must_ok(build_test_context().await, "test context should build");

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

    let logs = must_ok(
        ctx.state
            .cert_store
            .list_audit_logs(&AuditLogFilter::default(), 20, 0)
            .await,
        "audit logs should query",
    );
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].action, "LOGIN");
    assert_eq!(logs[0].resource_type, "auth");
    assert_eq!(logs[0].path, "/v1/auth/login");
    assert_eq!(logs[0].status_code, 200);
    assert_eq!(logs[0].username, "admin");
    assert!(logs[0]
        .request_body
        .as_deref()
        .unwrap_or("")
        .contains("\"encrypted_password\":\"***\""));

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

    let disabled_hash = must_ok(
        oxmon_storage::auth::hash_token("disabled-secret"),
        "disabled password hash should generate",
    );
    let _ = must_ok(
        ctx.state
            .cert_store
            .create_user(
                "disabled_admin",
                &disabled_hash,
                Some("disabled"),
                None,
                None,
                None,
            )
            .await,
        "disabled admin should create",
    );
    let disabled_password = encrypt_password_with_state(&ctx.state, "disabled-secret");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"disabled_admin","encrypted_password": disabled_password})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_err_envelope(&body, 1002);

    let logs = must_ok(
        ctx.state
            .cert_store
            .list_audit_logs(&AuditLogFilter::default(), 20, 0)
            .await,
        "login audit logs should query",
    );
    assert_eq!(logs.len(), 4);
    assert_eq!(logs.iter().filter(|log| log.action == "LOGIN").count(), 1);
    assert_eq!(
        logs.iter()
            .filter(|log| log.action == "LOGIN_FAILED")
            .count(),
        3
    );
    assert!(logs.iter().any(|log| {
        log.action == "LOGIN_FAILED"
            && log
                .request_body
                .as_deref()
                .unwrap_or("")
                .contains("\"failure_reason\":\"user_disabled\"")
    }));
    assert!(logs.iter().any(|log| {
        log.action == "LOGIN_FAILED"
            && log
                .request_body
                .as_deref()
                .unwrap_or("")
                .contains("\"failure_reason\":\"missing_credentials\"")
    }));
    assert!(logs.iter().any(|log| {
        log.action == "LOGIN_FAILED"
            && log
                .request_body
                .as_deref()
                .unwrap_or("")
                .contains("\"failure_reason\":\"invalid_credentials\"")
            && log
                .request_body
                .as_deref()
                .unwrap_or("")
                .contains("\"encrypted_password\":\"***\"")
    }));
}

#[tokio::test]
async fn auth_change_password_success_and_revocation() {
    let ctx = must_ok(build_test_context().await, "test context should build");
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
    let err_msg = match body["err_msg"].as_str() {
        Some(msg) => msg,
        None => "",
    };
    assert!(err_msg.contains("login"));

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
    let ctx = must_ok(build_test_context().await, "test context should build");
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
    let ctx = must_ok(build_test_context().await, "test context should build");
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
    must_ok(
        ctx.state.storage.write_batch(&batch).await,
        "write metric batch should succeed",
    );
    must_ok(
        ctx.state.agent_registry.lock(),
        "registry lock should succeed",
    )
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
    let items = must_some(
        body["data"]["items"].as_array(),
        "data.items should be array",
    );
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
    let ctx = must_ok(build_test_context().await, "test context should build");
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
    let id = must_some(body["data"]["id"].as_str(), "id should exist").to_string();

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
    let items = must_some(
        body["data"]["items"].as_array(),
        "data.items should be array",
    );
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
    let ctx = must_ok(build_test_context().await, "test context should build");
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
    let created_id = must_some(body["data"]["id"].as_str(), "id should exist").to_string();

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

    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/certs/domains/summary", Some(&token)).await;
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
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    for index in 0..25 {
        ensure_cert_domain_with_result(&ctx, &format!("default-limit-{index}.example.com")).await;
    }

    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/certificates", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let items = must_some(body["data"]["items"].as_array(), "items should be array");
    assert_eq!(items.len(), 20);
}

#[tokio::test]
async fn dictionary_endpoints_should_cover_crud_paths() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    // List types (initially empty)
    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/dictionaries/types", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let types = must_some(body["data"]["items"].as_array(), "items should be array");
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
    let item_id = must_some(body["data"]["id"].as_str(), "id should exist").to_string();
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
    let items = must_some(body["data"]["items"].as_array(), "items should be array");
    assert_eq!(items.len(), 2);

    // List types again (should have 1 type, with auto-created dict_type_label)
    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/dictionaries/types", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    let types = must_some(body["data"]["items"].as_array(), "items should be array");
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
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    // List (initially empty)
    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/system/configs", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let items = must_some(body["data"]["items"].as_array(), "items should be array");
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
    let config_id = must_some(body["data"]["id"].as_str(), "id should exist").to_string();
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
    let sms_id = must_some(body["data"]["id"].as_str(), "id should exist").to_string();
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
    let ctx = must_ok(build_test_context().await, "test context should build");
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
    let items: Vec<serde_json::Value> = must_ok(
        serde_json::from_value(body["data"]["items"].clone()),
        "items should decode",
    );
    assert!(items.is_empty());

    // Insert test logs directly via cert_store
    let now = chrono::Utc::now();
    let log1 = oxmon_storage::NotificationLogRow {
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
    must_ok(
        ctx.state.cert_store.insert_notification_log(&log1).await,
        "insert notification log1 should succeed",
    );

    let log2 = oxmon_storage::NotificationLogRow {
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
    must_ok(
        ctx.state.cert_store.insert_notification_log(&log2).await,
        "insert notification log2 should succeed",
    );

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
    let items: Vec<serde_json::Value> = must_ok(
        serde_json::from_value(body["data"]["items"].clone()),
        "items should decode",
    );
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
    let items: Vec<serde_json::Value> = must_ok(
        serde_json::from_value(body["data"]["items"].clone()),
        "items should decode",
    );
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
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let now = chrono::Utc::now();
    let row = oxmon_storage::NotificationChannelRow {
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
    let inserted = must_ok(
        ctx.state.cert_store.insert_notification_channel(&row).await,
        "insert notification channel should succeed",
    );

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
async fn cloud_account_create_and_get_should_normalize_regions_and_default_interval() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/cloud/accounts",
        Some(&token),
        Some(json!({
            "config_key": "cloud_tencent_prod",
            "provider": "tencent",
            "display_name": "Tencent Prod",
            "config": {
                "secret_id": "sid",
                "secret_key": "skey",
                "default_region": "ap-guangzhou"
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);
    let id = must_some(body["data"]["id"].as_str(), "id should exist").to_string();
    assert_eq!(body["data"]["config"]["regions"], json!(["ap-guangzhou"]));
    assert_eq!(
        body["data"]["config"]["default_region"],
        serde_json::Value::Null
    );
    assert_eq!(body["data"]["config"]["collection_interval_secs"], 3600);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/cloud/accounts/{id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["config"]["regions"], json!(["ap-guangzhou"]));
    assert_eq!(
        body["data"]["config"]["default_region"],
        serde_json::Value::Null
    );
    assert_eq!(body["data"]["config"]["collection_interval_secs"], 3600);
}

#[tokio::test]
async fn cloud_instances_chart_should_filter_by_normalized_status() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let now_ts = chrono::Utc::now().timestamp();
    must_ok(
        ctx.state
            .cert_store
            .upsert_cloud_instance(&oxmon_storage::CloudInstanceRow {
                id: String::new(),
                instance_id: "ins-chart-running".to_string(),
                instance_name: Some("chart-running".to_string()),
                provider: "tencent".to_string(),
                account_config_key: "cloud_tencent_chart_filter".to_string(),
                region: "ap-guangzhou".to_string(),
                public_ip: None,
                private_ip: None,
                os: None,
                status: Some("RUNNING".to_string()),
                last_seen_at: now_ts,
                created_at: now_ts,
                updated_at: now_ts,
                instance_type: None,
                cpu_cores: None,
                memory_gb: None,
                disk_gb: None,
                created_time: None,
                expired_time: None,
                charge_type: None,
                vpc_id: None,
                subnet_id: None,
                security_group_ids: None,
                zone: None,
                internet_max_bandwidth: None,
                ipv6_addresses: None,
                eip_allocation_id: None,
                internet_charge_type: None,
                image_id: None,
                hostname: None,
                description: None,
                gpu: None,
                io_optimized: None,
                latest_operation: None,
                latest_operation_state: None,
                tags: None,
                project_id: None,
                resource_group_id: None,
                auto_renew_flag: None,
            })
            .await,
        "upsert running cloud instance should succeed",
    );
    must_ok(
        ctx.state
            .cert_store
            .upsert_cloud_instance(&oxmon_storage::CloudInstanceRow {
                id: String::new(),
                instance_id: "ins-chart-stopped".to_string(),
                instance_name: Some("chart-stopped".to_string()),
                provider: "alibaba".to_string(),
                account_config_key: "cloud_alibaba_chart_filter".to_string(),
                region: "cn-hangzhou".to_string(),
                public_ip: None,
                private_ip: None,
                os: None,
                status: Some("Stopped".to_string()),
                last_seen_at: now_ts,
                created_at: now_ts,
                updated_at: now_ts,
                instance_type: None,
                cpu_cores: None,
                memory_gb: None,
                disk_gb: None,
                created_time: None,
                expired_time: None,
                charge_type: None,
                vpc_id: None,
                subnet_id: None,
                security_group_ids: None,
                zone: None,
                internet_max_bandwidth: None,
                ipv6_addresses: None,
                eip_allocation_id: None,
                internet_charge_type: None,
                image_id: None,
                hostname: None,
                description: None,
                gpu: None,
                io_optimized: None,
                latest_operation: None,
                latest_operation_state: None,
                tags: None,
                project_id: None,
                resource_group_id: None,
                auto_renew_flag: None,
            })
            .await,
        "upsert stopped cloud instance should succeed",
    );

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/cloud/instances/chart?status=running",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["labels"].as_array().map_or(0, |v| v.len()), 1);
    assert_eq!(
        body["data"]["instances"][0]["normalized_status"],
        serde_json::Value::String("running".to_string())
    );

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/cloud/instances/chart?status=stopped",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["labels"].as_array().map_or(0, |v| v.len()), 1);
    assert_eq!(
        body["data"]["instances"][0]["normalized_status"],
        serde_json::Value::String("stopped".to_string())
    );
}

#[tokio::test]
async fn dashboard_overview_should_include_cloud_resource_summary() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let now = chrono::Utc::now();
    must_ok(
        ctx.state
            .cert_store
            .insert_system_config(&oxmon_storage::SystemConfigRow {
                id: oxmon_common::id::next_id(),
                config_key: "cloud_tencent_dashboard".to_string(),
                config_type: "cloud_account".to_string(),
                provider: Some("tencent".to_string()),
                display_name: "Cloud Dashboard".to_string(),
                description: None,
                config_json:
                    r#"{"secret_id":"sid","secret_key":"skey","regions":["ap-guangzhou"]}"#
                        .to_string(),
                enabled: true,
                created_at: now,
                updated_at: now,
            })
            .await,
        "insert cloud account should succeed",
    );

    let now_ts = now.timestamp();
    must_ok(
        ctx.state
            .cert_store
            .upsert_cloud_instance(&oxmon_storage::CloudInstanceRow {
                id: String::new(),
                instance_id: "ins-dashboard-1".to_string(),
                instance_name: Some("Dashboard-1".to_string()),
                provider: "tencent".to_string(),
                account_config_key: "cloud_tencent_dashboard".to_string(),
                region: "ap-guangzhou".to_string(),
                public_ip: None,
                private_ip: None,
                os: None,
                status: Some("RUNNING".to_string()),
                last_seen_at: now_ts,
                created_at: now_ts,
                updated_at: now_ts,
                instance_type: None,
                cpu_cores: None,
                memory_gb: None,
                disk_gb: None,
                created_time: None,
                expired_time: None,
                charge_type: None,
                vpc_id: None,
                subnet_id: None,
                security_group_ids: None,
                zone: None,
                internet_max_bandwidth: None,
                ipv6_addresses: None,
                eip_allocation_id: None,
                internet_charge_type: None,
                image_id: None,
                hostname: None,
                description: None,
                gpu: None,
                io_optimized: None,
                latest_operation: None,
                latest_operation_state: None,
                tags: None,
                project_id: None,
                resource_group_id: None,
                auto_renew_flag: None,
            })
            .await,
        "upsert cloud instance should succeed",
    );
    must_ok(
        ctx.state
            .cert_store
            .upsert_cloud_instance(&oxmon_storage::CloudInstanceRow {
                id: String::new(),
                instance_id: "ins-dashboard-2".to_string(),
                instance_name: Some("Dashboard-2".to_string()),
                provider: "tencent".to_string(),
                account_config_key: "cloud_tencent_dashboard".to_string(),
                region: "ap-shanghai".to_string(),
                public_ip: None,
                private_ip: None,
                os: None,
                status: Some("STOPPED".to_string()),
                last_seen_at: now_ts,
                created_at: now_ts,
                updated_at: now_ts,
                instance_type: None,
                cpu_cores: None,
                memory_gb: None,
                disk_gb: None,
                created_time: None,
                expired_time: None,
                charge_type: None,
                vpc_id: None,
                subnet_id: None,
                security_group_ids: None,
                zone: None,
                internet_max_bandwidth: None,
                ipv6_addresses: None,
                eip_allocation_id: None,
                internet_charge_type: None,
                image_id: None,
                hostname: None,
                description: None,
                gpu: None,
                io_optimized: None,
                latest_operation: None,
                latest_operation_state: None,
                tags: None,
                project_id: None,
                resource_group_id: None,
                auto_renew_flag: None,
            })
            .await,
        "upsert cloud instance should succeed",
    );

    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/dashboard/overview", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["cloud_summary"]["total_accounts"], 1);
    assert_eq!(body["data"]["cloud_summary"]["enabled_accounts"], 1);
    assert_eq!(body["data"]["cloud_summary"]["total_instances"], 2);
    assert_eq!(body["data"]["cloud_summary"]["running_instances"], 1);
    assert_eq!(body["data"]["cloud_summary"]["stopped_instances"], 1);
    assert_eq!(body["data"]["cloud_summary"]["unknown_instances"], 0);
}

#[tokio::test]
async fn dashboard_overview_should_count_unknown_cloud_instance_statuses() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let now = chrono::Utc::now();
    must_ok(
        ctx.state
            .cert_store
            .insert_system_config(&oxmon_storage::SystemConfigRow {
                id: oxmon_common::id::next_id(),
                config_key: "cloud_tencent_unknown_status".to_string(),
                config_type: "cloud_account".to_string(),
                provider: Some("tencent".to_string()),
                display_name: "Cloud Unknown Status".to_string(),
                description: None,
                config_json:
                    r#"{"secret_id":"sid","secret_key":"skey","regions":["ap-guangzhou"]}"#
                        .to_string(),
                enabled: true,
                created_at: now,
                updated_at: now,
            })
            .await,
        "insert cloud account should succeed",
    );

    let now_ts = now.timestamp();
    for (instance_id, status) in [
        ("ins-unknown-null", None),
        ("ins-unknown-literal", Some("unknown")),
        ("ins-unknown-garbage", Some("mystery_status")),
    ] {
        must_ok(
            ctx.state
                .cert_store
                .upsert_cloud_instance(&oxmon_storage::CloudInstanceRow {
                    id: String::new(),
                    instance_id: instance_id.to_string(),
                    instance_name: Some(instance_id.to_string()),
                    provider: "tencent".to_string(),
                    account_config_key: "cloud_tencent_unknown_status".to_string(),
                    region: "ap-guangzhou".to_string(),
                    public_ip: None,
                    private_ip: None,
                    os: None,
                    status: status.map(str::to_string),
                    last_seen_at: now_ts,
                    created_at: now_ts,
                    updated_at: now_ts,
                    instance_type: None,
                    cpu_cores: None,
                    memory_gb: None,
                    disk_gb: None,
                    created_time: None,
                    expired_time: None,
                    charge_type: None,
                    vpc_id: None,
                    subnet_id: None,
                    security_group_ids: None,
                    zone: None,
                    internet_max_bandwidth: None,
                    ipv6_addresses: None,
                    eip_allocation_id: None,
                    internet_charge_type: None,
                    image_id: None,
                    hostname: None,
                    description: None,
                    gpu: None,
                    io_optimized: None,
                    latest_operation: None,
                    latest_operation_state: None,
                    tags: None,
                    project_id: None,
                    resource_group_id: None,
                    auto_renew_flag: None,
                })
                .await,
            "upsert cloud instance should succeed",
        );
    }

    let (status, body, _) =
        request_no_body(&ctx.app, "GET", "/v1/dashboard/overview", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["cloud_summary"]["total_accounts"], 1);
    assert_eq!(body["data"]["cloud_summary"]["total_instances"], 3);
    assert_eq!(body["data"]["cloud_summary"]["unknown_instances"], 3);
}

#[tokio::test]
async fn system_certs_backfill_domains_should_backfill_from_certificate_details() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let now = chrono::Utc::now();
    let domain = "manual-backfill.example.com";
    must_ok(
        ctx.state
            .cert_store
            .upsert_certificate_details(&oxmon_common::types::CertificateDetails {
                id: oxmon_common::id::next_id(),
                domain: domain.to_string(),
                not_before: now - chrono::Duration::days(1),
                not_after: now + chrono::Duration::days(30),
                ip_addresses: vec!["1.1.1.1".to_string()],
                issuer_cn: Some("Test CA".to_string()),
                issuer_o: None,
                issuer_ou: None,
                issuer_c: None,
                subject_alt_names: vec![domain.to_string()],
                chain_valid: true,
                chain_error: None,
                last_checked: now,
                created_at: now,
                updated_at: now,
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
            })
            .await,
        "upsert certificate details should succeed",
    );

    // Remove auto-backfilled domain to simulate legacy orphan data, then use manual endpoint.
    let existing = must_some(
        must_ok(
            ctx.state.cert_store.get_domain_by_name(domain).await,
            "query domain should succeed",
        ),
        "domain should exist after upsert",
    );
    let deleted = must_ok(
        ctx.state.cert_store.delete_domain(&existing.id).await,
        "delete domain should succeed",
    );
    assert!(deleted);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "POST",
        "/v1/system/certs/backfill-domains",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["inserted_domains"], 1);
    assert_eq!(body["data"]["dry_run"], false);
    assert!(body["data"]["domains_preview"].is_array());
    assert_eq!(body["data"]["domains_preview"][0], domain);
}

#[tokio::test]
async fn system_certs_backfill_domains_dry_run_should_preview_without_writing() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let now = chrono::Utc::now();
    let domain = "manual-backfill-dry-run.example.com";
    must_ok(
        ctx.state
            .cert_store
            .upsert_certificate_details(&oxmon_common::types::CertificateDetails {
                id: oxmon_common::id::next_id(),
                domain: domain.to_string(),
                not_before: now - chrono::Duration::days(1),
                not_after: now + chrono::Duration::days(30),
                ip_addresses: vec!["1.1.1.1".to_string()],
                issuer_cn: Some("Test CA".to_string()),
                issuer_o: None,
                issuer_ou: None,
                issuer_c: None,
                subject_alt_names: vec![domain.to_string()],
                chain_valid: true,
                chain_error: None,
                last_checked: now,
                created_at: now,
                updated_at: now,
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
            })
            .await,
        "upsert certificate details should succeed",
    );

    let existing = must_some(
        must_ok(
            ctx.state.cert_store.get_domain_by_name(domain).await,
            "query domain should succeed",
        ),
        "domain should exist after upsert",
    );
    must_ok(
        ctx.state.cert_store.delete_domain(&existing.id).await,
        "delete domain should succeed",
    );

    let (status, body, _) = request_no_body(
        &ctx.app,
        "POST",
        "/v1/system/certs/backfill-domains?dry_run=true",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["inserted_domains"], 1);
    assert_eq!(body["data"]["dry_run"], true);
    assert!(body["data"]["domains_preview"].is_array());
    assert_eq!(body["data"]["domains_preview"][0], domain);

    // dry run should not write
    assert!(must_ok(
        ctx.state.cert_store.get_domain_by_name(domain).await,
        "query domain should succeed",
    )
    .is_none());
}

#[tokio::test]
async fn openapi_endpoints_should_be_accessible() {
    let ctx = must_ok(build_test_context().await, "test context should build");

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["paths"].is_object());
    assert_eq!(
        body["paths"]["/v1/auth/login"]["post"]["responses"]["429"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/LoginLockoutResponse"
    );
    assert!(
        body["components"]["schemas"]["LoginLockoutResponse"]["properties"]["data"].is_object()
    );
    assert!(
        body["components"]["schemas"]["LoginLockoutInfo"]["properties"]["locked_until"].is_object()
    );
    assert!(
        body["components"]["schemas"]["LoginLockoutInfo"]["properties"]["retry_after_seconds"]
            .is_object()
    );
    assert_eq!(
        body["paths"]["/v1/admin/users/login-throttles"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["$ref"],
        "#/components/schemas/LoginThrottleListResponse"
    );
    assert!(
        body["components"]["schemas"]["LoginThrottleListResponse"]["properties"]["data"]
            .is_object()
    );
    assert!(
        body["components"]["schemas"]["LoginThrottleItem"]["properties"]["locked_until"]
            .is_object()
    );
    assert_eq!(
        body["paths"]["/v1/admin/users/unlock-login-throttle"]["post"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/EmptySuccessResponse"
    );
    assert!(body["components"]["schemas"]["EmptySuccessResponse"]["example"].is_object());
    assert!(body["components"]["schemas"]["UnlockLoginThrottleRequest"]["example"].is_object());
    assert_eq!(
        body["paths"]["/v1/auth/logout"]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/EmptySuccessResponse"
    );
    assert!(body["components"]["schemas"]["EmptySuccessResponse"]["example"].is_object());
    assert_eq!(
        body["paths"]["/v1/auth/password"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["$ref"],
        "#/components/schemas/EmptySuccessResponse"
    );
    assert!(body["components"]["schemas"]["EmptySuccessResponse"]["example"].is_object());
    assert_eq!(
        body["paths"]["/v1/admin/users/{id}/password"]["post"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["$ref"],
        "#/components/schemas/EmptySuccessResponse"
    );
    assert!(body["components"]["schemas"]["EmptySuccessResponse"]["example"].is_object());
    assert_eq!(
        body["paths"]["/v1/admin/users/{id}"]["delete"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["$ref"],
        "#/components/schemas/EmptySuccessResponse"
    );
    assert!(body["components"]["schemas"]["EmptySuccessResponse"]["example"].is_object());

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.yaml", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_null() || body.is_object() || body.is_string());
    if let Some(raw) = body.as_str() {
        assert!(raw.contains("openapi:"));
    }
}

#[tokio::test]
async fn auth_logout_and_login_lockout_should_work() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let token = login_and_get_token(&ctx.app).await;

    let (status, body, _) =
        request_no_body(&ctx.app, "POST", "/v1/auth/logout", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let logout_audits = must_ok(
        ctx.state
            .cert_store
            .list_audit_logs(
                &oxmon_storage::AuditLogFilter {
                    action: Some("LOGOUT".to_string()),
                    ..Default::default()
                },
                20,
                0,
            )
            .await,
        "logout audit logs should query",
    );
    assert!(logout_audits.iter().any(|row| {
        row.username == "admin"
            && row.path == "/v1/auth/logout"
            && row.status_code == StatusCode::OK.as_u16() as i32
    }));

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/agents", Some(&token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_err_envelope(&body, 1002);

    let encrypted_wrong = encrypt_password_with_state(&ctx.state, "wrong-password");
    for _ in 0..4 {
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
    }

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["err_code"], 1010);
    assert!(body["err_msg"].is_string());
    assert!(body["data"]["locked_until"].is_string());
    assert!(body["data"]["retry_after_seconds"].as_i64().unwrap_or(-1) >= 0);

    let alerts = must_ok(
        ctx.state
            .storage
            .query_alert_history(
                chrono::Utc::now() - chrono::Duration::hours(1),
                chrono::Utc::now() + chrono::Duration::minutes(1),
                Some("critical"),
                None,
                20,
                0,
            )
            .await,
        "security alerts should query",
    );
    assert!(alerts
        .iter()
        .any(|event| event.rule_id == "security-login-lockout"));

    let encrypted_ok = encrypt_password_with_state(&ctx.state, "changeme");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(json!({"username":"admin","encrypted_password": encrypted_ok})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["err_code"], 1010);
    assert!(body["err_msg"].is_string());
    assert!(body["data"]["locked_until"].is_string());
    assert!(body["data"]["retry_after_seconds"].as_i64().unwrap_or(-1) >= 0);
}

#[tokio::test]
async fn admin_create_and_update_user_should_write_audit_logs() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;

    let encrypted = encrypt_password_with_state(&ctx.state, "createpass123");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/admin/users",
        Some(&admin_token),
        Some(json!({
            "username": "audit_create_target",
            "encrypted_password": encrypted,
            "status": "active",
            "avatar": "https://example.com/a.png",
            "phone": "13800000000",
            "email": "audit@example.com"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);
    let user_id =
        must_some(body["data"]["id"].as_str(), "created user id should exist").to_string();

    let create_audits = must_ok(
        ctx.state
            .cert_store
            .list_audit_logs(
                &AuditLogFilter {
                    action: Some("CREATE_ADMIN_USER".to_string()),
                    ..Default::default()
                },
                20,
                0,
            )
            .await,
        "create admin user audit logs should query",
    );
    assert!(create_audits.iter().any(|row| {
        row.username == "admin"
            && row.resource_id.as_deref() == Some(user_id.as_str())
            && row.path == "/v1/admin/users"
            && row.status_code == StatusCode::CREATED.as_u16() as i32
            && row.request_body.as_deref().unwrap_or("").contains("\"encrypted_password\":\"***\"")
    }));

    let (status, body, _) = request_json(
        &ctx.app,
        "PUT",
        &format!("/v1/admin/users/{user_id}"),
        Some(&admin_token),
        Some(json!({
            "status": "disabled",
            "avatar": "https://example.com/b.png",
            "phone": "13900000000",
            "email": "audit2@example.com"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert_eq!(body["data"]["status"], "disabled");

    let update_audits = must_ok(
        ctx.state
            .cert_store
            .list_audit_logs(
                &AuditLogFilter {
                    action: Some("UPDATE_ADMIN_USER".to_string()),
                    ..Default::default()
                },
                20,
                0,
            )
            .await,
        "update admin user audit logs should query",
    );
    assert!(update_audits.iter().any(|row| {
        row.username == "admin"
            && row.resource_id.as_deref() == Some(user_id.as_str())
            && row.path == format!("/v1/admin/users/{user_id}")
            && row.method == "PUT"
            && row.status_code == StatusCode::OK.as_u16() as i32
            && row.request_body.as_deref().unwrap_or("").contains("\"status\":\"disabled\"")
    }));
}

#[tokio::test]
async fn admin_reset_password_and_delete_user_should_write_audit_logs() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;

    let encrypted = encrypt_password_with_state(&ctx.state, "userpass123");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/admin/users",
        Some(&admin_token),
        Some(json!({
            "username": "audit_target",
            "encrypted_password": encrypted,
            "status": "active"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_ok_envelope(&body);
    let user_id =
        must_some(body["data"]["id"].as_str(), "created user id should exist").to_string();

    let encrypted_new = encrypt_password_with_state(&ctx.state, "userpass456");
    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        &format!("/v1/admin/users/{user_id}/password"),
        Some(&admin_token),
        Some(json!({"encrypted_new_password": encrypted_new})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let reset_audits = must_ok(
        ctx.state
            .cert_store
            .list_audit_logs(
                &AuditLogFilter {
                    action: Some("RESET_ADMIN_PASSWORD".to_string()),
                    ..Default::default()
                },
                20,
                0,
            )
            .await,
        "reset password audit logs should query",
    );
    assert!(reset_audits.iter().any(|row| {
        row.username == "admin"
            && row.resource_id.as_deref() == Some(user_id.as_str())
            && row.path == format!("/v1/admin/users/{user_id}/password")
            && row
                .request_body
                .as_deref()
                .unwrap_or("")
                .contains("\"encrypted_new_password\":\"***\"")
    }));

    let (status, body, _) = request_no_body(
        &ctx.app,
        "DELETE",
        &format!("/v1/admin/users/{user_id}"),
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let delete_audits = must_ok(
        ctx.state
            .cert_store
            .list_audit_logs(
                &AuditLogFilter {
                    action: Some("DELETE_ADMIN_USER".to_string()),
                    ..Default::default()
                },
                20,
                0,
            )
            .await,
        "delete admin user audit logs should query",
    );
    assert!(delete_audits.iter().any(|row| {
        row.username == "admin"
            && row.resource_id.as_deref() == Some(user_id.as_str())
            && row.path == format!("/v1/admin/users/{user_id}")
            && row.method == "DELETE"
            && row.status_code == StatusCode::OK.as_u16() as i32
    }));
}

#[tokio::test]
async fn admin_unlock_login_throttle_should_clear_lock() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;
    let ip = "198.51.100.10";
    let headers = [("x-forwarded-for", ip)];

    let encrypted_wrong = encrypt_password_with_state(&ctx.state, "wrong-password");
    for _ in 0..4 {
        let (status, body, _) = request_json_with_headers(
            &ctx.app,
            "POST",
            "/v1/auth/login",
            None,
            &headers,
            Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_err_envelope(&body, 1002);
    }

    let (status, body, _) = request_json_with_headers(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        &headers,
        Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["err_code"], 1010);
    assert!(body["err_msg"].is_string());
    assert!(body["data"]["locked_until"].is_string());
    assert!(body["data"]["retry_after_seconds"].as_i64().unwrap_or(-1) >= 0);

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/admin/users/unlock-login-throttle",
        Some(&admin_token),
        Some(json!({"username":"admin","ip_address": ip})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let unlock_audits = must_ok(
        ctx.state
            .cert_store
            .list_audit_logs(
                &AuditLogFilter {
                    action: Some("UNLOCK_LOGIN_THROTTLE".to_string()),
                    ..Default::default()
                },
                20,
                0,
            )
            .await,
        "unlock audit logs should query",
    );
    assert!(unlock_audits.iter().any(|row| {
        row.username == "admin"
            && row.path == "/v1/admin/users/unlock-login-throttle"
            && row.status_code == StatusCode::OK.as_u16() as i32
            && row.resource_id.as_deref() == Some("admin")
    }));

    let active_security_alerts = must_ok(
        ctx.state
            .storage
            .query_active_alerts(
                None,
                Some("critical"),
                Some("security-login-lockout"),
                None,
                20,
                0,
            )
            .await,
        "active security alerts should query",
    );
    assert!(active_security_alerts.is_empty());

    let encrypted_ok = encrypt_password_with_state(&ctx.state, "changeme");
    let (status, body, _) = request_json_with_headers(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        &headers,
        Some(json!({"username":"admin","encrypted_password": encrypted_ok})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
}

#[tokio::test]
async fn admin_list_login_throttles_should_show_active_locks() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;
    let ip = "203.0.113.10";
    let headers = [("x-forwarded-for", ip)];
    let encrypted_wrong = encrypt_password_with_state(&ctx.state, "wrong-password");

    for _ in 0..5 {
        let _ = request_json_with_headers(
            &ctx.app,
            "POST",
            "/v1/auth/login",
            None,
            &headers,
            Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
        )
        .await;
    }

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/admin/users/login-throttles?username=admin&locked_only=true",
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let items = body["data"]["items"]
        .as_array()
        .expect("items should be array");
    assert!(!items.is_empty());
    assert_eq!(items[0]["username"], "admin");
    assert_eq!(items[0]["ip_address"], ip);
    assert!(items[0]["locked_until"].is_string());
}

#[tokio::test]
async fn audit_logs_should_filter_unlock_login_throttle_action() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;
    let ip = "198.51.100.31";
    let headers = [("x-forwarded-for", ip)];
    let encrypted_wrong = encrypt_password_with_state(&ctx.state, "wrong-password");

    for _ in 0..5 {
        let _ = request_json_with_headers(
            &ctx.app,
            "POST",
            "/v1/auth/login",
            None,
            &headers,
            Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
        )
        .await;
    }

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/admin/users/unlock-login-throttle",
        Some(&admin_token),
        Some(json!({"username":"admin","ip_address": ip})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/audit/logs?action=UNLOCK_LOGIN_THROTTLE&path__contains=%2Fadmin%2Fusers%2Funlock-login-throttle&status_code=200",
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let items = body["data"]["items"]
        .as_array()
        .expect("items should be array");
    assert!(!items.is_empty());
    assert!(items.iter().any(|item| {
        item["action"] == "UNLOCK_LOGIN_THROTTLE"
            && item["username"] == "admin"
            && item["path"] == "/v1/admin/users/unlock-login-throttle"
            && item["status_code"] == 200
    }));
}

#[tokio::test]
async fn audit_logs_should_filter_logout_action() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;

    let (status, body, _) =
        request_no_body(&ctx.app, "POST", "/v1/auth/logout", Some(&admin_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let new_admin_token = login_and_get_token(&ctx.app).await;
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/audit/logs?action=LOGOUT&path__contains=%2Fauth%2Flogout&status_code=200",
        Some(&new_admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);

    let items = body["data"]["items"]
        .as_array()
        .expect("items should be array");
    assert!(!items.is_empty());
    assert!(items.iter().any(|item| {
        item["action"] == "LOGOUT"
            && item["username"] == "admin"
            && item["path"] == "/v1/auth/logout"
            && item["status_code"] == 200
    }));
}

#[tokio::test]
async fn audit_logs_should_filter_login_failed_by_username_and_ip() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;
    let ip = "198.51.100.25";
    let headers = [("x-forwarded-for", ip)];
    let encrypted_wrong = encrypt_password_with_state(&ctx.state, "wrong-password");

    let (status, body, _) = request_json_with_headers(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        &headers,
        Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_err_envelope(&body, 1002);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/audit/logs?action=LOGIN_FAILED&username__contains=adm&ip_address=198.51.100.25&path__contains=%2Fauth%2Flogin&status_code=401",
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let items = body["data"]["items"]
        .as_array()
        .expect("items should be array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["action"], "LOGIN_FAILED");
    assert_eq!(items[0]["username"], "admin");
    assert_eq!(items[0]["ip_address"], ip);
    assert_eq!(items[0]["status_code"], 401);
}

#[tokio::test]
async fn audit_security_summary_should_aggregate_login_events() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;
    let headers = [("x-forwarded-for", "203.0.113.50")];
    let encrypted_wrong = encrypt_password_with_state(&ctx.state, "wrong-password");

    let (status, body, _) = request_json_with_headers(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        &headers,
        Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_err_envelope(&body, 1002);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/audit/logs/security-summary?hours=24",
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    assert!(body["data"]["login_success_count"].as_u64().unwrap_or(0) >= 1);
    assert!(body["data"]["login_failed_count"].as_u64().unwrap_or(0) >= 1);
    assert!(body["data"]["unique_failed_ips"].as_u64().unwrap_or(0) >= 1);
    assert!(body["data"]["top_failed_ips"].is_array());
    assert_eq!(body["data"]["top_failed_ips"][0]["key"], "203.0.113.50");
}

#[tokio::test]
async fn audit_security_timeseries_should_return_hourly_points() {
    let ctx = must_ok(build_test_context().await, "test context should build");
    let admin_token = login_and_get_token(&ctx.app).await;
    let headers = [("x-forwarded-for", "203.0.113.77")];
    let encrypted_wrong = encrypt_password_with_state(&ctx.state, "wrong-password");

    let _ = request_json_with_headers(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        &headers,
        Some(json!({"username":"admin","encrypted_password": encrypted_wrong})),
    )
    .await;

    let encrypted_ok = encrypt_password_with_state(&ctx.state, "changeme");
    let _ = request_json_with_headers(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        &headers,
        Some(json!({"username":"admin","encrypted_password": encrypted_ok})),
    )
    .await;

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/audit/logs/security-summary/timeseries?hours=6",
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let points = body["data"]["points"]
        .as_array()
        .expect("points should be array");
    assert_eq!(points.len(), 6);
    assert!(points.iter().all(|point| point["hour"].is_string()));
    assert!(points
        .iter()
        .any(|point| point["login_success_count"].as_u64().unwrap_or(0) >= 1));
    assert!(points
        .iter()
        .any(|point| point["login_failed_count"].as_u64().unwrap_or(0) >= 1));
}
