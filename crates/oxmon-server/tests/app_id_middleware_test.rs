mod common;

use axum::http::StatusCode;
use common::{build_test_context, login_and_get_token, request_json, request_no_body};

#[tokio::test]
async fn health_without_app_id_when_disabled_should_return_200() {
    // Default config has require_app_id = false
    let ctx = build_test_context().expect("test context should build");

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/health", None).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["err_code"], 0);
    assert_eq!(body["data"]["storage_status"], "ok");
}

#[tokio::test]
async fn login_without_app_id_when_disabled_should_work() {
    // Default config has require_app_id = false
    let ctx = build_test_context().expect("test context should build");

    let payload = serde_json::json!({
        "username": "admin",
        "password": "changeme"
    });

    let (status, body, _) = request_json(
        &ctx.app,
        "POST",
        "/v1/auth/login",
        None,
        Some(payload),
    )
    .await;

    // Should succeed with valid credentials
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["err_code"], 0);
    assert!(body["data"]["access_token"].is_string());
}

#[tokio::test]
async fn protected_route_not_affected_by_app_id() {
    // Protected routes should only check Bearer Token, not ox-app-id
    let ctx = build_test_context().expect("test context should build");

    // Without Bearer token, should return 401 (not 403 for missing app-id)
    let (status, _, _) = request_no_body(&ctx.app, "GET", "/v1/agents", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // With valid token but no app-id, should work
    let token = login_and_get_token(&ctx.app).await;

    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/agents", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["err_code"], 0);
}

// Note: Testing with require_app_id = true requires modifying the config
// This would need a separate test context builder with custom config
// For now, we verify the disabled (default) behavior works correctly
