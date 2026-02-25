mod common;

use axum::http::StatusCode;
use common::{
    add_whitelist_agent, assert_ok_envelope, build_test_context, grpc_report_direct,
    login_and_get_token, request_no_body,
};
use oxmon_server::grpc;

#[tokio::test]
async fn grpc_report_should_write_metrics_and_be_queryable_via_rest() {
    let ctx = build_test_context().expect("test context should build");
    let http_token = login_and_get_token(&ctx.app).await;
    let agent_token = add_whitelist_agent(&ctx.app, &http_token, "agent-grpc-1").await;
    let service = grpc::MetricServiceImpl::new(ctx.state.clone(), true);

    let resp = grpc_report_direct(
        &service,
        "agent-grpc-1",
        Some(&agent_token),
        Some("agent-grpc-1"),
        "cpu.usage",
        88.0,
    )
    .await
    .expect("grpc report should succeed");
    assert!(resp.get_ref().success);

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/metrics?agent_id__eq=agent-grpc-1&metric_name__eq=cpu.usage&limit=10&offset=0",
        Some(&http_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let items = body["data"]["items"]
        .as_array()
        .expect("data.items should be array");
    assert!(!items.is_empty());

    // 先通过列表接口获取 agent 的数据库 id
    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        "/v1/agents?limit=100&offset=0",
        Some(&http_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let agents = body["data"]["items"].as_array().expect("agents list");
    let agent_db_id = agents
        .iter()
        .find(|a| a["agent_id"].as_str() == Some("agent-grpc-1"))
        .and_then(|a| a["id"].as_str())
        .expect("agent-grpc-1 should have a database id");

    let (status, body, _) = request_no_body(
        &ctx.app,
        "GET",
        &format!("/v1/agents/{agent_db_id}/latest"),
        Some(&http_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ok_envelope(&body);
    let rows = body["data"].as_array().expect("data should be array");
    assert!(!rows.is_empty());
}

#[tokio::test]
async fn grpc_report_should_fail_without_or_with_invalid_auth() {
    let ctx = build_test_context().expect("test context should build");
    let http_token = login_and_get_token(&ctx.app).await;
    let agent_token = add_whitelist_agent(&ctx.app, &http_token, "agent-grpc-2").await;
    let service = grpc::MetricServiceImpl::new(ctx.state.clone(), true);

    let err = grpc_report_direct(
        &service,
        "agent-grpc-2",
        None,
        Some("agent-grpc-2"),
        "cpu.usage",
        50.0,
    )
    .await
    .expect_err("missing auth should fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let err = grpc_report_direct(
        &service,
        "agent-grpc-2",
        Some("wrong-token"),
        Some("agent-grpc-2"),
        "cpu.usage",
        50.0,
    )
    .await
    .expect_err("invalid auth should fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let resp = grpc_report_direct(
        &service,
        "agent-grpc-2",
        Some(&agent_token),
        Some("agent-grpc-2"),
        "cpu.usage",
        50.0,
    )
    .await
    .expect("valid auth should pass");
    assert!(resp.get_ref().success);
}

#[tokio::test]
async fn grpc_report_should_reject_metadata_payload_agent_mismatch() {
    let ctx = build_test_context().expect("test context should build");
    let http_token = login_and_get_token(&ctx.app).await;
    let agent_token = add_whitelist_agent(&ctx.app, &http_token, "agent-grpc-3").await;
    let service = grpc::MetricServiceImpl::new(ctx.state.clone(), true);

    let err = grpc_report_direct(
        &service,
        "another-agent",
        Some(&agent_token),
        Some("agent-grpc-3"),
        "cpu.usage",
        60.0,
    )
    .await
    .expect_err("agent mismatch should fail");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}
