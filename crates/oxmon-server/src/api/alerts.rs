use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_empty_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use oxmon_storage::cert_store::{AlertRuleRow, AlertRuleUpdate};
use oxmon_storage::StorageEngine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};


/// 告警规则详情
#[derive(Serialize, ToSchema)]
struct AlertRuleDetailResponse {
    id: String,
    name: String,
    rule_type: String,
    metric: String,
    agent_pattern: String,
    severity: String,
    enabled: bool,
    config_json: String,
    silence_secs: u64,
    source: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<AlertRuleRow> for AlertRuleDetailResponse {
    fn from(r: AlertRuleRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            rule_type: r.rule_type,
            metric: r.metric,
            agent_pattern: r.agent_pattern,
            severity: r.severity,
            enabled: r.enabled,
            config_json: r.config_json,
            silence_secs: r.silence_secs,
            source: r.source,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// 获取单条告警规则详情。
#[utoipa::path(
    get,
    path = "/v1/alerts/rules/{id}",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "告警规则 ID")),
    responses(
        (status = 200, description = "告警规则详情", body = AlertRuleDetailResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "规则不存在", body = crate::api::ApiError)
    )
)]
async fn get_alert_rule(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_alert_rule_by_id(&id) {
        Ok(Some(rule)) => success_response(StatusCode::OK, &trace_id, AlertRuleDetailResponse::from(rule)),
        Ok(None) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Rule not found")
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get alert rule");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

#[derive(Deserialize, ToSchema)]
struct CreateAlertRuleRequest {
    name: String,
    rule_type: String,
    metric: String,
    #[serde(default = "default_agent_pattern")]
    agent_pattern: String,
    #[serde(default = "default_severity")]
    severity: String,
    #[serde(default)]
    config_json: String,
    #[serde(default = "default_silence_secs")]
    silence_secs: u64,
}

fn default_agent_pattern() -> String {
    "*".to_string()
}
fn default_severity() -> String {
    "info".to_string()
}
fn default_silence_secs() -> u64 {
    600
}

/// 创建告警规则。
#[utoipa::path(
    post,
    path = "/v1/alerts/rules",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    request_body = CreateAlertRuleRequest,
    responses(
        (status = 201, description = "告警规则已创建", body = AlertRuleDetailResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn create_alert_rule(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateAlertRuleRequest>,
) -> impl IntoResponse {
    let row = AlertRuleRow {
        id: oxmon_common::id::next_id(),
        name: req.name,
        rule_type: req.rule_type,
        metric: req.metric,
        agent_pattern: req.agent_pattern,
        severity: req.severity,
        enabled: true,
        config_json: req.config_json,
        silence_secs: req.silence_secs,
        source: "api".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    match state.cert_store.insert_alert_rule(&row) {
        Ok(rule) => success_response(StatusCode::CREATED, &trace_id, AlertRuleDetailResponse::from(rule)),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                error_response(StatusCode::CONFLICT, &trace_id, "conflict", "Rule name already exists")
                    .into_response()
            } else {
                tracing::error!(error = %e, "Failed to create alert rule");
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "storage_error",
                    "Database error",
                )
                .into_response()
            }
        }
    }
}

/// 更新告警规则。
#[utoipa::path(
    put,
    path = "/v1/alerts/rules/{id}",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "告警规则 ID")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "告警规则已更新", body = AlertRuleDetailResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "规则不存在", body = crate::api::ApiError)
    )
)]
async fn update_alert_rule(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update): Json<AlertRuleUpdate>,
) -> impl IntoResponse {
    match state.cert_store.update_alert_rule(&id, &update) {
        Ok(Some(rule)) => success_response(StatusCode::OK, &trace_id, AlertRuleDetailResponse::from(rule)),
        Ok(None) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Rule not found")
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update alert rule");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 删除告警规则。
#[utoipa::path(
    delete,
    path = "/v1/alerts/rules/{id}",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "告警规则 ID")),
    responses(
        (status = 200, description = "告警规则已删除"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "规则不存在", body = crate::api::ApiError)
    )
)]
async fn delete_alert_rule(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_alert_rule(&id) {
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "Rule deleted"),
        Ok(false) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Rule not found")
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete alert rule");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

#[derive(Deserialize, ToSchema)]
struct EnableRequest {
    enabled: bool,
}

/// 启用或禁用告警规则。
#[utoipa::path(
    put,
    path = "/v1/alerts/rules/{id}/enable",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "告警规则 ID")),
    request_body = EnableRequest,
    responses(
        (status = 200, description = "告警规则状态已更新", body = AlertRuleDetailResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "规则不存在", body = crate::api::ApiError)
    )
)]
async fn set_alert_rule_enabled(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<EnableRequest>,
) -> impl IntoResponse {
    match state.cert_store.set_alert_rule_enabled(&id, req.enabled) {
        Ok(Some(rule)) => success_response(StatusCode::OK, &trace_id, AlertRuleDetailResponse::from(rule)),
        Ok(None) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Rule not found")
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update rule enabled state");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 列出持久化的告警规则。
#[utoipa::path(
    get,
    path = "/v1/alerts/rules/config",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "告警规则配置列表", body = Vec<AlertRuleDetailResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_alert_rules_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    match state
        .cert_store
        .list_alert_rules(pagination.limit(), pagination.offset())
    {
        Ok(rules) => {
            let resp: Vec<AlertRuleDetailResponse> =
                rules.into_iter().map(AlertRuleDetailResponse::from).collect();
            success_response(StatusCode::OK, &trace_id, resp)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list alert rules");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

// ---- Alert lifecycle ----

/// 确认告警事件。
#[utoipa::path(
    post,
    path = "/v1/alerts/history/{id}/acknowledge",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "告警事件 ID")),
    responses(
        (status = 200, description = "告警已确认"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "告警不存在", body = crate::api::ApiError)
    )
)]
async fn acknowledge_alert(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.acknowledge_alert(&id) {
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "Alert acknowledged"),
        Ok(false) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Alert not found")
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to acknowledge alert");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 解决告警事件。
#[utoipa::path(
    post,
    path = "/v1/alerts/history/{id}/resolve",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "告警事件 ID")),
    responses(
        (status = 200, description = "告警已解决"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "告警不存在", body = crate::api::ApiError)
    )
)]
async fn resolve_alert(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.resolve_alert(&id) {
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "Alert resolved"),
        Ok(false) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Alert not found")
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to resolve alert");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 查询当前活跃（未解决）告警。
#[utoipa::path(
    get,
    path = "/v1/alerts/active",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "活跃告警列表"),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn active_alerts(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    match state
        .storage
        .query_active_alerts(pagination.limit(), pagination.offset())
    {
        Ok(events) => success_response(StatusCode::OK, &trace_id, events),
        Err(e) => {
            tracing::error!(error = %e, "Failed to query active alerts");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 告警统计摘要。
#[utoipa::path(
    get,
    path = "/v1/alerts/summary",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "告警统计摘要"),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn alert_summary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let to = Utc::now();
    let from = to - chrono::Duration::days(1);
    match state.storage.query_alert_summary(from, to) {
        Ok(summary) => success_response(StatusCode::OK, &trace_id, summary),
        Err(e) => {
            tracing::error!(error = %e, "Failed to query alert summary");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

pub fn alert_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(super::list_alert_rules, create_alert_rule))
        .routes(routes!(get_alert_rule))
        .routes(routes!(list_alert_rules_config))
        .routes(routes!(update_alert_rule, delete_alert_rule))
        .routes(routes!(set_alert_rule_enabled))
        .routes(routes!(acknowledge_alert))
        .routes(routes!(resolve_alert))
        .routes(routes!(active_alerts))
        .routes(routes!(alert_summary))
}

