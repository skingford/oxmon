use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use oxmon_common::types::UpdateAlertRuleRequest;
use oxmon_storage::cert_store::AlertRuleRow;
use oxmon_storage::StorageEngine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

// ---- Alert Rules ----

/// 告警规则信息
#[derive(Serialize, ToSchema)]
pub struct AlertRuleResponse {
    /// 规则唯一标识
    pub id: String,
    /// 规则名称
    pub name: String,
    /// 规则类型（threshold / rate_of_change / trend_prediction / cert_expiration）
    pub rule_type: String,
    /// 监控指标名称
    pub metric: String,
    /// Agent 匹配模式（支持 glob）
    pub agent_pattern: String,
    /// 告警级别
    pub severity: String,
    /// 是否启用
    pub enabled: bool,
}

/// 告警规则列表查询参数
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListAlertRulesParams {
    /// 规则名称模糊匹配
    #[param(required = false, rename = "name__contains")]
    #[serde(rename = "name__contains")]
    name_contains: Option<String>,
    /// 规则类型精确匹配（threshold / rate_of_change / trend_prediction / cert_expiration）
    #[param(required = false, rename = "rule_type__eq")]
    #[serde(rename = "rule_type__eq")]
    rule_type_eq: Option<String>,
    /// 监控指标模糊匹配
    #[param(required = false, rename = "metric__contains")]
    #[serde(rename = "metric__contains")]
    metric_contains: Option<String>,
    /// 告警级别精确匹配（info / warning / critical）
    #[param(required = false, rename = "severity__eq")]
    #[serde(rename = "severity__eq")]
    severity_eq: Option<String>,
    /// 是否启用精确匹配
    #[param(required = false, rename = "enabled__eq")]
    #[serde(rename = "enabled__eq")]
    enabled_eq: Option<bool>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(
        default,
        deserialize_with = "crate::api::pagination::deserialize_optional_u64"
    )]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(
        default,
        deserialize_with = "crate::api::pagination::deserialize_optional_u64"
    )]
    offset: Option<u64>,
}

/// 分页查询告警规则列表。
/// 默认排序：`created_at` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/alerts/rules",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(ListAlertRulesParams),
    responses(
        (status = 200, description = "告警规则分页列表", body = Vec<AlertRuleResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_alert_rules(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListAlertRulesParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);
    let name_contains = params.name_contains.as_deref();
    let rule_type = params.rule_type_eq.as_deref();
    let metric_contains = params.metric_contains.as_deref();
    let severity = params.severity_eq.as_deref();
    let enabled = params.enabled_eq;

    let total = match state.cert_store.count_alert_rules(name_contains, rule_type, metric_contains, severity, enabled) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count alert rules");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state
        .cert_store
        .list_alert_rules(name_contains, rule_type, metric_contains, severity, enabled, limit, offset)
    {
        Ok(rules) => {
            let items: Vec<AlertRuleResponse> = rules
                .into_iter()
                .map(|r| AlertRuleResponse {
                    id: r.id,
                    name: r.name,
                    rule_type: r.rule_type,
                    metric: r.metric,
                    agent_pattern: r.agent_pattern,
                    severity: r.severity,
                    enabled: r.enabled,
                })
                .collect();
            success_paginated_response(
                StatusCode::OK,
                &trace_id,
                items,
                total,
                limit,
                offset,
            )
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
        Ok(Some(rule)) => success_response(
            StatusCode::OK,
            &trace_id,
            AlertRuleDetailResponse::from(rule),
        ),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Rule not found",
        )
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
    #[serde(default = "default_enabled")]
    enabled: bool,
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
fn default_enabled() -> bool {
    true
}

/// 创建告警规则。
#[utoipa::path(
    post,
    path = "/v1/alerts/rules",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    request_body = CreateAlertRuleRequest,
    responses(
        (status = 201, description = "告警规则已创建", body = crate::api::IdResponse),
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
        enabled: req.enabled,
        config_json: req.config_json,
        silence_secs: req.silence_secs,
        source: "api".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    match state.cert_store.insert_alert_rule(&row) {
        Ok(rule) => {
            if let Err(e) =
                crate::rule_builder::reload_alert_engine(&state.cert_store, &state.alert_engine)
            {
                tracing::error!(error = %e, "Failed to reload alert engine after rule creation");
            }
            crate::api::success_id_response(
                StatusCode::CREATED,
                &trace_id,
                rule.id,
            )
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                error_response(
                    StatusCode::CONFLICT,
                    &trace_id,
                    "conflict",
                    "Rule name already exists",
                )
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
    request_body = UpdateAlertRuleRequest,
    responses(
        (status = 200, description = "告警规则已更新", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "规则不存在", body = crate::api::ApiError)
    )
)]
async fn update_alert_rule(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAlertRuleRequest>,
) -> impl IntoResponse {
    // 转换为存储层的更新类型
    let update = oxmon_storage::cert_store::AlertRuleUpdate {
        name: req.name,
        metric: req.metric,
        agent_pattern: req.agent_pattern,
        severity: req.severity,
        enabled: req.enabled,
        config_json: req.config_json,
        silence_secs: req.silence_secs,
    };

    match state.cert_store.update_alert_rule(&id, &update) {
        Ok(Some(rule)) => {
            if let Err(e) =
                crate::rule_builder::reload_alert_engine(&state.cert_store, &state.alert_engine)
            {
                tracing::error!(error = %e, "Failed to reload alert engine after rule update");
            }
            crate::api::success_id_response(
                StatusCode::OK,
                &trace_id,
                rule.id,
            )
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Rule not found",
        )
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
        (status = 200, description = "告警规则已删除", body = crate::api::IdResponse),
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
        Ok(true) => {
            if let Err(e) =
                crate::rule_builder::reload_alert_engine(&state.cert_store, &state.alert_engine)
            {
                tracing::error!(error = %e, "Failed to reload alert engine after rule deletion");
            }
            crate::api::success_id_response(StatusCode::OK, &trace_id, id)
        }
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Rule not found",
        )
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
        (status = 200, description = "告警规则状态已更新", body = crate::api::IdResponse),
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
        Ok(Some(rule)) => {
            if let Err(e) =
                crate::rule_builder::reload_alert_engine(&state.cert_store, &state.alert_engine)
            {
                tracing::error!(
                    error = %e,
                    "Failed to reload alert engine after rule enable/disable"
                );
            }
            crate::api::success_id_response(
                StatusCode::OK,
                &trace_id,
                rule.id,
            )
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Rule not found",
        )
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

// ---- Alert history ----

// GET /v1/alerts/history
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AlertHistoryQueryParams {
    /// Agent ID 精确匹配（agent_id__eq，可选）
    #[param(required = false)]
    #[serde(rename = "agent_id__eq")]
    agent_id_eq: Option<String>,
    /// 告警级别精确匹配（severity__eq,可选)
    #[param(required = false)]
    #[serde(rename = "severity__eq")]
    severity_eq: Option<String>,
    /// 时间下界（timestamp >=，默认为当前时间前 1 天）
    #[param(required = false)]
    #[serde(rename = "timestamp__gte")]
    timestamp_gte: Option<DateTime<Utc>>,
    /// 时间上界（timestamp <=，默认为当前时间）
    #[param(required = false)]
    #[serde(rename = "timestamp__lte")]
    timestamp_lte: Option<DateTime<Utc>>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "crate::api::pagination::deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "crate::api::pagination::deserialize_optional_u64")]
    offset: Option<u64>,
}

/// 告警事件
#[derive(Serialize, ToSchema)]
struct AlertEventResponse {
    /// 事件唯一标识
    id: String,
    /// 触发规则 ID
    rule_id: String,
    /// Agent 唯一标识
    agent_id: String,
    /// 指标名称
    metric_name: String,
    /// 告警级别
    severity: String,
    /// 告警消息
    message: String,
    /// 当前指标值
    value: f64,
    /// 告警阈值
    threshold: f64,
    /// 触发时间
    timestamp: DateTime<Utc>,
    /// 预测突破时间（趋势预测规则）
    predicted_breach: Option<DateTime<Utc>>,
    /// 状态：1=未处理, 2=已确认, 3=已处理
    status: u8,
}

/// 分页查询告警事件历史（支持按 agent_id__eq、severity__eq、时间范围过滤）。
/// 默认排序：`timestamp` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/alerts/history",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(AlertHistoryQueryParams),
    responses(
        (status = 200, description = "告警事件分页列表", body = Vec<AlertEventResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn alert_history(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<AlertHistoryQueryParams>,
) -> impl IntoResponse {
    let to = params.timestamp_lte.unwrap_or_else(Utc::now);
    let from = params
        .timestamp_gte
        .unwrap_or_else(|| to - chrono::Duration::days(1));
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    let total = match state.storage.count_alert_history(
        from,
        to,
        params.severity_eq.as_deref(),
        params.agent_id_eq.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count alert history");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response();
        }
    };

    match state.storage.query_alert_history(
        from,
        to,
        params.severity_eq.as_deref(),
        params.agent_id_eq.as_deref(),
        limit,
        offset,
    ) {
        Ok(events) => {
            let items: Vec<AlertEventResponse> = events
                .into_iter()
                .map(|e| AlertEventResponse {
                    id: e.id,
                    rule_id: e.rule_id,
                    agent_id: e.agent_id,
                    metric_name: e.metric_name,
                    severity: e.severity.to_string(),
                    message: e.message,
                    value: e.value,
                    threshold: e.threshold,
                    timestamp: e.timestamp,
                    predicted_breach: e.predicted_breach,
                    status: e.status,
                })
                .collect();
            success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response()
        }
    }
}

/// 获取单个告警事件详情（按 ID）。
#[utoipa::path(
    get,
    path = "/v1/alerts/history/{id}",
    params(
        ("id" = String, Path, description = "告警事件 ID")
    ),
    responses(
        (status = 200, description = "告警事件详情", body = AlertEventResponse),
        (status = 404, description = "告警事件不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Alerts"
)]
async fn get_alert_event(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_alert_event_by_id(&id) {
        Ok(Some(e)) => {
            let response = AlertEventResponse {
                id: e.id,
                rule_id: e.rule_id,
                agent_id: e.agent_id,
                metric_name: e.metric_name,
                severity: e.severity.to_string(),
                message: e.message,
                value: e.value,
                threshold: e.threshold,
                timestamp: e.timestamp,
                predicted_breach: e.predicted_breach,
                status: e.status,
            };
            success_response(StatusCode::OK, &trace_id, response)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Alert event not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get alert event");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
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
        (status = 200, description = "告警已确认", body = crate::api::IdResponse),
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
        Ok(true) => crate::api::success_id_response(StatusCode::OK, &trace_id, id),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Alert not found",
        )
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
        (status = 200, description = "告警已解决", body = crate::api::IdResponse),
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
        Ok(true) => crate::api::success_id_response(StatusCode::OK, &trace_id, id),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Alert not found",
        )
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

/// 活跃告警列表查询参数
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ActiveAlertsParams {
    /// Agent ID 模糊匹配
    #[param(required = false, rename = "agent_id__contains")]
    #[serde(rename = "agent_id__contains")]
    agent_id_contains: Option<String>,
    /// 告警级别精确匹配（info / warning / critical）
    #[param(required = false, rename = "severity__eq")]
    #[serde(rename = "severity__eq")]
    severity_eq: Option<String>,
    /// 规则 ID 精确匹配
    #[param(required = false, rename = "rule_id__eq")]
    #[serde(rename = "rule_id__eq")]
    rule_id_eq: Option<String>,
    /// 指标名称精确匹配
    #[param(required = false, rename = "metric_name__eq")]
    #[serde(rename = "metric_name__eq")]
    metric_name_eq: Option<String>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(
        default,
        deserialize_with = "crate::api::pagination::deserialize_optional_u64"
    )]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(
        default,
        deserialize_with = "crate::api::pagination::deserialize_optional_u64"
    )]
    offset: Option<u64>,
}

/// 查询当前活跃（未解决）告警。
#[utoipa::path(
    get,
    path = "/v1/alerts/active",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(ActiveAlertsParams),
    responses(
        (status = 200, description = "活跃告警列表"),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn active_alerts(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ActiveAlertsParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);
    let agent_id_contains = params.agent_id_contains.as_deref();
    let severity = params.severity_eq.as_deref();
    let rule_id = params.rule_id_eq.as_deref();
    let metric_name = params.metric_name_eq.as_deref();

    let total = match state.storage.count_active_alerts(agent_id_contains, severity, rule_id, metric_name) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count active alerts");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state
        .storage
        .query_active_alerts(agent_id_contains, severity, rule_id, metric_name, limit, offset)
    {
        Ok(events) => success_paginated_response(
            StatusCode::OK,
            &trace_id,
            events,
            total,
            limit,
            offset,
        ),
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
///
/// 可选查询参数 `hours`（默认 24）控制统计时间范围。
#[utoipa::path(
    get,
    path = "/v1/alerts/summary",
    tag = "Alerts",
    params(
        ("hours" = Option<u64>, Query, description = "统计时间范围（小时），默认 24")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "告警统计摘要"),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn alert_summary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let hours: u64 = params
        .get("hours")
        .and_then(|h| h.parse().ok())
        .unwrap_or(24);
    let to = Utc::now();
    let from = to - chrono::Duration::hours(hours as i64);
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
        .routes(routes!(list_alert_rules, create_alert_rule))
        .routes(routes!(get_alert_rule))
        .routes(routes!(alert_history))
        .routes(routes!(get_alert_event))
        .routes(routes!(update_alert_rule, delete_alert_rule))
        .routes(routes!(set_alert_rule_enabled))
        .routes(routes!(acknowledge_alert))
        .routes(routes!(resolve_alert))
        .routes(routes!(active_alerts))
        .routes(routes!(alert_summary))
}
