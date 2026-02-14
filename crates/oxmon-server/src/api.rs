pub mod alerts;
pub mod certificates;
pub mod dashboard;
pub mod dictionaries;
pub mod notifications;
pub mod pagination;
pub mod sys_configs;
pub mod system;
pub mod whitelist;

use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use oxmon_storage::StorageEngine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::pagination::PaginationParams;

/// API 错误响应
#[derive(Serialize, ToSchema)]
pub struct ApiError {
    /// 错误码
    pub err_code: i32,
    /// 错误信息
    pub err_msg: String,
    /// 链路追踪 ID（默认空字符串）
    pub trace_id: String,
}

/// API 统一响应包裹
#[derive(Serialize)]
pub struct ApiResponse<T>
where
    T: Serialize,
{
    /// 错误码（成功时为 0）
    pub err_code: i32,
    /// 错误信息（成功时为 success）
    pub err_msg: String,
    /// 链路追踪 ID（默认空字符串）
    pub trace_id: String,
    /// 业务数据（有数据时返回）
    pub data: Option<T>,
}

pub fn success_response<T>(status: StatusCode, trace_id: &str, data: T) -> Response
where
    T: Serialize,
{
    (
        status,
        Json(ApiResponse {
            err_code: 0,
            err_msg: "success".to_string(),
            trace_id: trace_id.to_string(),
            data: Some(data),
        }),
    )
        .into_response()
}

pub fn success_empty_response(status: StatusCode, trace_id: &str, msg: &str) -> Response {
    (
        status,
        Json(ApiResponse::<Value> {
            err_code: 0,
            err_msg: msg.to_string(),
            trace_id: trace_id.to_string(),
            data: None,
        }),
    )
        .into_response()
}

fn to_custom_error_code(code: &str) -> i32 {
    match code {
        "BAD_REQUEST" | "bad_request" => 1001,
        "UNAUTHORIZED" | "unauthorized" => 1002,
        "TOKEN_EXPIRED" | "token_expired" => 1003,
        "NOT_FOUND" | "not_found" => 1004,
        "CONFLICT" | "conflict" => 1005,
        "duplicate_domain" => 1101,
        "invalid_domain" => 1102,
        "invalid_port" => 1103,
        "empty_batch" => 1104,
        "no_results" => 1105,
        "disabled_system_config" => 1106,
        "invalid_system_config" => 1107,
        "storage_error" => 1501,
        "INTERNAL_ERROR" | "internal_error" => 1500,
        _ => 1999,
    }
}

pub fn error_response(status: StatusCode, trace_id: &str, code: &str, msg: &str) -> Response {
    (
        status,
        Json(ApiResponse::<Value> {
            err_code: to_custom_error_code(code),
            err_msg: msg.to_string(),
            trace_id: trace_id.to_string(),
            data: None,
        }),
    )
        .into_response()
}

/// 健康检查响应
#[derive(Serialize, ToSchema)]
struct HealthResponse {
    /// 服务版本号
    version: String,
    /// 运行时长（秒）
    uptime_secs: i64,
    /// 已注册 Agent 数量
    agent_count: usize,
    /// 存储状态
    storage_status: String,
}

/// 获取服务健康状态。
/// 鉴权：无需 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "Health",
    responses(
        (status = 200, description = "服务健康状态", body = HealthResponse)
    )
)]
async fn health(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let uptime = (Utc::now() - state.start_time).num_seconds();
    let agent_count = state
        .agent_registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .list_agents()
        .len();
    success_response(
        StatusCode::OK,
        &trace_id,
        HealthResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: uptime,
            agent_count,
            storage_status: "ok".to_string(),
        },
    )
}

/// Agent 信息
#[derive(Serialize, ToSchema)]
struct AgentResponse {
    /// 白名单条目 ID（仅白名单 agent 有值）
    id: Option<String>,
    /// Agent 唯一标识
    agent_id: String,
    /// 最后上报时间
    last_seen: Option<DateTime<Utc>>,
    /// 状态（active / inactive / unknown）
    status: String,
    /// 创建时间（仅白名单 agent 有值）
    created_at: Option<DateTime<Utc>>,
    /// 采集间隔（秒），仅白名单 agent 且配置了才有值
    collection_interval_secs: Option<u64>,
}

/// Agent 详细信息
#[derive(Serialize, ToSchema)]
struct AgentDetail {
    /// 数据库 ID
    id: String,
    /// Agent 唯一标识
    agent_id: String,
    /// 首次上报时间
    first_seen: DateTime<Utc>,
    /// 最后上报时间
    last_seen: DateTime<Utc>,
    /// 状态（active / inactive）
    status: String,
    /// 采集间隔（秒）
    collection_interval_secs: Option<u64>,
    /// 描述
    description: Option<String>,
    /// 创建时间
    created_at: DateTime<Utc>,
    /// 更新时间
    updated_at: DateTime<Utc>,
    /// 是否在白名单中
    in_whitelist: bool,
    /// 白名单条目 ID（如果在白名单中）
    whitelist_id: Option<String>,
}

/// 分页查询 Agent 列表。
/// 默认排序：`last_seen` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/agents",
    tag = "Agents",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "Agent 分页列表", body = Vec<AgentResponse>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn list_agents(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();

    // 从数据库查询 agent 列表
    let agents = match state.cert_store.list_agents_from_db(limit, offset).map_err(|e| {
        tracing::error!(error = %e, "Failed to list agents from database");
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &trace_id,
            "INTERNAL_ERROR",
            "Database error",
        )
    }) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let paginated_agents: Vec<AgentResponse> = agents
        .into_iter()
        .map(|agent_info| {
            // 尝试从白名单获取白名单特有的信息（id, created_at）
            let whitelist_entry = state
                .cert_store
                .get_agent_by_agent_id(&agent_info.agent_id)
                .ok()
                .flatten();

            // 计算 active 状态（collection_interval_secs 现在来自 agent_info）
            let collection_interval = agent_info
                .collection_interval_secs
                .unwrap_or(state.config.agent_collection_interval_secs);
            let timeout = chrono::Duration::seconds((collection_interval * 3) as i64);
            let now = Utc::now();
            let active = now - agent_info.last_seen < timeout;

            AgentResponse {
                id: whitelist_entry.as_ref().map(|e| e.id.clone()),
                agent_id: agent_info.agent_id,
                last_seen: Some(agent_info.last_seen),
                status: if active {
                    "active".to_string()
                } else {
                    "inactive".to_string()
                },
                created_at: whitelist_entry.as_ref().map(|e| e.created_at),
                collection_interval_secs: agent_info.collection_interval_secs,
            }
        })
        .collect();

    success_response(StatusCode::OK, &trace_id, paginated_agents)
}

/// 获取指定 Agent 的详细信息。
/// 支持通过 agent_id 或数据库 id 查询。
#[utoipa::path(
    get,
    path = "/v1/agents/{id}",
    tag = "Agents",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID 或数据库 ID")
    ),
    responses(
        (status = 200, description = "Agent 详细信息", body = AgentDetail),
        (status = 401, description = "未认证", body = ApiError),
        (status = 404, description = "Agent 不存在", body = ApiError)
    )
)]
async fn get_agent(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 先尝试按 agent_id 查询
    let agent_entry = match state.cert_store.get_agent_by_id_or_agent_id(&id).map_err(|e| {
        tracing::error!(error = %e, "Failed to query agent");
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &trace_id,
            "INTERNAL_ERROR",
            "Database error",
        )
    }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "NOT_FOUND",
                &format!("Agent '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    // 检查是否在白名单中
    let whitelist_entry = state
        .cert_store
        .get_agent_by_agent_id(&agent_entry.agent_id)
        .ok()
        .flatten();

    // 计算 active 状态
    let collection_interval = agent_entry
        .collection_interval_secs
        .unwrap_or(state.config.agent_collection_interval_secs);
    let timeout = chrono::Duration::seconds((collection_interval * 3) as i64);
    let now = Utc::now();
    let active = now - agent_entry.last_seen < timeout;

    success_response(
        StatusCode::OK,
        &trace_id,
        AgentDetail {
            id: agent_entry.id,
            agent_id: agent_entry.agent_id,
            first_seen: agent_entry.first_seen,
            last_seen: agent_entry.last_seen,
            status: if active {
                "active".to_string()
            } else {
                "inactive".to_string()
            },
            collection_interval_secs: agent_entry.collection_interval_secs,
            description: agent_entry.description,
            created_at: agent_entry.created_at,
            updated_at: agent_entry.updated_at,
            in_whitelist: whitelist_entry.is_some(),
            whitelist_id: whitelist_entry.map(|e| e.id),
        },
    )
}

/// 最新指标数据
#[derive(Serialize, ToSchema)]
struct LatestMetric {
    /// 指标名称
    metric_name: String,
    /// 指标值
    value: f64,
    /// 标签 (如 mount=/、interface=eth0、core=0)
    labels: HashMap<String, String>,
    /// 采集时间
    timestamp: DateTime<Utc>,
}

/// 获取指定 Agent 的最新指标数据。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/agents/{id}/latest",
    tag = "Agents",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID（agent.id）")
    ),
    responses(
        (status = 200, description = "Agent 最新指标数据", body = Vec<LatestMetric>),
        (status = 401, description = "未认证", body = ApiError),
        (status = 404, description = "Agent 不存在", body = ApiError)
    )
)]
async fn agent_latest(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 直接按 agent.id 查询最新一条指标，不区分是否在白名单。
    let from = DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_default();
    let to = Utc::now();
    let rows = match state
        .storage
        .query_metrics_paginated(from, to, Some(&id), None, 1, 0)
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(id = %id, error = %err, "failed to query latest metric");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Failed to query latest metric",
            )
            .into_response();
        }
    };

    if let Some(point) = rows.first() {
        return success_response(
            StatusCode::OK,
            &trace_id,
            vec![LatestMetric {
                metric_name: point.metric_name.clone(),
                value: point.value,
                labels: point.labels.clone(),
                timestamp: point.timestamp,
            }],
        );
    }

    error_response(
        StatusCode::NOT_FOUND,
        &trace_id,
        "not_found",
        "Agent not found",
    )
    .into_response()
}

// GET /v1/metrics
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MetricsQueryParams {
    /// Agent ID 精确匹配（agent_id__eq，可选）
    #[param(required = false)]
    #[serde(rename = "agent_id__eq")]
    agent_id_eq: Option<String>,
    /// 指标名称精确匹配（metric_name__eq，可选）
    #[param(required = false)]
    #[serde(rename = "metric_name__eq")]
    metric_name_eq: Option<String>,
    /// 时间下界（timestamp >=，默认为当前时间前 1 小时）
    #[param(required = false)]
    #[serde(rename = "timestamp__gte")]
    timestamp_gte: Option<DateTime<Utc>>,
    /// 时间上界（timestamp <=，默认为当前时间）
    #[param(required = false)]
    #[serde(rename = "timestamp__lte")]
    timestamp_lte: Option<DateTime<Utc>>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    offset: Option<u64>,
}

/// 指标数据点（完整）
#[derive(Serialize, ToSchema)]
struct MetricDataPointResponse {
    /// 指标唯一标识
    id: String,
    /// 采集时间
    timestamp: DateTime<Utc>,
    /// Agent 唯一标识
    agent_id: String,
    /// 指标名称
    metric_name: String,
    /// 指标值
    value: f64,
    /// 指标标签（如 mount=/、interface=eth0、core=0）
    labels: HashMap<String, String>,
    /// 创建时间
    created_at: DateTime<Utc>,
}

/// 分页查询指标数据点列表（支持按 agent_id__eq、metric_name__eq、时间范围过滤）。
/// 默认排序：`created_at` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/metrics",
    tag = "Metrics",
    security(("bearer_auth" = [])),
    params(MetricsQueryParams),
    responses(
        (status = 200, description = "指标数据点分页列表", body = Vec<MetricDataPointResponse>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn query_all_metrics(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<MetricsQueryParams>,
) -> impl IntoResponse {
    let to = params.timestamp_lte.unwrap_or_else(Utc::now);
    let from = params
        .timestamp_gte
        .unwrap_or_else(|| to - chrono::Duration::hours(1));
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    match state.storage.query_metrics_paginated(
        from,
        to,
        params.agent_id_eq.as_deref(),
        params.metric_name_eq.as_deref(),
        limit,
        offset,
    ) {
        Ok(points) => {
            let resp: Vec<MetricDataPointResponse> = points
                .into_iter()
                .map(|dp| MetricDataPointResponse {
                    id: dp.id,
                    timestamp: dp.timestamp,
                    agent_id: dp.agent_id,
                    metric_name: dp.metric_name,
                    value: dp.value,
                    labels: dp.labels,
                    created_at: dp.created_at,
                })
                .collect();
            success_response(StatusCode::OK, &trace_id, resp)
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

/// 告警规则信息
#[derive(Serialize, ToSchema)]
struct AlertRuleResponse {
    /// 规则唯一标识
    id: String,
    /// 规则名称
    name: String,
    /// 规则类型（threshold / rate_of_change / trend_prediction / cert_expiration）
    rule_type: String,
    /// 监控指标名称
    metric: String,
    /// Agent 匹配模式（支持 glob）
    agent_pattern: String,
    /// 告警级别
    severity: String,
    /// 是否启用
    enabled: bool,
}

/// 分页查询告警规则列表。
/// 默认排序：`id` 升序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/alerts/rules",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "告警规则分页列表", body = Vec<AlertRuleResponse>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn list_alert_rules(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    match state
        .cert_store
        .list_alert_rules(pagination.limit(), pagination.offset())
    {
        Ok(rules) => {
            let resp: Vec<AlertRuleResponse> = rules
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

// GET /v1/alerts/history
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AlertHistoryQueryParams {
    /// Agent ID 精确匹配（agent_id__eq，可选）
    #[param(required = false)]
    #[serde(rename = "agent_id__eq")]
    agent_id_eq: Option<String>,
    /// 告警级别精确匹配（severity__eq，可选）
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
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
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
        (status = 401, description = "未认证", body = ApiError)
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

    match state.storage.query_alert_history(
        from,
        to,
        params.severity_eq.as_deref(),
        params.agent_id_eq.as_deref(),
        limit,
        offset,
    ) {
        Ok(events) => {
            let resp: Vec<AlertEventResponse> = events
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
            success_response(StatusCode::OK, &trace_id, resp)
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

// ---- Metric discovery and summary endpoints ----

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MetricDiscoveryParams {
    /// 时间下界（默认前 24 小时）
    #[param(required = false)]
    #[serde(rename = "timestamp__gte")]
    timestamp_gte: Option<DateTime<Utc>>,
    /// 时间上界（默认当前时间）
    #[param(required = false)]
    #[serde(rename = "timestamp__lte")]
    timestamp_lte: Option<DateTime<Utc>>,
}

/// 获取时间范围内所有指标名称。
#[utoipa::path(
    get,
    path = "/v1/metrics/names",
    tag = "Metrics",
    security(("bearer_auth" = [])),
    params(MetricDiscoveryParams, PaginationParams),
    responses(
        (status = 200, description = "指标名称列表", body = Vec<String>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn metric_names(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<MetricDiscoveryParams>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let to = params.timestamp_lte.unwrap_or_else(Utc::now);
    let from = params
        .timestamp_gte
        .unwrap_or_else(|| to - chrono::Duration::days(1));
    match state.storage.query_distinct_metric_names(
        from,
        to,
        pagination.limit(),
        pagination.offset(),
    ) {
        Ok(names) => success_response(StatusCode::OK, &trace_id, names),
        Err(e) => {
            tracing::error!(error = %e, "Failed to query metric names");
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

/// 获取时间范围内所有上报 Agent ID。
#[utoipa::path(
    get,
    path = "/v1/metrics/agents",
    tag = "Metrics",
    security(("bearer_auth" = [])),
    params(MetricDiscoveryParams, PaginationParams),
    responses(
        (status = 200, description = "Agent ID 列表", body = Vec<String>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn metric_agents(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<MetricDiscoveryParams>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let to = params.timestamp_lte.unwrap_or_else(Utc::now);
    let from = params
        .timestamp_gte
        .unwrap_or_else(|| to - chrono::Duration::days(1));
    match state
        .storage
        .query_distinct_agent_ids(from, to, pagination.limit(), pagination.offset())
    {
        Ok(ids) => success_response(StatusCode::OK, &trace_id, ids),
        Err(e) => {
            tracing::error!(error = %e, "Failed to query agent ids");
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

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MetricSummaryParams {
    /// Agent ID（必填）
    #[param(required = true)]
    agent_id: String,
    /// 指标名称（必填）
    #[param(required = true)]
    metric_name: String,
    /// 时间下界（默认前 1 小时）
    #[param(required = false)]
    #[serde(rename = "timestamp__gte")]
    timestamp_gte: Option<DateTime<Utc>>,
    /// 时间上界（默认当前时间）
    #[param(required = false)]
    #[serde(rename = "timestamp__lte")]
    timestamp_lte: Option<DateTime<Utc>>,
}

/// 获取指标聚合统计（min/max/avg/count）。
#[utoipa::path(
    get,
    path = "/v1/metrics/summary",
    tag = "Metrics",
    security(("bearer_auth" = [])),
    params(MetricSummaryParams),
    responses(
        (status = 200, description = "指标聚合统计"),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn metric_summary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<MetricSummaryParams>,
) -> impl IntoResponse {
    let to = params.timestamp_lte.unwrap_or_else(Utc::now);
    let from = params
        .timestamp_gte
        .unwrap_or_else(|| to - chrono::Duration::hours(1));
    match state
        .storage
        .query_metric_summary(from, to, &params.agent_id, &params.metric_name)
    {
        Ok(summary) => success_response(StatusCode::OK, &trace_id, summary),
        Err(e) => {
            tracing::error!(error = %e, "Failed to query metric summary");
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

/// 证书健康摘要。
#[utoipa::path(
    get,
    path = "/v1/certs/summary",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "证书健康摘要"),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn cert_summary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.cert_store.cert_summary() {
        Ok(summary) => success_response(StatusCode::OK, &trace_id, summary),
        Err(e) => {
            tracing::error!(error = %e, "Failed to query cert summary");
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

// ---- Cert check history ----

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct CertHistoryParams {
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    offset: Option<u64>,
}

/// 获取指定域名的证书检查历史记录。
#[utoipa::path(
    get,
    path = "/v1/certs/domains/{id}/history",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "域名 ID"),
        CertHistoryParams,
    ),
    responses(
        (status = 200, description = "证书检查历史"),
        (status = 401, description = "未认证", body = ApiError),
        (status = 404, description = "域名不存在", body = ApiError)
    )
)]
async fn cert_check_history(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<CertHistoryParams>,
) -> impl IntoResponse {
    // Verify domain exists
    match state.cert_store.get_domain_by_id(&id) {
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Domain not found",
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response();
        }
        _ => {}
    }

    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    match state
        .cert_store
        .query_check_results_by_domain_id(&id, limit, offset)
    {
        Ok(results) => success_response(StatusCode::OK, &trace_id, results),
        Err(e) => {
            tracing::error!(error = %e, "Failed to query cert check history");
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

pub fn public_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(health))
}

pub fn auth_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(crate::auth::login))
}

pub fn protected_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(crate::auth::change_password))
        .routes(routes!(list_agents))
        .routes(routes!(get_agent))
        .routes(routes!(agent_latest))
        .routes(routes!(query_all_metrics))
        .routes(routes!(alert_history))
        .routes(routes!(metric_names))
        .routes(routes!(metric_agents))
        .routes(routes!(metric_summary))
        .routes(routes!(cert_summary))
        .routes(routes!(cert_check_history))
        .merge(whitelist::whitelist_routes())
        .merge(certificates::certificates_routes())
        .merge(alerts::alert_routes())
        .merge(notifications::notification_routes())
        .merge(dashboard::dashboard_routes())
        .merge(system::system_routes())
        .merge(dictionaries::dictionary_routes())
        .merge(sys_configs::sys_config_routes())
}
