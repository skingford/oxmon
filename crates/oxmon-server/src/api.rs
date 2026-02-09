pub mod certificates;
pub mod pagination;
pub mod whitelist;

use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use oxmon_common::types::MetricDataPoint;
use oxmon_storage::{MetricQuery, StorageEngine};
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

pub fn success_response<T>(status: StatusCode, data: T) -> Response
where
    T: Serialize,
{
    (
        status,
        Json(ApiResponse {
            err_code: 0,
            err_msg: "success".to_string(),
            trace_id: String::new(),
            data: Some(data),
        }),
    )
        .into_response()
}

pub fn success_empty_response(status: StatusCode, msg: &str) -> Response {
    (
        status,
        Json(ApiResponse::<Value> {
            err_code: 0,
            err_msg: msg.to_string(),
            trace_id: String::new(),
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
        "storage_error" => 1501,
        "INTERNAL_ERROR" | "internal_error" => 1500,
        _ => 1999,
    }
}

pub fn error_response(status: StatusCode, code: &str, msg: &str) -> Response {
    (
        status,
        Json(ApiResponse::<Value> {
            err_code: to_custom_error_code(code),
            err_msg: msg.to_string(),
            trace_id: String::new(),
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
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = (Utc::now() - state.start_time).num_seconds();
    let agent_count = state.agent_registry.lock().unwrap().list_agents().len();
    success_response(
        StatusCode::OK,
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
    /// Agent 唯一标识
    agent_id: String,
    /// 最后上报时间
    last_seen: DateTime<Utc>,
    /// 状态（active / inactive）
    status: String,
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
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();

    let mut agents = state.agent_registry.lock().unwrap().list_agents();
    agents.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

    let resp: Vec<AgentResponse> = agents
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|a| AgentResponse {
            agent_id: a.agent_id,
            last_seen: a.last_seen,
            status: if a.active {
                "active".to_string()
            } else {
                "inactive".to_string()
            },
        })
        .collect();
    success_response(StatusCode::OK, resp)
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
        ("id" = String, Path, description = "Agent ID（路径参数）")
    ),
    responses(
        (status = 200, description = "Agent 最新指标数据", body = Vec<LatestMetric>),
        (status = 401, description = "未认证", body = ApiError),
        (status = 404, description = "Agent 不存在", body = ApiError)
    )
)]
async fn agent_latest(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    // Query last 5 minutes of data to get latest values
    let to = Utc::now();
    let from = to - chrono::Duration::minutes(5);

    // All metric names collected by agent
    let metric_names = [
        // CPU
        "cpu.usage",      // CPU 总使用率 (%)
        "cpu.core_usage", // 每核 CPU 使用率 (%, label: core)
        // Memory
        "memory.total",        // 总物理内存 (bytes)
        "memory.used",         // 已用内存 (bytes)
        "memory.available",    // 可用内存 (bytes)
        "memory.used_percent", // 内存使用率 (%)
        "memory.swap_total",   // 交换区总量 (bytes)
        "memory.swap_used",    // 交换区已用 (bytes)
        "memory.swap_percent", // 交换区使用率 (%)
        // Disk (per mount point, label: mount)
        "disk.total",        // 磁盘总空间 (bytes)
        "disk.used",         // 磁盘已用 (bytes)
        "disk.available",    // 磁盘可用 (bytes)
        "disk.used_percent", // 磁盘使用率 (%)
        // Network (per interface, label: interface)
        "network.bytes_recv",   // 接收字节增量
        "network.bytes_sent",   // 发送字节增量
        "network.packets_recv", // 接收包增量
        "network.packets_sent", // 发送包增量
        // System load
        "system.load_1",  // 1 分钟负载
        "system.load_5",  // 5 分钟负载
        "system.load_15", // 15 分钟负载
        "system.uptime",  // 运行时间 (秒)
    ];

    let mut latest: Vec<LatestMetric> = Vec::new();
    for metric_name in &metric_names {
        let query = MetricQuery {
            agent_id: agent_id.clone(),
            metric_name: metric_name.to_string(),
            from,
            to,
        };
        if let Ok(points) = state.storage.query(&query) {
            // Group by labels to return latest value per (metric_name, labels) combination
            // e.g. disk.used_percent for mount=/ and mount=/data separately
            let mut seen: HashMap<String, &MetricDataPoint> = HashMap::new();
            for point in &points {
                let label_key = format!("{:?}", point.labels);
                seen.entry(label_key)
                    .and_modify(|existing| {
                        if point.timestamp > existing.timestamp {
                            *existing = point;
                        }
                    })
                    .or_insert(point);
            }
            for point in seen.values() {
                latest.push(LatestMetric {
                    metric_name: point.metric_name.clone(),
                    value: point.value,
                    labels: point.labels.clone(),
                    timestamp: point.timestamp,
                });
            }
        }
    }

    if latest.is_empty() {
        // Check if agent exists in whitelist or registry
        let in_registry = state
            .agent_registry
            .lock()
            .unwrap()
            .get_agent(&agent_id)
            .is_some();
        let in_whitelist = state
            .cert_store
            .get_agent_token_hash(&agent_id)
            .unwrap_or(None)
            .is_some();
        if !in_registry && !in_whitelist {
            return error_response(StatusCode::NOT_FOUND, "not_found", "Agent not found")
                .into_response();
        }
    }

    success_response(StatusCode::OK, latest)
}

// GET /v1/metrics
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MetricsFilterParams {
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
}

#[derive(Deserialize)]
struct MetricsPageParams {
    #[serde(flatten)]
    filter: MetricsFilterParams,
    #[serde(flatten)]
    pagination: PaginationParams,
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
    params(MetricsFilterParams, PaginationParams),
    responses(
        (status = 200, description = "指标数据点分页列表", body = Vec<MetricDataPointResponse>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn query_all_metrics(
    State(state): State<AppState>,
    Query(params): Query<MetricsPageParams>,
) -> impl IntoResponse {
    let to = params.filter.timestamp_lte.unwrap_or_else(Utc::now);
    let from = params
        .filter
        .timestamp_gte
        .unwrap_or_else(|| to - chrono::Duration::hours(1));
    let limit = params.pagination.limit();
    let offset = params.pagination.offset();

    match state.storage.query_metrics_paginated(
        from,
        to,
        params.filter.agent_id_eq.as_deref(),
        params.filter.metric_name_eq.as_deref(),
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
            success_response(StatusCode::OK, resp)
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Query failed: {e}"),
        )
        .into_response(),
    }
}

/// 告警规则信息
#[derive(Serialize, ToSchema)]
struct AlertRuleResponse {
    /// 规则唯一标识
    id: String,
    /// 监控指标名称
    metric: String,
    /// Agent 匹配模式（支持 glob）
    agent_pattern: String,
    /// 告警级别
    severity: String,
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
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();

    let engine = state.alert_engine.lock().unwrap();
    let mut rules: Vec<AlertRuleResponse> = engine
        .rules()
        .iter()
        .map(|r| AlertRuleResponse {
            id: r.id().to_string(),
            metric: r.metric().to_string(),
            agent_pattern: r.agent_pattern().to_string(),
            severity: r.severity().to_string(),
        })
        .collect();

    rules.sort_by(|a, b| a.id.cmp(&b.id));
    let rules: Vec<AlertRuleResponse> = rules.into_iter().skip(offset).take(limit).collect();

    success_response(StatusCode::OK, rules)
}

// GET /v1/alerts/history
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AlertHistoryFilterParams {
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
}

#[derive(Deserialize)]
struct AlertHistoryPageParams {
    #[serde(flatten)]
    filter: AlertHistoryFilterParams,
    #[serde(flatten)]
    pagination: PaginationParams,
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
}

/// 分页查询告警事件历史（支持按 agent_id__eq、severity__eq、时间范围过滤）。
/// 默认排序：`timestamp` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/alerts/history",
    tag = "Alerts",
    security(("bearer_auth" = [])),
    params(AlertHistoryFilterParams, PaginationParams),
    responses(
        (status = 200, description = "告警事件分页列表", body = Vec<AlertEventResponse>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn alert_history(
    State(state): State<AppState>,
    Query(params): Query<AlertHistoryPageParams>,
) -> impl IntoResponse {
    let to = params.filter.timestamp_lte.unwrap_or_else(Utc::now);
    let from = params
        .filter
        .timestamp_gte
        .unwrap_or_else(|| to - chrono::Duration::days(1));
    let limit = params.pagination.limit();
    let offset = params.pagination.offset();

    match state.storage.query_alert_history(
        from,
        to,
        params.filter.severity_eq.as_deref(),
        params.filter.agent_id_eq.as_deref(),
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
                })
                .collect();
            success_response(StatusCode::OK, resp)
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Query failed: {e}"),
        )
        .into_response(),
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
        .routes(routes!(agent_latest))
        .routes(routes!(query_all_metrics))
        .routes(routes!(list_alert_rules))
        .routes(routes!(alert_history))
        .merge(whitelist::whitelist_routes())
        .merge(certificates::certificates_routes())
}
