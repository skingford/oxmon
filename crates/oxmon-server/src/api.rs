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
use oxmon_common::types::UpdateAgentRequest;
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

/// 分页数据结构
#[derive(Serialize, ToSchema)]
pub struct PaginatedData<T>
where
    T: Serialize,
{
    /// 数据项列表
    pub items: Vec<T>,
    /// 总数
    pub total: u64,
    /// 每页数量
    pub limit: usize,
    /// 偏移量
    pub offset: usize,
}

/// 变更操作响应（创建/更新/删除）
#[derive(Serialize, ToSchema)]
pub struct IdResponse {
    /// 资源 ID
    pub id: String,
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

pub fn success_paginated_response<T>(
    status: StatusCode,
    trace_id: &str,
    items: Vec<T>,
    total: u64,
    limit: usize,
    offset: usize,
) -> Response
where
    T: Serialize,
{
    success_response(
        status,
        trace_id,
        PaginatedData {
            items,
            total,
            limit,
            offset,
        },
    )
}

pub fn success_id_response(status: StatusCode, trace_id: &str, id: String) -> Response {
    success_response(status, trace_id, IdResponse { id })
}

fn to_custom_error_code(code: &str) -> i32 {
    match code {
        "bad_request" => 1001,
        "unauthorized" => 1002,
        "token_expired" => 1003,
        "not_found" => 1004,
        "conflict" => 1005,
        "app_id_missing" => 1008,
        "app_id_invalid" => 1009,
        "duplicate_domain" => 1101,
        "invalid_domain" => 1102,
        "invalid_port" => 1103,
        "empty_batch" => 1104,
        "no_results" => 1105,
        "disabled_system_config" => 1106,
        "invalid_system_config" => 1107,
        "storage_error" => 1501,
        "internal_error" => 1500,
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
/// 鉴权：无需 Bearer Token，但需要 ox-app-id 请求头（如果在配置中启用）。
#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "Health",
    security(("app_id_auth" = [])),
    responses(
        (status = 200, description = "服务健康状态", body = HealthResponse),
        (status = 403, description = "缺少或无效的 ox-app-id", body = ApiError)
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

/// Agent 列表查询参数
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AgentListQueryParams {
    /// Agent ID 包含匹配（agent_id__contains，可选）
    #[param(required = false)]
    #[serde(rename = "agent_id__contains")]
    agent_id_contains: Option<String>,
    /// 状态精确匹配（status__eq，可选，active/inactive）
    #[param(required = false)]
    #[serde(rename = "status__eq")]
    status_eq: Option<String>,
    /// 最后上报时间下界（last_seen__gte，可选，Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(rename = "last_seen__gte")]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    last_seen_gte: Option<u64>,
    /// 最后上报时间上界（last_seen__lte，可选，Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(rename = "last_seen__lte")]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    last_seen_lte: Option<u64>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "pagination::deserialize_optional_u64")]
    offset: Option<u64>,
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

/// 分页查询 Agent 列表（支持按 agent_id__contains、status__eq、last_seen__gte/lte 过滤）。
/// 默认排序：`last_seen` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/agents",
    tag = "Agents",
    security(("bearer_auth" = [])),
    params(AgentListQueryParams),
    responses(
        (status = 200, description = "Agent 分页列表", body = Vec<AgentResponse>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn list_agents(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<AgentListQueryParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    // 构建过滤条件
    let filter = oxmon_storage::AgentListFilter {
        agent_id_contains: params.agent_id_contains.clone(),
        status_eq: params.status_eq.clone(),
        last_seen_gte: params.last_seen_gte.and_then(|v| chrono::DateTime::from_timestamp(v as i64, 0)),
        last_seen_lte: params.last_seen_lte.and_then(|v| chrono::DateTime::from_timestamp(v as i64, 0)),
    };

    // 获取总数
    let total = match state
        .cert_store
        .count_agents_from_db_with_filter(&filter)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to count agents");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // 从数据库查询 agent 列表
    let agents = match state
        .cert_store
        .list_agents_from_db_with_filter(&filter, limit, offset)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list agents from database");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // 批量加载白名单 created_at，避免 N+1 查询
    let whitelist_map = state
        .cert_store
        .get_whitelist_created_at_map()
        .await
        .unwrap_or_default();

    let items: Vec<AgentResponse> = agents
        .into_iter()
        .map(|agent_info| {
            // 计算 active 状态（collection_interval_secs 现在来自 agent_info）
            let collection_interval = agent_info
                .collection_interval_secs
                .unwrap_or(state.config.agent_collection_interval_secs);
            let timeout = chrono::Duration::seconds((collection_interval * 3) as i64);
            let now = Utc::now();
            let active = now - agent_info.last_seen < timeout;

            let created_at = whitelist_map.get(&agent_info.agent_id).copied();

            AgentResponse {
                id: Some(agent_info.id),
                agent_id: agent_info.agent_id,
                last_seen: Some(agent_info.last_seen),
                status: if active {
                    "active".to_string()
                } else {
                    "inactive".to_string()
                },
                created_at,
                collection_interval_secs: agent_info.collection_interval_secs,
            }
        })
        .collect();

    success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
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
    let agent_entry = match state
        .cert_store
        .get_agent_by_id_or_agent_id(&id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query agent");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                &format!("Agent '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    // 检查是否在白名单中
    let whitelist_entry = state
        .cert_store
        .get_agent_by_agent_id(&agent_entry.agent_id)
        .await
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

/// 更新指定 Agent 的信息（描述、采集间隔）。
/// 支持通过 agent_id 或数据库 id 查询。如果 Agent 同时在白名单中，同步更新白名单。
#[utoipa::path(
    put,
    path = "/v1/agents/{id}",
    request_body = UpdateAgentRequest,
    tag = "Agents",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID 或数据库 ID")
    ),
    responses(
        (status = 200, description = "更新成功", body = IdResponse),
        (status = 401, description = "未认证", body = ApiError),
        (status = 404, description = "Agent 不存在", body = ApiError),
        (status = 500, description = "服务器错误", body = ApiError)
    )
)]
async fn update_agent_info(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> impl IntoResponse {
    // 查找 agent
    let agent_entry = match state
        .cert_store
        .get_agent_by_id_or_agent_id(&id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query agent");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                &format!("Agent '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    // 更新 agents 表
    if let Err(resp) = state
        .cert_store
        .update_agent_config(
            &agent_entry.agent_id,
            req.collection_interval_secs.map(Some),
            req.description.as_deref().map(Some),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update agent config");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        })
    {
        return resp;
    }

    // 如果 agent 在白名单中，同步更新白名单表
    if let Ok(Some(whitelist_entry)) = state
        .cert_store
        .get_agent_by_agent_id(&agent_entry.agent_id)
        .await
    {
        if let Err(e) = state
            .cert_store
            .update_agent_whitelist(&whitelist_entry.id, req.description.as_deref().map(Some))
            .await
        {
            tracing::warn!(error = %e, agent_id = %agent_entry.agent_id, "Failed to sync whitelist description");
        }
    }

    tracing::info!(id = %agent_entry.id, agent_id = %agent_entry.agent_id, "Agent info updated");

    success_id_response(StatusCode::OK, &trace_id, agent_entry.id)
}

/// 删除指定 Agent 记录。
/// 支持通过 agent_id 或数据库 id 查询。同时清理白名单和内存注册表。
#[utoipa::path(
    delete,
    path = "/v1/agents/{id}",
    tag = "Agents",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent ID 或数据库 ID")
    ),
    responses(
        (status = 200, description = "删除成功", body = IdResponse),
        (status = 401, description = "未认证", body = ApiError),
        (status = 404, description = "Agent 不存在", body = ApiError),
        (status = 500, description = "服务器错误", body = ApiError)
    )
)]
async fn delete_agent_record(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 查找 agent
    let agent_entry = match state
        .cert_store
        .get_agent_by_id_or_agent_id(&id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query agent");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                &format!("Agent '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    // 如果 agent 在白名单中，先删除白名单条目
    if let Ok(Some(whitelist_entry)) = state
        .cert_store
        .get_agent_by_agent_id(&agent_entry.agent_id)
        .await
    {
        if let Err(e) = state
            .cert_store
            .delete_agent_from_whitelist(&whitelist_entry.id)
            .await
        {
            tracing::warn!(error = %e, agent_id = %agent_entry.agent_id, "Failed to delete agent from whitelist");
        }
    }

    // 从 agents 表删除
    if let Err(resp) = state
        .cert_store
        .delete_agent_from_db(&agent_entry.id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to delete agent from database");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        })
    {
        return resp;
    }

    // 从内存注册表中移除
    state
        .agent_registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove_agent(&agent_entry.agent_id);

    tracing::info!(id = %agent_entry.id, agent_id = %agent_entry.agent_id, "Agent deleted");

    success_id_response(StatusCode::OK, &trace_id, agent_entry.id)
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
    // 先将数据库 id 解析为 agent_id，因为 metrics 按 agent_id 存储
    let agent_entry = match state
        .cert_store
        .get_agent_by_id_or_agent_id(&id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query agent");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                &format!("Agent '{}' not found", id),
            )
            .into_response()
        }
        Err(resp) => return resp.into_response(),
    };

    let to = Utc::now();
    let from = to - chrono::Duration::days(2);
    let rows = match state.storage.query_metrics_paginated(
        from,
        to,
        Some(&agent_entry.agent_id),
        None,
        1,
        0,
    ) {
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

    let total = match state.storage.count_metrics(
        from,
        to,
        params.agent_id_eq.as_deref(),
        params.metric_name_eq.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Count metrics failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response();
        }
    };

    match state.storage.query_metrics_paginated(
        from,
        to,
        params.agent_id_eq.as_deref(),
        params.metric_name_eq.as_deref(),
        limit,
        offset,
    ) {
        Ok(points) => {
            let items: Vec<MetricDataPointResponse> = points
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

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MetricSourceQueryParams {
    /// 最近时间下界（按 last_seen 过滤）
    #[param(required = false)]
    #[serde(rename = "timestamp__gte")]
    timestamp_gte: Option<DateTime<Utc>>,
    /// 最近时间上界（按 last_seen 过滤）
    #[param(required = false)]
    #[serde(rename = "timestamp__lte")]
    timestamp_lte: Option<DateTime<Utc>>,
    /// 数据来源过滤（agent / cloud，留空表示全部）
    #[param(required = false)]
    #[serde(rename = "source__eq")]
    source_eq: Option<String>,
    /// 模糊搜索关键字（匹配 agent_id / 云实例ID/名称/账号/地域等）
    #[param(required = false)]
    #[serde(rename = "query__contains")]
    query_contains: Option<String>,
    /// 云实例 provider 精确匹配（仅 cloud 来源生效）
    #[param(required = false)]
    #[serde(rename = "provider__eq")]
    provider_eq: Option<String>,
    /// 云实例 region 精确匹配（仅 cloud 来源生效）
    #[param(required = false)]
    #[serde(rename = "region__eq")]
    region_eq: Option<String>,
    /// 状态过滤：
    /// - agent: active / inactive
    /// - cloud: running / stopped / pending / error / unknown
    #[param(required = false)]
    #[serde(rename = "status__eq")]
    status_eq: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct MetricSourceItemResponse {
    /// 用于指标查询的主体 ID（agent: 原始 agent_id；cloud: cloud:{provider}:{instance_id}）
    id: String,
    /// 来源类型（agent / cloud）
    source: String,
    /// 展示名称
    display_name: String,
    /// 状态（agent: active/inactive；cloud: running/stopped/pending/error/unknown）
    status: String,
    /// provider（仅 cloud 有值）
    provider: Option<String>,
    /// region（仅 cloud 有值）
    region: Option<String>,
    /// cloud 原始实例 ID（仅 cloud 有值）
    instance_id: Option<String>,
    /// cloud 账号配置键（仅 cloud 有值）
    account_config_key: Option<String>,
    /// 最近时间（agent: last_seen；cloud: last_seen_at）
    last_seen: Option<DateTime<Utc>>,
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

    let total = match state.storage.count_distinct_metric_names(from, to) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count metric names");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response();
        }
    };

    match state.storage.query_distinct_metric_names(
        from,
        to,
        pagination.limit(),
        pagination.offset(),
    ) {
        Ok(names) => success_paginated_response(
            StatusCode::OK,
            &trace_id,
            names,
            total,
            pagination.limit(),
            pagination.offset(),
        ),
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

    let total = match state.storage.count_distinct_agent_ids(from, to) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count agent ids");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response();
        }
    };

    match state
        .storage
        .query_distinct_agent_ids(from, to, pagination.limit(), pagination.offset())
    {
        Ok(ids) => success_paginated_response(
            StatusCode::OK,
            &trace_id,
            ids,
            total,
            pagination.limit(),
            pagination.offset(),
        ),
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

fn normalize_cloud_status(value: Option<&str>) -> &'static str {
    match value.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "running" => "running",
        "stopped" | "stop" => "stopped",
        "pending" | "starting" | "stopping" => "pending",
        "error" | "failed" | "terminated" => "error",
        _ => "unknown",
    }
}

/// 获取可用于指标查询的数据来源（主动上报 Agent + 云实例）。
/// 支持分页、来源过滤和模糊搜索；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/metrics/sources",
    tag = "Metrics",
    security(("bearer_auth" = [])),
    params(MetricSourceQueryParams, PaginationParams),
    responses(
        (status = 200, description = "指标来源列表", body = Vec<MetricSourceItemResponse>),
        (status = 401, description = "未认证", body = ApiError)
    )
)]
async fn metric_sources(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<MetricSourceQueryParams>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();
    let source_filter = params
        .source_eq
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase());
    let status_filter = params
        .status_eq
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase());
    let include_agent = source_filter
        .as_deref()
        .map(|v| v == "agent")
        .unwrap_or(true);
    let include_cloud = source_filter
        .as_deref()
        .map(|v| v == "cloud")
        .unwrap_or(true);

    let keyword = params
        .query_contains
        .as_deref()
        .map(str::trim)
        .unwrap_or("");
    let keyword_lc = keyword.to_ascii_lowercase();
    let has_keyword = !keyword_lc.is_empty();
    let last_seen_gte_ts = params.timestamp_gte.map(|dt| dt.timestamp());
    let last_seen_lte_ts = params.timestamp_lte.map(|dt| dt.timestamp());

    let mut items: Vec<MetricSourceItemResponse> = Vec::new();

    if include_agent {
        let mut agent_filter = oxmon_storage::AgentListFilter::default();
        if has_keyword {
            agent_filter.agent_id_contains = Some(keyword.to_string());
        }
        agent_filter.last_seen_gte = last_seen_gte_ts.and_then(|v| chrono::DateTime::from_timestamp(v, 0));
        agent_filter.last_seen_lte = last_seen_lte_ts.and_then(|v| chrono::DateTime::from_timestamp(v, 0));

        let agents = match state
            .cert_store
            .list_agents_from_db_with_filter(&agent_filter, 10000, 0)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "Failed to list agents for metric sources");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "storage_error",
                    "Internal query error",
                )
                .into_response();
            }
        };

        for agent_info in agents {
            let collection_interval = agent_info
                .collection_interval_secs
                .unwrap_or(state.config.agent_collection_interval_secs);
            let timeout = chrono::Duration::seconds((collection_interval * 3) as i64);
            let active = Utc::now() - agent_info.last_seen < timeout;
            let status = if active { "active" } else { "inactive" };

            if let Some(ref wanted_status) = status_filter {
                if wanted_status != status {
                    continue;
                }
            }

            items.push(MetricSourceItemResponse {
                id: agent_info.agent_id.clone(),
                source: "agent".to_string(),
                display_name: agent_info.agent_id,
                status: status.to_string(),
                provider: None,
                region: None,
                instance_id: None,
                account_config_key: None,
                last_seen: Some(agent_info.last_seen),
            });
        }
    }

    if include_cloud {
        let cloud_rows = match state.cert_store.list_cloud_instances(
            params.provider_eq.as_deref(),
            params.region_eq.as_deref(),
            status_filter.as_deref(),
            if has_keyword { Some(keyword) } else { None },
            10000,
            0,
        ).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "Failed to list cloud instances for metric sources");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "storage_error",
                    "Internal query error",
                )
                .into_response();
            }
        };

        for row in cloud_rows {
            if let Some(gte) = last_seen_gte_ts {
                if row.last_seen_at < gte {
                    continue;
                }
            }
            if let Some(lte) = last_seen_lte_ts {
                if row.last_seen_at > lte {
                    continue;
                }
            }
            let normalized_status = normalize_cloud_status(row.status.as_deref()).to_string();
            let provider = row.provider.clone();
            let display_name = row
                .instance_name
                .clone()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| row.instance_id.clone());

            items.push(MetricSourceItemResponse {
                id: format!("cloud:{}:{}", provider, row.instance_id),
                source: "cloud".to_string(),
                display_name,
                status: normalized_status,
                provider: Some(provider),
                region: Some(row.region),
                instance_id: Some(row.instance_id),
                account_config_key: Some(row.account_config_key),
                last_seen: DateTime::from_timestamp(row.last_seen_at, 0),
            });
        }
    }

    items.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.id.cmp(&b.id)));

    let total = items.len() as u64;
    let paged_items: Vec<MetricSourceItemResponse> =
        items.into_iter().skip(offset).take(limit).collect();

    success_paginated_response(StatusCode::OK, &trace_id, paged_items, total, limit, offset)
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

pub fn public_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(health))
}

pub fn auth_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(crate::auth::login))
        .routes(routes!(crate::auth::get_public_key))
}

pub fn protected_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(crate::auth::change_password))
        .routes(routes!(list_agents))
        .routes(routes!(get_agent, update_agent_info, delete_agent_record))
        .routes(routes!(agent_latest))
        .routes(routes!(query_all_metrics))
        .routes(routes!(metric_names))
        .routes(routes!(metric_agents))
        .routes(routes!(metric_sources))
        .routes(routes!(metric_summary))
        .merge(whitelist::whitelist_routes())
        .merge(certificates::certificates_routes())
        .merge(alerts::alert_routes())
        .merge(notifications::notification_routes())
        .merge(dashboard::dashboard_routes())
        .merge(system::system_routes())
        .merge(dictionaries::dictionary_routes())
        .merge(sys_configs::sys_config_routes())
        .merge(crate::cloud::cloud_routes())
}
