use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use oxmon_storage::{MetricQuery, StorageEngine};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// API 错误响应
#[derive(Serialize, ToSchema)]
pub(crate) struct ApiError {
    /// 错误信息
    error: String,
    /// 错误码
    code: String,
}

fn error_response(status: StatusCode, code: &str, msg: &str) -> impl IntoResponse {
    (
        status,
        Json(ApiError {
            error: msg.to_string(),
            code: code.to_string(),
        }),
    )
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

/// 获取服务健康状态
#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "Health",
    responses(
        (status = 200, description = "服务健康信息", body = HealthResponse)
    )
)]
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = (Utc::now() - state.start_time).num_seconds();
    let agent_count = state.agent_registry.lock().unwrap().list_agents().len();
    Json(HealthResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: uptime,
        agent_count,
        storage_status: "ok".to_string(),
    })
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

/// 获取所有已注册 Agent 列表
#[utoipa::path(
    get,
    path = "/v1/agents",
    tag = "Agents",
    responses(
        (status = 200, description = "Agent 列表", body = Vec<AgentResponse>)
    )
)]
async fn list_agents(State(state): State<AppState>) -> impl IntoResponse {
    let agents = state.agent_registry.lock().unwrap().list_agents();
    let resp: Vec<AgentResponse> = agents
        .into_iter()
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
    Json(resp)
}

/// 最新指标数据
#[derive(Serialize, ToSchema)]
struct LatestMetric {
    /// 指标名称
    metric_name: String,
    /// 指标值
    value: f64,
    /// 采集时间
    timestamp: DateTime<Utc>,
}

/// 获取指定 Agent 的最新指标
#[utoipa::path(
    get,
    path = "/v1/agents/{id}/latest",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Agent 唯一标识")
    ),
    responses(
        (status = 200, description = "最新指标列表", body = Vec<LatestMetric>),
        (status = 404, description = "Agent 不存在", body = ApiError)
    )
)]
async fn agent_latest(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    let registry = state.agent_registry.lock().unwrap();
    if registry.get_agent(&agent_id).is_none() {
        return error_response(StatusCode::NOT_FOUND, "not_found", "Agent not found")
            .into_response();
    }
    drop(registry);

    // Query last 5 minutes of data to get latest values
    let to = Utc::now();
    let from = to - chrono::Duration::minutes(5);

    // Get common metric names and query each
    let metric_names = [
        "cpu.usage",
        "memory.used_percent",
        "disk.used_percent",
        "system.load_1",
        "system.load_5",
        "system.load_15",
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
            if let Some(last) = points.last() {
                latest.push(LatestMetric {
                    metric_name: last.metric_name.clone(),
                    value: last.value,
                    timestamp: last.timestamp,
                });
            }
        }
    }

    Json(latest).into_response()
}

// GET /v1/metrics
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MetricQueryParams {
    /// Agent 唯一标识
    #[param(required = false)]
    agent: Option<String>,
    /// 指标名称（如 cpu.usage、memory.used_percent）
    #[param(required = false)]
    metric: Option<String>,
    /// 起始时间（默认为结束时间前 1 小时）
    #[param(required = false)]
    from: Option<DateTime<Utc>>,
    /// 结束时间（默认为当前时间）
    #[param(required = false)]
    to: Option<DateTime<Utc>>,
}

/// 指标数据点
#[derive(Serialize, ToSchema)]
struct MetricPointResponse {
    /// 采集时间
    timestamp: DateTime<Utc>,
    /// 指标值
    value: f64,
}

/// 查询指标时序数据
#[utoipa::path(
    get,
    path = "/v1/metrics",
    tag = "Metrics",
    params(MetricQueryParams),
    responses(
        (status = 200, description = "指标数据点列表", body = Vec<MetricPointResponse>),
        (status = 400, description = "请求参数错误", body = ApiError)
    )
)]
async fn query_metrics(
    State(state): State<AppState>,
    Query(params): Query<MetricQueryParams>,
) -> impl IntoResponse {
    let agent = match params.agent {
        Some(a) => a,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "Missing required parameter: agent",
            )
            .into_response()
        }
    };
    let metric = match params.metric {
        Some(m) => m,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "missing_param",
                "Missing required parameter: metric",
            )
            .into_response()
        }
    };

    let to = params.to.unwrap_or_else(Utc::now);
    let from = params
        .from
        .unwrap_or_else(|| to - chrono::Duration::hours(1));

    let query = MetricQuery {
        agent_id: agent,
        metric_name: metric,
        from,
        to,
    };

    match state.storage.query(&query) {
        Ok(points) => {
            let resp: Vec<MetricPointResponse> = points
                .into_iter()
                .map(|dp| MetricPointResponse {
                    timestamp: dp.timestamp,
                    value: dp.value,
                })
                .collect();
            Json(resp).into_response()
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

/// 获取所有告警规则
#[utoipa::path(
    get,
    path = "/v1/alerts/rules",
    tag = "Alerts",
    responses(
        (status = 200, description = "告警规则列表", body = Vec<AlertRuleResponse>)
    )
)]
async fn list_alert_rules(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state.alert_engine.lock().unwrap();
    let rules: Vec<AlertRuleResponse> = engine
        .rules()
        .iter()
        .map(|r| AlertRuleResponse {
            id: r.id().to_string(),
            metric: r.metric().to_string(),
            agent_pattern: r.agent_pattern().to_string(),
            severity: r.severity().to_string(),
        })
        .collect();
    Json(rules)
}

// GET /v1/alerts/history
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AlertHistoryParams {
    /// 起始时间（默认为 1 天前）
    #[param(required = false)]
    from: Option<DateTime<Utc>>,
    /// 结束时间（默认为当前时间）
    #[param(required = false)]
    to: Option<DateTime<Utc>>,
    /// 按告警级别过滤
    #[param(required = false)]
    severity: Option<String>,
    /// 按 Agent ID 过滤
    #[param(required = false)]
    agent: Option<String>,
    /// 每页条数（默认 10）
    #[param(required = false)]
    limit: Option<u64>,
    /// 分页偏移量（默认 0）
    #[param(required = false)]
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
}

/// 查询告警事件历史
#[utoipa::path(
    get,
    path = "/v1/alerts/history",
    tag = "Alerts",
    params(AlertHistoryParams),
    responses(
        (status = 200, description = "告警事件列表", body = Vec<AlertEventResponse>)
    )
)]
async fn alert_history(
    State(state): State<AppState>,
    Query(params): Query<AlertHistoryParams>,
) -> impl IntoResponse {
    let to = params.to.unwrap_or_else(Utc::now);
    let from = params
        .from
        .unwrap_or_else(|| to - chrono::Duration::days(1));
    let limit = params.limit.unwrap_or(10) as usize;
    let offset = params.offset.unwrap_or(0) as usize;

    match state.storage.query_alert_history(
        from,
        to,
        params.severity.as_deref(),
        params.agent.as_deref(),
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
            Json(resp).into_response()
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Query failed: {e}"),
        )
        .into_response(),
    }
}

pub fn api_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(health))
        .routes(routes!(list_agents))
        .routes(routes!(agent_latest))
        .routes(routes!(query_metrics))
        .routes(routes!(list_alert_rules))
        .routes(routes!(alert_history))
}