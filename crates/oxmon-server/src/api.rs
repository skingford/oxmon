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

#[derive(Serialize, ToSchema)]
pub(crate) struct ApiError {
    error: String,
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

// GET /v1/health
#[derive(Serialize, ToSchema)]
struct HealthResponse {
    version: String,
    uptime_secs: i64,
    agent_count: usize,
    storage_status: String,
}

/// Get server health status
#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "Health",
    responses(
        (status = 200, description = "Server health info", body = HealthResponse)
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

// GET /v1/agents
#[derive(Serialize, ToSchema)]
struct AgentResponse {
    agent_id: String,
    last_seen: DateTime<Utc>,
    status: String,
}

/// List all registered agents
#[utoipa::path(
    get,
    path = "/v1/agents",
    tag = "Agents",
    responses(
        (status = 200, description = "List of agents", body = Vec<AgentResponse>)
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

// GET /v1/agents/:id/latest
#[derive(Serialize, ToSchema)]
struct LatestMetric {
    metric_name: String,
    value: f64,
    timestamp: DateTime<Utc>,
}

/// Get latest metrics for an agent
#[utoipa::path(
    get,
    path = "/v1/agents/{id}/latest",
    tag = "Agents",
    params(
        ("id" = String, Path, description = "Agent ID")
    ),
    responses(
        (status = 200, description = "Latest metric values", body = Vec<LatestMetric>),
        (status = 404, description = "Agent not found", body = ApiError)
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
    /// Agent ID
    #[param(required = false)]
    agent: Option<String>,
    /// Metric name (e.g., cpu.usage, memory.used_percent)
    #[param(required = false)]
    metric: Option<String>,
    /// Start time (defaults to 1 hour before `to`)
    #[param(required = false)]
    from: Option<DateTime<Utc>>,
    /// End time (defaults to now)
    #[param(required = false)]
    to: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
struct MetricPointResponse {
    timestamp: DateTime<Utc>,
    value: f64,
}

/// Query metric time series data
#[utoipa::path(
    get,
    path = "/v1/metrics",
    tag = "Metrics",
    params(MetricQueryParams),
    responses(
        (status = 200, description = "Metric data points", body = Vec<MetricPointResponse>),
        (status = 400, description = "Bad request", body = ApiError)
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

// GET /v1/alerts/rules
#[derive(Serialize, ToSchema)]
struct AlertRuleResponse {
    id: String,
    metric: String,
    agent_pattern: String,
    severity: String,
}

/// List all alert rules
#[utoipa::path(
    get,
    path = "/v1/alerts/rules",
    tag = "Alerts",
    responses(
        (status = 200, description = "List of alert rules", body = Vec<AlertRuleResponse>)
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
    /// Start time (defaults to 1 day ago)
    #[param(required = false)]
    from: Option<DateTime<Utc>>,
    /// End time (defaults to now)
    #[param(required = false)]
    to: Option<DateTime<Utc>>,
    /// Filter by severity
    #[param(required = false)]
    severity: Option<String>,
    /// Filter by agent ID
    #[param(required = false)]
    agent: Option<String>,
    /// Results per page (default: 10)
    #[param(required = false)]
    limit: Option<u64>,
    /// Pagination offset (default: 0)
    #[param(required = false)]
    offset: Option<u64>,
}

#[derive(Serialize, ToSchema)]
struct AlertEventResponse {
    id: String,
    rule_id: String,
    agent_id: String,
    metric_name: String,
    severity: String,
    message: String,
    value: f64,
    threshold: f64,
    timestamp: DateTime<Utc>,
    predicted_breach: Option<DateTime<Utc>>,
}

/// Query alert event history
#[utoipa::path(
    get,
    path = "/v1/alerts/history",
    tag = "Alerts",
    params(AlertHistoryParams),
    responses(
        (status = 200, description = "Alert events", body = Vec<AlertEventResponse>)
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