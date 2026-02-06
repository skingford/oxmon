use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use oxmon_storage::{MetricQuery, StorageEngine};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ApiError {
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

// GET /api/v1/health
#[derive(Serialize)]
struct HealthResponse {
    version: String,
    uptime_secs: i64,
    agent_count: usize,
    storage_status: String,
}

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

// GET /api/v1/agents
#[derive(Serialize)]
struct AgentResponse {
    agent_id: String,
    last_seen: DateTime<Utc>,
    status: String,
}

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

// GET /api/v1/agents/:id/latest
#[derive(Serialize)]
struct LatestMetric {
    metric_name: String,
    value: f64,
    timestamp: DateTime<Utc>,
}

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

// GET /api/v1/metrics
#[derive(Deserialize)]
struct MetricQueryParams {
    agent: Option<String>,
    metric: Option<String>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct MetricPointResponse {
    timestamp: DateTime<Utc>,
    value: f64,
}

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

// GET /api/v1/alerts/rules
#[derive(Serialize)]
struct AlertRuleResponse {
    id: String,
    metric: String,
    agent_pattern: String,
    severity: String,
}

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

// GET /api/v1/alerts/history
#[derive(Deserialize)]
struct AlertHistoryParams {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    severity: Option<String>,
    agent: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Serialize)]
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

async fn alert_history(
    State(state): State<AppState>,
    Query(params): Query<AlertHistoryParams>,
) -> impl IntoResponse {
    let to = params.to.unwrap_or_else(Utc::now);
    let from = params
        .from
        .unwrap_or_else(|| to - chrono::Duration::days(1));
    let limit = params.limit.unwrap_or(100);
    let offset = params.offset.unwrap_or(0);

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

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/:id/latest", get(agent_latest))
        .route("/api/v1/metrics", get(query_metrics))
        .route("/api/v1/alerts/rules", get(list_alert_rules))
        .route("/api/v1/alerts/history", get(alert_history))
        .with_state(state)
}
