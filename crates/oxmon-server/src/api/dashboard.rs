use crate::api::success_response;
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use oxmon_storage::StorageEngine;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 仪表盘概览数据
#[derive(Serialize, ToSchema)]
struct DashboardOverview {
    /// 活跃 Agent 数量
    active_agents: usize,
    /// 已注册 Agent 总数
    total_agents: usize,
    /// 24 小时内告警总数
    alerts_24h: u64,
    /// 告警按级别统计
    alerts_by_severity: std::collections::HashMap<String, u64>,
    /// 证书健康摘要
    cert_summary: CertSummary,
    /// 存储分区数量
    partition_count: usize,
    /// 存储总大小（字节）
    storage_total_bytes: u64,
    /// 服务运行时长（秒）
    uptime_secs: i64,
}

#[derive(Serialize, ToSchema)]
struct CertSummary {
    total_domains: u64,
    valid: u64,
    invalid: u64,
    expiring_soon: u64,
}

/// 获取仪表盘概览数据。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/dashboard/overview",
    tag = "Dashboard",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "仪表盘概览", body = DashboardOverview),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn dashboard_overview(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let registry = state
        .agent_registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let agents = registry.list_agents();
    let active_agents = agents.iter().filter(|a| a.active).count();
    let total_agents = agents.len();
    drop(registry);

    // Alert summary for last 24h
    let to = Utc::now();
    let from = to - chrono::Duration::days(1);
    let (alerts_24h, alerts_by_severity) = match state.storage.query_alert_summary(from, to) {
        Ok(summary) => (summary.total, summary.by_severity),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get alert summary for dashboard");
            (0, std::collections::HashMap::new())
        }
    };

    // Cert summary
    let cert_summary = match state.cert_store.cert_summary() {
        Ok(s) => CertSummary {
            total_domains: s.total_domains,
            valid: s.valid,
            invalid: s.invalid,
            expiring_soon: s.expiring_soon,
        },
        Err(e) => {
            tracing::error!(error = %e, "Failed to get cert summary for dashboard");
            CertSummary {
                total_domains: 0,
                valid: 0,
                invalid: 0,
                expiring_soon: 0,
            }
        }
    };

    // Storage info
    let (partition_count, storage_total_bytes) = match state.storage.list_partitions() {
        Ok(partitions) => {
            let count = partitions.len();
            let total: u64 = partitions.iter().map(|p| p.size_bytes).sum();
            (count, total)
        }
        Err(_) => (0, 0),
    };

    let uptime = (Utc::now() - state.start_time).num_seconds();

    success_response(
        StatusCode::OK,
        &trace_id,
        DashboardOverview {
            active_agents,
            total_agents,
            alerts_24h,
            alerts_by_severity,
            cert_summary,
            partition_count,
            storage_total_bytes,
            uptime_secs: uptime,
        },
    )
}

pub fn dashboard_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(dashboard_overview))
}
