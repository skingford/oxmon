use crate::api::{error_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use oxmon_storage::StorageEngine;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 脱敏的运行时配置
#[derive(Serialize, ToSchema)]
struct RuntimeConfig {
    grpc_port: u16,
    http_port: u16,
    data_dir: String,
    retention_days: u32,
    require_agent_auth: bool,
    cert_check_enabled: bool,
    cert_check_default_interval_secs: u64,
    cert_check_tick_secs: u64,
    cert_check_max_concurrent: usize,
    notification_aggregation_window_secs: u64,
    alert_rules_count: usize,
    notification_channels_count: usize,
}

/// 获取运行时配置（敏感字段已脱敏）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/system/config",
    tag = "System",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "运行时配置", body = RuntimeConfig),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn get_system_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let config = &state.config;
    let notification_aggregation_window_secs = state
        .cert_store
        .get_runtime_setting_u64("notification_aggregation_window", 60);
    success_response(
        StatusCode::OK,
        &trace_id,
        RuntimeConfig {
            grpc_port: config.grpc_port,
            http_port: config.http_port,
            data_dir: config.data_dir.clone(),
            retention_days: config.retention_days,
            require_agent_auth: config.require_agent_auth,
            cert_check_enabled: config.cert_check.enabled,
            cert_check_default_interval_secs: config.cert_check.default_interval_secs,
            cert_check_tick_secs: config.cert_check.tick_secs,
            cert_check_max_concurrent: config.cert_check.max_concurrent,
            notification_aggregation_window_secs,
            alert_rules_count: state.cert_store.count_alert_rules().unwrap_or(0) as usize,
            notification_channels_count: state.cert_store.count_notification_channels().unwrap_or(0)
                as usize,
        },
    )
}

/// 存储分区信息
#[derive(Serialize, ToSchema)]
struct StorageInfo {
    /// 分区列表
    partitions: Vec<PartitionDetail>,
    /// 分区总数
    total_partitions: usize,
    /// 总存储大小（字节）
    total_size_bytes: u64,
}

#[derive(Serialize, ToSchema)]
struct PartitionDetail {
    date: String,
    size_bytes: u64,
}

/// 获取存储分区信息。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/system/storage",
    tag = "System",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "存储分区信息", body = StorageInfo),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn get_storage_info(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.storage.list_partitions() {
        Ok(partitions) => {
            let total_size_bytes: u64 = partitions.iter().map(|p| p.size_bytes).sum();
            let total_partitions = partitions.len();
            let details: Vec<PartitionDetail> = partitions
                .into_iter()
                .map(|p| PartitionDetail {
                    date: p.date,
                    size_bytes: p.size_bytes,
                })
                .collect();
            success_response(
                StatusCode::OK,
                &trace_id,
                StorageInfo {
                    partitions: details,
                    total_partitions,
                    total_size_bytes,
                },
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list partitions");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Failed to list storage partitions",
            )
            .into_response()
        }
    }
}

/// 手动触发存储清理。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/system/storage/cleanup",
    tag = "System",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "清理结果"),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn trigger_cleanup(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let retention_days = state.config.retention_days;
    match state.storage.cleanup(retention_days) {
        Ok(removed) => success_response(
            StatusCode::OK,
            &trace_id,
            serde_json::json!({ "partitions_removed": removed }),
        ),
        Err(e) => {
            tracing::error!(error = %e, "Manual cleanup failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Cleanup failed",
            )
            .into_response()
        }
    }
}

pub fn system_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_system_config))
        .routes(routes!(get_storage_info))
        .routes(routes!(trigger_cleanup))
}
