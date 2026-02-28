use crate::api::{error_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use oxmon_storage::StorageEngine;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
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
    /// 系统当前语言设置
    language: String,
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
        .get_runtime_setting_u64("notification_aggregation_window", 60)
        .await;
    let language = state
        .cert_store
        .get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE)
        .await;
    let alert_rules_count = state
        .cert_store
        .count_alert_rules(None, None)
        .await
        .unwrap_or(0) as usize;
    let notification_channels_count = state
        .cert_store
        .count_notification_channels(&oxmon_storage::NotificationChannelFilter {
            name_contains: None,
            channel_type_eq: None,
            enabled_eq: None,
            min_severity_eq: None,
        })
        .await
        .unwrap_or(0) as usize;
    success_response(
        StatusCode::OK,
        &trace_id,
        RuntimeConfig {
            grpc_port: config.grpc_port,
            http_port: config.http_port,
            data_dir: config.database.data_dir.clone(),
            retention_days: config.retention_days,
            require_agent_auth: config.require_agent_auth,
            cert_check_enabled: config.cert_check.enabled,
            cert_check_default_interval_secs: config.cert_check.default_interval_secs,
            cert_check_tick_secs: config.cert_check.tick_secs,
            cert_check_max_concurrent: config.cert_check.max_concurrent,
            notification_aggregation_window_secs,
            alert_rules_count,
            notification_channels_count,
            language,
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

#[derive(Serialize, ToSchema)]
struct CertDomainsBackfillResponse {
    /// 本次新增回填到监控域名表的域名数量
    inserted_domains: u64,
    /// 是否为预览模式（true 表示未实际写入）
    dry_run: bool,
    /// 样本域名列表（dry_run=true 时为“待回填样本”；执行模式时为“本次回填样本”）
    domains_preview: Vec<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct CertDomainsBackfillParams {
    /// 预览模式：仅返回将补齐的数量，不执行写入
    #[param(required = false)]
    dry_run: Option<bool>,
    /// 预览样本数量上限（仅 dry_run=true 生效，默认 10，最大 100）
    #[param(required = false)]
    preview_limit: Option<u64>,
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

/// 手动回填监控域名（从证书详情表补齐缺失域名）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/system/certs/backfill-domains",
    tag = "System",
    security(("bearer_auth" = [])),
    params(CertDomainsBackfillParams),
    responses(
        (status = 200, description = "回填结果", body = CertDomainsBackfillResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn trigger_cert_domains_backfill(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<CertDomainsBackfillParams>,
) -> impl IntoResponse {
    let dry_run = params.dry_run.unwrap_or(false);
    let preview_limit = params.preview_limit.unwrap_or(10).clamp(1, 100) as usize;
    let result: anyhow::Result<(u64, Vec<String>)> = if dry_run {
        match state
            .cert_store
            .count_missing_monitored_domains_from_certificate_details()
            .await
        {
            Ok(inserted) => {
                let preview = state
                    .cert_store
                    .preview_missing_monitored_domains_from_certificate_details(preview_limit)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::error!(
                            error = %e,
                            "Failed to preview missing monitored domains from certificate details"
                        );
                        Vec::new()
                    });
                Ok((inserted, preview))
            }
            Err(e) => Err(e),
        }
    } else {
        state
            .cert_store
            .sync_missing_monitored_domains_from_certificate_details_with_preview(preview_limit)
            .await
    };

    match result {
        Ok((inserted, domains_preview)) => {
            tracing::info!(
                inserted,
                dry_run,
                "Manual backfill of monitored domains from certificate details completed"
            );
            success_response(
                StatusCode::OK,
                &trace_id,
                CertDomainsBackfillResponse {
                    inserted_domains: inserted,
                    dry_run,
                    domains_preview,
                },
            )
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "Manual backfill of monitored domains from certificate details failed"
            );
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Backfill failed",
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
        .routes(routes!(trigger_cert_domains_backfill))
}
