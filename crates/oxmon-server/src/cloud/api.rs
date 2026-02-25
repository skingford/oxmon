use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use oxmon_cloud::{build_provider, CloudAccountConfig};
use oxmon_storage::cert_store::{CloudInstanceRow, SystemConfigRow, SystemConfigUpdate};
use oxmon_storage::StorageEngine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 云账户响应（凭证已脱敏）
#[derive(Serialize, ToSchema)]
struct CloudAccountResponse {
    id: String,
    config_key: String,
    provider: String,
    display_name: String,
    description: Option<String>,
    config: serde_json::Value,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

/// 创建云账户请求
#[derive(Deserialize, ToSchema)]
struct CreateCloudAccountRequest {
    /// 配置标识（唯一，如 cloud_tencent_prod）
    config_key: String,
    /// 云供应商（tencent 或 alibaba）
    provider: String,
    /// 显示名称
    display_name: String,
    /// 描述
    description: Option<String>,
    /// 云账户配置 JSON
    config: serde_json::Value,
}

/// 更新云账户请求
#[derive(Deserialize, ToSchema)]
struct UpdateCloudAccountRequest {
    display_name: Option<String>,
    description: Option<Option<String>>,
    config: Option<serde_json::Value>,
    enabled: Option<bool>,
}

/// 云实例响应
#[derive(Serialize, ToSchema)]
struct CloudInstanceResponse {
    id: String,
    instance_id: String,
    instance_name: Option<String>,
    provider: String,
    account_config_key: String,
    region: String,
    public_ip: Option<String>,
    private_ip: Option<String>,
    os: Option<String>,
    status: Option<String>,
    last_seen_at: String,
    created_at: String,
    updated_at: String,
}

/// 测试连接响应
#[derive(Serialize, ToSchema)]
struct TestConnectionResponse {
    success: bool,
    message: String,
    instance_count: Option<usize>,
}

/// 触发采集响应
#[derive(Serialize, ToSchema)]
struct TriggerCollectionResponse {
    success: bool,
    message: String,
    collected_count: Option<usize>,
}

/// 脱敏云账户配置（隐藏 secret_id 和 secret_key）
fn redact_cloud_config(config: &serde_json::Value) -> serde_json::Value {
    let mut redacted = config.clone();
    if let Some(obj) = redacted.as_object_mut() {
        for key in &["secret_id", "secret_key", "access_key_id", "access_key_secret"] {
            if obj.contains_key(*key) {
                obj.insert(key.to_string(), serde_json::json!("***"));
            }
        }
    }
    redacted
}

fn row_to_cloud_account_response(row: SystemConfigRow) -> CloudAccountResponse {
    let config_val: serde_json::Value =
        serde_json::from_str(&row.config_json).unwrap_or_else(|_| serde_json::json!({}));
    let redacted = redact_cloud_config(&config_val);

    // Extract provider from config_key (e.g., "cloud_tencent_prod" -> "tencent")
    let provider = row
        .config_key
        .strip_prefix("cloud_")
        .and_then(|s| s.split('_').next())
        .unwrap_or("unknown")
        .to_string();

    CloudAccountResponse {
        id: row.id,
        config_key: row.config_key,
        provider,
        display_name: row.display_name,
        description: row.description,
        config: redacted,
        enabled: row.enabled,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}

fn cloud_instance_row_to_response(row: CloudInstanceRow) -> CloudInstanceResponse {
    CloudInstanceResponse {
        id: row.id,
        instance_id: row.instance_id,
        instance_name: row.instance_name,
        provider: row.provider,
        account_config_key: row.account_config_key,
        region: row.region,
        public_ip: row.public_ip,
        private_ip: row.private_ip,
        os: row.os,
        status: row.status,
        last_seen_at: chrono::DateTime::from_timestamp(row.last_seen_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
        created_at: chrono::DateTime::from_timestamp(row.created_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
        updated_at: chrono::DateTime::from_timestamp(row.updated_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
    }
}

/// 云账户列表查询参数
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListCloudAccountParams {
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "crate::api::pagination::deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "crate::api::pagination::deserialize_optional_u64")]
    offset: Option<u64>,
    /// 按启用状态过滤
    #[param(required = false)]
    enabled: Option<bool>,
}

/// 列出所有云账户（凭证已脱敏）
#[utoipa::path(
    get,
    path = "/v1/cloud/accounts",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(ListCloudAccountParams),
    responses(
        (status = 200, description = "云账户列表", body = Vec<CloudAccountResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_cloud_accounts(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListCloudAccountParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    let total = match state
        .cert_store
        .count_system_configs(Some("cloud_account"), None, params.enabled)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count cloud accounts");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state.cert_store.list_system_configs(
        Some("cloud_account"),
        None,
        params.enabled,
        limit,
        offset,
    ) {
        Ok(rows) => {
            let resp: Vec<CloudAccountResponse> =
                rows.into_iter().map(row_to_cloud_account_response).collect();
            success_paginated_response(StatusCode::OK, &trace_id, resp, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list cloud accounts");
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

/// 创建云账户
#[utoipa::path(
    post,
    path = "/v1/cloud/accounts",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    request_body = CreateCloudAccountRequest,
    responses(
        (status = 201, description = "云账户已创建", body = CloudAccountResponse),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 409, description = "配置键已存在", body = crate::api::ApiError)
    )
)]
async fn create_cloud_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateCloudAccountRequest>,
) -> impl IntoResponse {
    // Validate provider
    if req.provider != "tencent" && req.provider != "alibaba" {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_provider",
            "Provider must be 'tencent' or 'alibaba'",
        )
        .into_response();
    }

    // Validate config_key format
    if !req.config_key.starts_with("cloud_") {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_config_key",
            "config_key must start with 'cloud_'",
        )
        .into_response();
    }

    // Validate config JSON structure
    let config_str = match serde_json::to_string(&req.config) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize config JSON");
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "invalid_config",
                "Invalid config JSON",
            )
            .into_response();
        }
    };

    // Try to parse as CloudAccountConfig to validate structure
    if let Err(e) = serde_json::from_str::<CloudAccountConfig>(&config_str) {
        tracing::error!(error = %e, "Invalid cloud account config structure");
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_config_structure",
            &format!("Invalid config structure: {}", e),
        )
        .into_response();
    }

    let now = chrono::Utc::now();
    let row = SystemConfigRow {
        id: oxmon_common::id::next_id(),
        config_key: req.config_key,
        config_type: "cloud_account".to_string(),
        provider: Some(req.provider),
        display_name: req.display_name,
        description: req.description,
        config_json: config_str,
        enabled: true,
        created_at: now,
        updated_at: now,
    };

    match state.cert_store.insert_system_config(&row) {
        Ok(row) => {
            let resp = row_to_cloud_account_response(row);
            success_response(StatusCode::CREATED, &trace_id, resp)
        }
        Err(e) => {
            let err_msg = e.to_string();
            if err_msg.contains("UNIQUE constraint failed") {
                error_response(
                    StatusCode::CONFLICT,
                    &trace_id,
                    "duplicate_config_key",
                    "Cloud account with this config_key already exists",
                )
                .into_response()
            } else {
                tracing::error!(error = %e, "Failed to create cloud account");
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

/// 获取单个云账户
#[utoipa::path(
    get,
    path = "/v1/cloud/accounts/{id}",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    responses(
        (status = 200, description = "云账户详情", body = CloudAccountResponse),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn get_cloud_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_system_config_by_id(&id) {
        Ok(Some(row)) => {
            if row.config_type != "cloud_account" {
                return error_response(
                    StatusCode::NOT_FOUND,
                    &trace_id,
                    "not_found",
                    "Cloud account not found",
                )
                .into_response();
            }
            let resp = row_to_cloud_account_response(row);
            success_response(StatusCode::OK, &trace_id, resp)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Cloud account not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get cloud account");
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

/// 更新云账户
#[utoipa::path(
    put,
    path = "/v1/cloud/accounts/{id}",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    request_body = UpdateCloudAccountRequest,
    responses(
        (status = 200, description = "云账户已更新", body = CloudAccountResponse),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn update_cloud_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateCloudAccountRequest>,
) -> impl IntoResponse {
    // Validate config if provided
    let config_str = if let Some(ref config) = req.config {
        let s = match serde_json::to_string(config) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize config JSON");
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &trace_id,
                    "invalid_config",
                    "Invalid config JSON",
                )
                .into_response();
            }
        };

        // Validate structure
        if let Err(e) = serde_json::from_str::<CloudAccountConfig>(&s) {
            tracing::error!(error = %e, "Invalid cloud account config structure");
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "invalid_config_structure",
                &format!("Invalid config structure: {}", e),
            )
            .into_response();
        }

        Some(s)
    } else {
        None
    };

    let update = SystemConfigUpdate {
        display_name: req.display_name,
        description: req.description,
        config_json: config_str,
        enabled: req.enabled,
    };

    match state.cert_store.update_system_config(&id, &update) {
        Ok(Some(row)) => {
            let resp = row_to_cloud_account_response(row);
            success_response(StatusCode::OK, &trace_id, resp)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Cloud account not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update cloud account");
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

/// 删除云账户
#[utoipa::path(
    delete,
    path = "/v1/cloud/accounts/{id}",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    responses(
        (status = 204, description = "云账户已删除"),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn delete_cloud_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_system_config(&id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Cloud account not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete cloud account");
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

/// 测试云账户连接
#[utoipa::path(
    post,
    path = "/v1/cloud/accounts/{id}/test",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    responses(
        (status = 200, description = "连接测试结果", body = TestConnectionResponse),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn test_cloud_account_connection(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Get cloud account config
    let row = match state.cert_store.get_system_config_by_id(&id) {
        Ok(Some(row)) => {
            if row.config_type != "cloud_account" {
                return error_response(
                    StatusCode::NOT_FOUND,
                    &trace_id,
                    "not_found",
                    "Cloud account not found",
                )
                .into_response();
            }
            row
        }
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Cloud account not found",
            )
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get cloud account");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    // Parse config
    let account_config: CloudAccountConfig = match serde_json::from_str(&row.config_json) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse cloud account config");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "config_error",
                "Invalid cloud account configuration",
            )
            .into_response();
        }
    };

    // Extract provider and account name
    let provider_type = row
        .config_key
        .strip_prefix("cloud_")
        .and_then(|s| s.split('_').next())
        .unwrap_or("unknown");
    let account_name = row
        .config_key
        .strip_prefix(&format!("cloud_{}_", provider_type))
        .unwrap_or("default");

    // Build provider and test connection
    match build_provider(provider_type, account_name, account_config) {
        Ok(provider) => match provider.list_instances().await {
            Ok(instances) => {
                let resp = TestConnectionResponse {
                    success: true,
                    message: format!("Successfully connected to {} cloud", provider_type),
                    instance_count: Some(instances.len()),
                };
                success_response(StatusCode::OK, &trace_id, resp)
            }
            Err(e) => {
                let resp = TestConnectionResponse {
                    success: false,
                    message: format!("Failed to list instances: {}", e),
                    instance_count: None,
                };
                success_response(StatusCode::OK, &trace_id, resp)
            }
        },
        Err(e) => {
            let resp = TestConnectionResponse {
                success: false,
                message: format!("Failed to build provider: {}", e),
                instance_count: None,
            };
            success_response(StatusCode::OK, &trace_id, resp)
        }
    }
}

/// 手动触发云账户采集
#[utoipa::path(
    post,
    path = "/v1/cloud/accounts/{id}/collect",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    responses(
        (status = 200, description = "采集任务已触发", body = TriggerCollectionResponse),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn trigger_cloud_account_collection(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Get cloud account config
    let row = match state.cert_store.get_system_config_by_id(&id) {
        Ok(Some(row)) => {
            if row.config_type != "cloud_account" {
                return error_response(
                    StatusCode::NOT_FOUND,
                    &trace_id,
                    "not_found",
                    "Cloud account not found",
                )
                .into_response();
            }
            row
        }
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Cloud account not found",
            )
            .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get cloud account");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    // Parse config
    let account_config: CloudAccountConfig = match serde_json::from_str(&row.config_json) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse cloud account config");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "config_error",
                "Invalid cloud account configuration",
            )
            .into_response();
        }
    };

    // Extract provider and account name
    let provider_type = row
        .config_key
        .strip_prefix("cloud_")
        .and_then(|s| s.split('_').next())
        .unwrap_or("unknown");
    let account_name = row
        .config_key
        .strip_prefix(&format!("cloud_{}_", provider_type))
        .unwrap_or("default");

    // Build provider and collect metrics
    match build_provider(provider_type, account_name, account_config) {
        Ok(provider) => {
            // Use CloudCollector to gather metrics
            let collector = oxmon_cloud::collector::CloudCollector::new(
                vec![std::sync::Arc::from(provider)],
                5,
            );

            match collector.collect_all().await {
                Ok(metrics) => {
                    // Convert to MetricDataPoint and write to storage
                    let now = chrono::Utc::now();
                    let mut data_points = Vec::new();

                    for m in &metrics {
                        let agent_id = format!("cloud:{}:{}", m.provider, m.instance_id);
                        let mut labels = std::collections::HashMap::new();
                        labels.insert("provider".to_string(), m.provider.clone());
                        labels.insert("region".to_string(), m.region.clone());
                        labels.insert("instance_name".to_string(), m.instance_name.clone());

                        if let Some(cpu) = m.cpu_usage {
                            data_points.push(oxmon_common::types::MetricDataPoint {
                                id: oxmon_common::id::next_id(),
                                timestamp: m.collected_at,
                                agent_id: agent_id.clone(),
                                metric_name: "cloud.cpu.usage".to_string(),
                                value: cpu,
                                labels: labels.clone(),
                                created_at: now,
                                updated_at: now,
                            });
                        }

                        if let Some(memory) = m.memory_usage {
                            data_points.push(oxmon_common::types::MetricDataPoint {
                                id: oxmon_common::id::next_id(),
                                timestamp: m.collected_at,
                                agent_id: agent_id.clone(),
                                metric_name: "cloud.memory.usage".to_string(),
                                value: memory,
                                labels: labels.clone(),
                                created_at: now,
                                updated_at: now,
                            });
                        }

                        if let Some(disk) = m.disk_usage {
                            data_points.push(oxmon_common::types::MetricDataPoint {
                                id: oxmon_common::id::next_id(),
                                timestamp: m.collected_at,
                                agent_id: agent_id.clone(),
                                metric_name: "cloud.disk.usage".to_string(),
                                value: disk,
                                labels,
                                created_at: now,
                                updated_at: now,
                            });
                        }
                    }

                    if !data_points.is_empty() {
                        let batch = oxmon_common::types::MetricBatch {
                            agent_id: "manual-collection".to_string(),
                            timestamp: now,
                            data_points,
                        };

                        if let Err(e) = state.storage.write_batch(&batch) {
                            tracing::error!(error = %e, "Failed to write cloud metrics batch");
                            return error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &trace_id,
                                "storage_error",
                                "Failed to write metrics",
                            )
                            .into_response();
                        }
                    }

                    let resp = TriggerCollectionResponse {
                        success: true,
                        message: format!("Successfully collected metrics from {} instances", metrics.len()),
                        collected_count: Some(metrics.len()),
                    };
                    success_response(StatusCode::OK, &trace_id, resp)
                }
                Err(e) => {
                    let resp = TriggerCollectionResponse {
                        success: false,
                        message: format!("Failed to collect metrics: {}", e),
                        collected_count: None,
                    };
                    success_response(StatusCode::OK, &trace_id, resp)
                }
            }
        }
        Err(e) => {
            let resp = TriggerCollectionResponse {
                success: false,
                message: format!("Failed to build provider: {}", e),
                collected_count: None,
            };
            success_response(StatusCode::OK, &trace_id, resp)
        }
    }
}

/// 云实例列表查询参数
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListCloudInstancesParams {
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "crate::api::pagination::deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "crate::api::pagination::deserialize_optional_u64")]
    offset: Option<u64>,
    /// 按供应商过滤
    #[param(required = false)]
    provider: Option<String>,
    /// 按区域过滤
    #[param(required = false)]
    region: Option<String>,
}

/// 列出所有云实例
#[utoipa::path(
    get,
    path = "/v1/cloud/instances",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(ListCloudInstancesParams),
    responses(
        (status = 200, description = "云实例列表", body = Vec<CloudInstanceResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_cloud_instances(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListCloudInstancesParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    let total = match state.cert_store.count_cloud_instances(
        params.provider.as_deref(),
        params.region.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count cloud instances");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state.cert_store.list_cloud_instances(
        params.provider.as_deref(),
        params.region.as_deref(),
        limit,
        offset,
    ) {
        Ok(rows) => {
            let resp: Vec<CloudInstanceResponse> = rows
                .into_iter()
                .map(cloud_instance_row_to_response)
                .collect();
            success_paginated_response(StatusCode::OK, &trace_id, resp, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list cloud instances");
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

/// 注册云API路由
pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_cloud_accounts))
        .routes(routes!(create_cloud_account))
        .routes(routes!(get_cloud_account))
        .routes(routes!(update_cloud_account))
        .routes(routes!(delete_cloud_account))
        .routes(routes!(test_cloud_account_connection))
        .routes(routes!(trigger_cloud_account_collection))
        .routes(routes!(list_cloud_instances))
}
