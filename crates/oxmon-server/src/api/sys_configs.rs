use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use oxmon_storage::cert_store::{SystemConfigRow, SystemConfigUpdate};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 系统配置响应（密钥已脱敏）
#[derive(Serialize, ToSchema)]
struct SystemConfigResponse {
    id: String,
    config_key: String,
    config_type: String,
    provider: Option<String>,
    display_name: String,
    description: Option<String>,
    config_json: serde_json::Value,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

/// 创建系统配置请求
#[derive(Deserialize, ToSchema)]
struct CreateSystemConfigRequest {
    /// 配置标识（唯一，如 email、sms_aliyun）
    config_key: String,
    /// 配置类型（email 或 sms）
    config_type: String,
    /// 短信子供应商（sms 类型时填写：aliyun、tencent、generic）
    provider: Option<String>,
    /// 显示名称
    display_name: String,
    /// 描述
    description: Option<String>,
    /// 配置 JSON（SMTP 或短信供应商配置）
    config_json: String,
}

/// 更新系统配置请求
#[derive(Deserialize, ToSchema)]
struct UpdateSystemConfigRequest {
    display_name: Option<String>,
    description: Option<Option<String>>,
    config_json: Option<String>,
    enabled: Option<bool>,
}

fn redact_config(config_type: &str, config: &serde_json::Value) -> serde_json::Value {
    let mut redacted = config.clone();
    if let Some(obj) = redacted.as_object_mut() {
        match config_type {
            "email" => {
                if obj.contains_key("smtp_password") {
                    obj.insert("smtp_password".to_string(), serde_json::json!("***"));
                }
            }
            "sms" => {
                for key in &["api_key", "access_key_secret", "secret_key"] {
                    if obj.contains_key(*key) {
                        obj.insert(key.to_string(), serde_json::json!("***"));
                    }
                }
            }
            _ => {}
        }
    }
    redacted
}

fn row_to_response(row: SystemConfigRow) -> SystemConfigResponse {
    let config_val: serde_json::Value =
        serde_json::from_str(&row.config_json).unwrap_or_else(|_| serde_json::json!({}));
    let redacted = redact_config(&row.config_type, &config_val);
    SystemConfigResponse {
        id: row.id,
        config_key: row.config_key,
        config_type: row.config_type,
        provider: row.provider,
        display_name: row.display_name,
        description: row.description,
        config_json: redacted,
        enabled: row.enabled,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}

/// 列出所有系统配置（密钥已脱敏）。
#[utoipa::path(
    get,
    path = "/v1/system/configs",
    tag = "SystemConfig",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "系统配置列表", body = Vec<SystemConfigResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_system_configs(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();

    let total = match state.cert_store.count_system_configs() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count system configs");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state.cert_store.list_system_configs(limit, offset) {
        Ok(rows) => {
            let resp: Vec<SystemConfigResponse> = rows.into_iter().map(row_to_response).collect();
            success_paginated_response(StatusCode::OK, &trace_id, resp, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list system configs");
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

/// 获取单个系统配置（密钥已脱敏）。
#[utoipa::path(
    get,
    path = "/v1/system/configs/{id}",
    tag = "SystemConfig",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "系统配置 ID")),
    responses(
        (status = 200, description = "系统配置详情", body = SystemConfigResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "系统配置不存在", body = crate::api::ApiError)
    )
)]
async fn get_system_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_system_config_by_id(&id) {
        Ok(Some(row)) => success_response(StatusCode::OK, &trace_id, row_to_response(row)),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "System config not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get system config");
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

/// 创建系统配置。
#[utoipa::path(
    post,
    path = "/v1/system/configs",
    tag = "SystemConfig",
    security(("bearer_auth" = [])),
    request_body = CreateSystemConfigRequest,
    responses(
        (status = 201, description = "系统配置已创建", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 409, description = "config_key 已存在", body = crate::api::ApiError)
    )
)]
async fn create_system_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateSystemConfigRequest>,
) -> impl IntoResponse {
    // 限制只能创建 runtime 类型的系统配置
    // 发送方配置（email/sms）应直接在 notification_channels.config_json 中配置
    if req.config_type != "runtime" {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "Only config_type='runtime' is allowed. Sender configs (email/sms) should be configured directly in notification channels.",
        )
        .into_response();
    }

    // 验证 config_json 是有效 JSON
    let config_val: serde_json::Value = match serde_json::from_str(&req.config_json) {
        Ok(v) => v,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "config_json is not valid JSON",
            )
            .into_response();
        }
    };

    // Runtime 配置通常是简单的值，不需要 plugin 验证
    // 验证 config_json 包含 "value" 字段
    if !config_val.is_object() || config_val.get("value").is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "Runtime config_json must be an object with 'value' field",
        )
        .into_response();
    }

    let row = SystemConfigRow {
        id: oxmon_common::id::next_id(),
        config_key: req.config_key,
        config_type: req.config_type,
        provider: req.provider,
        display_name: req.display_name,
        description: req.description,
        config_json: req.config_json,
        enabled: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    match state.cert_store.insert_system_config(&row) {
        Ok(inserted) => crate::api::success_id_response(StatusCode::CREATED, &trace_id, inserted.id),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                error_response(
                    StatusCode::CONFLICT,
                    &trace_id,
                    "conflict",
                    "System config with this config_key already exists",
                )
                .into_response()
            } else {
                tracing::error!(error = %e, "Failed to create system config");
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

/// 更新系统配置。
#[utoipa::path(
    put,
    path = "/v1/system/configs/{id}",
    tag = "SystemConfig",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "系统配置 ID")),
    request_body = UpdateSystemConfigRequest,
    responses(
        (status = 200, description = "系统配置已更新", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "系统配置不存在", body = crate::api::ApiError)
    )
)]
async fn update_system_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSystemConfigRequest>,
) -> impl IntoResponse {
    let update = SystemConfigUpdate {
        display_name: req.display_name,
        description: req.description,
        config_json: req.config_json,
        enabled: req.enabled,
    };

    match state.cert_store.update_system_config(&id, &update) {
        Ok(Some(row)) => {
            // 触发通知渠道热重载（可能有渠道引用此系统配置）
            if let Err(e) = state.notifier.reload().await {
                tracing::warn!(error = %e, "Failed to reload channels after system config update");
            }
            crate::api::success_id_response(StatusCode::OK, &trace_id, row.id)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "System config not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update system config");
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

/// 删除系统配置（有渠道引用时拒绝删除）。
#[utoipa::path(
    delete,
    path = "/v1/system/configs/{id}",
    tag = "SystemConfig",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "系统配置 ID")),
    responses(
        (status = 200, description = "系统配置已删除", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "系统配置不存在", body = crate::api::ApiError),
        (status = 409, description = "有渠道引用此系统配置", body = crate::api::ApiError)
    )
)]
async fn delete_system_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_system_config(&id) {
        Ok(true) => crate::api::success_id_response(StatusCode::OK, &trace_id, id),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "System config not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete system config");
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

pub fn sys_config_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_system_configs, create_system_config))
        .routes(routes!(
            get_system_config,
            update_system_config,
            delete_system_config
        ))
}
