use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_empty_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use oxmon_storage::cert_store::{NotificationChannelRow, NotificationChannelUpdate, SilenceWindowRow};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 通知渠道概览（含收件人列表）
#[derive(Serialize, ToSchema)]
struct ChannelOverview {
    id: String,
    name: String,
    channel_type: String,
    description: Option<String>,
    min_severity: String,
    enabled: bool,
    recipient_type: Option<String>,
    recipients: Vec<String>,
    created_at: String,
    updated_at: String,
}

/// 列出所有通知渠道配置（含收件人）。
#[utoipa::path(
    get,
    path = "/v1/notifications/channels",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "通知渠道列表", body = Vec<ChannelOverview>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_channels(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    match state
        .cert_store
        .list_notification_channels(pagination.limit(), pagination.offset())
    {
        Ok(channels) => {
            let mut result = Vec::with_capacity(channels.len());
            for ch in channels {
                let recipients = state
                    .cert_store
                    .list_recipients_by_channel(&ch.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|r| r.value)
                    .collect();
                let recipient_type = state
                    .notifier
                    .registry()
                    .get_plugin(&ch.channel_type)
                    .map(|p| p.recipient_type().to_string());
                result.push(ChannelOverview {
                    id: ch.id,
                    name: ch.name,
                    channel_type: ch.channel_type,
                    description: ch.description,
                    min_severity: ch.min_severity,
                    enabled: ch.enabled,
                    recipient_type,
                    recipients,
                    created_at: ch.created_at.to_rfc3339(),
                    updated_at: ch.updated_at.to_rfc3339(),
                });
            }
            success_response(StatusCode::OK, &trace_id, result)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list notification channels");
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

/// 发送测试通知到指定渠道（按 ID）。
#[utoipa::path(
    post,
    path = "/v1/notifications/channels/{id}/test",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "渠道 ID")
    ),
    responses(
        (status = 200, description = "测试通知已发送"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "渠道不存在", body = crate::api::ApiError)
    )
)]
async fn test_channel(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let ch = match state.cert_store.get_notification_channel_by_id(&id) {
        Ok(Some(ch)) => ch,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Channel not found")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get channel");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &trace_id, "storage_error", "Database error")
                .into_response();
        }
    };

    let config: serde_json::Value = serde_json::from_str(&ch.config_json)
        .unwrap_or_else(|_| serde_json::json!({}));

    let channel = match state
        .notifier
        .registry()
        .create_channel(&ch.channel_type, &ch.id, &config)
    {
        Ok(c) => c,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "invalid_config",
                &format!("Cannot create channel: {e}"),
            )
            .into_response();
        }
    };

    let recipients: Vec<String> = state
        .cert_store
        .list_recipients_by_channel(&ch.id)
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.value)
        .collect();

    let test_event = oxmon_common::types::AlertEvent {
        id: format!("test-{}", chrono::Utc::now().timestamp_millis()),
        rule_id: "test-rule".to_string(),
        agent_id: "test-agent".to_string(),
        metric_name: "test.metric".to_string(),
        severity: oxmon_common::types::Severity::Info,
        message: "This is a test notification from oxmon.".to_string(),
        value: 0.0,
        threshold: 0.0,
        timestamp: chrono::Utc::now(),
        predicted_breach: None,
        status: 1,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    match channel.send(&test_event, &recipients).await {
        Ok(()) => success_empty_response(StatusCode::OK, &trace_id, "Test notification sent"),
        Err(e) => {
            tracing::error!(error = %e, "Test notification failed");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                &format!("Test notification failed: {e}"),
            )
            .into_response()
        }
    }
}

// ---- Notification channels CRUD ----

#[derive(Deserialize, ToSchema)]
struct CreateChannelRequest {
    name: String,
    channel_type: String,
    description: Option<String>,
    #[serde(default = "default_min_severity")]
    min_severity: String,
    #[serde(default)]
    config_json: String,
    #[serde(default)]
    recipients: Vec<String>,
}

fn default_min_severity() -> String {
    "info".to_string()
}

/// 列出持久化的通知渠道配置。
#[utoipa::path(
    get,
    path = "/v1/notifications/channels/config",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "通知渠道配置列表", body = Vec<serde_json::Value>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_channel_configs(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    match state
        .cert_store
        .list_notification_channels(pagination.limit(), pagination.offset())
    {
        Ok(channels) => success_response(StatusCode::OK, &trace_id, channels),
        Err(e) => {
            tracing::error!(error = %e, "Failed to list notification channels");
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

/// 创建通知渠道配置（含收件人）。
#[utoipa::path(
    post,
    path = "/v1/notifications/channels/config",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    request_body = CreateChannelRequest,
    responses(
        (status = 201, description = "通知渠道已创建", body = serde_json::Value),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn create_channel_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateChannelRequest>,
) -> impl IntoResponse {
    // 校验 config_json 是否可被对应 plugin 解析
    let config_value: serde_json::Value = match serde_json::from_str(&req.config_json) {
        Ok(v) => v,
        Err(_) => serde_json::json!({}),
    };
    if let Some(plugin) = state.notifier.registry().get_plugin(&req.channel_type) {
        if let Err(e) = plugin.validate_config(&config_value) {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "invalid_config",
                &format!("Config validation failed: {e}"),
            )
            .into_response();
        }
    } else {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "unknown_channel_type",
            &format!("Unknown channel type: {}", req.channel_type),
        )
        .into_response();
    }

    let row = NotificationChannelRow {
        id: oxmon_common::id::next_id(),
        name: req.name,
        channel_type: req.channel_type,
        description: req.description,
        min_severity: req.min_severity,
        enabled: true,
        config_json: req.config_json,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let channel_id = row.id.clone();
    match state.cert_store.insert_notification_channel(&row) {
        Ok(ch) => {
            // 写入收件人
            if !req.recipients.is_empty() {
                let _ = state.cert_store.set_channel_recipients(&channel_id, &req.recipients);
            }
            // 触发热重载
            if let Err(e) = state.notifier.reload().await {
                tracing::warn!(error = %e, "Failed to reload channels after create");
            }
            success_response(StatusCode::CREATED, &trace_id, ch)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                error_response(StatusCode::CONFLICT, &trace_id, "conflict", "Channel name already exists")
                    .into_response()
            } else {
                tracing::error!(error = %e, "Failed to create notification channel");
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

/// 更新通知渠道配置。
#[utoipa::path(
    put,
    path = "/v1/notifications/channels/config/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "渠道配置 ID")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "通知渠道已更新", body = serde_json::Value),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "渠道不存在", body = crate::api::ApiError)
    )
)]
async fn update_channel_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update): Json<NotificationChannelUpdate>,
) -> impl IntoResponse {
    match state.cert_store.update_notification_channel(&id, &update) {
        Ok(Some(ch)) => {
            if let Err(e) = state.notifier.reload().await {
                tracing::warn!(error = %e, "Failed to reload channels after update");
            }
            success_response(StatusCode::OK, &trace_id, ch)
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Channel not found")
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update notification channel");
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

/// 删除通知渠道配置。
#[utoipa::path(
    delete,
    path = "/v1/notifications/channels/config/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "渠道配置 ID")),
    responses(
        (status = 200, description = "通知渠道已删除"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "渠道不存在", body = crate::api::ApiError)
    )
)]
async fn delete_channel_config(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_notification_channel(&id) {
        Ok(true) => {
            if let Err(e) = state.notifier.reload().await {
                tracing::warn!(error = %e, "Failed to reload channels after delete");
            }
            success_empty_response(StatusCode::OK, &trace_id, "Channel deleted")
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Channel not found")
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete notification channel");
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

// ---- Recipients management ----

#[derive(Deserialize, ToSchema)]
struct SetRecipientsRequest {
    recipients: Vec<String>,
}

/// 设置（替换）渠道收件人列表。
#[utoipa::path(
    put,
    path = "/v1/notifications/channels/{id}/recipients",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "渠道 ID")),
    request_body = SetRecipientsRequest,
    responses(
        (status = 200, description = "收件人已更新", body = Vec<String>),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "渠道不存在", body = crate::api::ApiError)
    )
)]
async fn set_recipients(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SetRecipientsRequest>,
) -> impl IntoResponse {
    // 验证渠道存在
    match state.cert_store.get_notification_channel_by_id(&id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "Channel not found")
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get channel");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &trace_id, "storage_error", "Database error")
                .into_response();
        }
    }

    match state.cert_store.set_channel_recipients(&id, &req.recipients) {
        Ok(rows) => {
            if let Err(e) = state.notifier.reload().await {
                tracing::warn!(error = %e, "Failed to reload channels after recipients update");
            }
            let values: Vec<String> = rows.into_iter().map(|r| r.value).collect();
            success_response(StatusCode::OK, &trace_id, values)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to set recipients");
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

/// 获取渠道收件人列表。
#[utoipa::path(
    get,
    path = "/v1/notifications/channels/{id}/recipients",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "渠道 ID")),
    responses(
        (status = 200, description = "收件人列表", body = Vec<String>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn get_recipients(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.list_recipients_by_channel(&id) {
        Ok(rows) => {
            let values: Vec<String> = rows.into_iter().map(|r| r.value).collect();
            success_response(StatusCode::OK, &trace_id, values)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list recipients");
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

// ---- Silence windows CRUD ----

/// 列出持久化的静默窗口。
#[utoipa::path(
    get,
    path = "/v1/notifications/silence-windows",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "静默窗口列表", body = Vec<serde_json::Value>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_silence_windows(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    match state
        .cert_store
        .list_silence_windows(pagination.limit(), pagination.offset())
    {
        Ok(windows) => success_response(StatusCode::OK, &trace_id, windows),
        Err(e) => {
            tracing::error!(error = %e, "Failed to list silence windows");
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

#[derive(Deserialize, ToSchema)]
struct CreateSilenceWindowRequest {
    start_time: String,
    end_time: String,
    recurrence: Option<String>,
}

/// 创建静默窗口。
#[utoipa::path(
    post,
    path = "/v1/notifications/silence-windows",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    request_body = CreateSilenceWindowRequest,
    responses(
        (status = 201, description = "静默窗口已创建", body = serde_json::Value),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn create_silence_window(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateSilenceWindowRequest>,
) -> impl IntoResponse {
    let row = SilenceWindowRow {
        id: oxmon_common::id::next_id(),
        start_time: req.start_time,
        end_time: req.end_time,
        recurrence: req.recurrence,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    match state.cert_store.insert_silence_window(&row) {
        Ok(sw) => success_response(StatusCode::CREATED, &trace_id, sw),
        Err(e) => {
            tracing::error!(error = %e, "Failed to create silence window");
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

/// 删除静默窗口。
#[utoipa::path(
    delete,
    path = "/v1/notifications/silence-windows/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "静默窗口 ID")),
    responses(
        (status = 200, description = "静默窗口已删除"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "静默窗口不存在", body = crate::api::ApiError)
    )
)]
async fn delete_silence_window(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_silence_window(&id) {
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "Silence window deleted"),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Silence window not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete silence window");
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

pub fn notification_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_channels))
        .routes(routes!(test_channel))
        .routes(routes!(list_channel_configs, create_channel_config))
        .routes(routes!(update_channel_config, delete_channel_config))
        .routes(routes!(set_recipients, get_recipients))
        .routes(routes!(list_silence_windows, create_silence_window))
        .routes(routes!(delete_silence_window))
}
