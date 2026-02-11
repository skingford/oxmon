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

/// 通知渠道信息
#[derive(Serialize, ToSchema)]
struct ChannelResponse {
    /// 渠道索引
    index: usize,
    /// 渠道类型名称
    channel_name: String,
}

/// 通知渠道路由信息
#[derive(Serialize, ToSchema)]
struct ChannelRouteResponse {
    /// 最低告警级别
    min_severity: String,
    /// 关联的渠道索引
    channel_index: usize,
}

/// 静默窗口信息
#[derive(Serialize, ToSchema)]
struct SilenceWindowResponse {
    /// 开始时间（HH:MM）
    start: String,
    /// 结束时间（HH:MM）
    end: String,
    /// 循环规则
    recurrence: Option<String>,
}

/// 通知概览
#[derive(Serialize, ToSchema)]
struct NotificationOverview {
    /// 已配置的渠道列表（运行时）
    channels: Vec<ChannelResponse>,
    /// 路由规则
    routes: Vec<ChannelRouteResponse>,
    /// 静默窗口（运行时）
    silence_windows: Vec<SilenceWindowResponse>,
}

/// 列出运行时通知渠道和路由配置。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/notifications/channels",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "通知渠道概览", body = NotificationOverview),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_channels(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let channels: Vec<ChannelResponse> = state
        .notifier
        .channels()
        .iter()
        .enumerate()
        .map(|(i, ch)| ChannelResponse {
            index: i,
            channel_name: ch.channel_name().to_string(),
        })
        .collect();

    let routes: Vec<ChannelRouteResponse> = state
        .notifier
        .routes()
        .iter()
        .map(|r| ChannelRouteResponse {
            min_severity: format!("{}", r.min_severity),
            channel_index: r.channel_index,
        })
        .collect();

    let silence_windows: Vec<SilenceWindowResponse> = state
        .notifier
        .silence_windows()
        .iter()
        .map(|sw| SilenceWindowResponse {
            start: sw.start.format("%H:%M").to_string(),
            end: sw.end.format("%H:%M").to_string(),
            recurrence: sw.recurrence.clone(),
        })
        .collect();

    success_response(
        StatusCode::OK,
        &trace_id,
        NotificationOverview {
            channels,
            routes,
            silence_windows,
        },
    )
}

/// 发送测试通知到指定渠道。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/notifications/channels/{index}/test",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(
        ("index" = usize, Path, description = "渠道索引")
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
    Path(index): Path<usize>,
) -> impl IntoResponse {
    let channels = state.notifier.channels();
    let channel = match channels.get(index) {
        Some(ch) => ch,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Channel not found",
            )
            .into_response();
        }
    };

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
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    match channel.send(&test_event).await {
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

// ---- Persisted notification channels CRUD ----

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

#[derive(Deserialize, ToSchema)]
struct CreateChannelRequest {
    name: String,
    channel_type: String,
    #[serde(default = "default_min_severity")]
    min_severity: String,
    #[serde(default)]
    config_json: String,
}

fn default_min_severity() -> String {
    "info".to_string()
}

/// 创建通知渠道配置。
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
    let row = NotificationChannelRow {
        id: oxmon_common::id::next_id(),
        name: req.name,
        channel_type: req.channel_type,
        min_severity: req.min_severity,
        enabled: true,
        config_json: req.config_json,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    match state.cert_store.insert_notification_channel(&row) {
        Ok(ch) => success_response(StatusCode::CREATED, &trace_id, ch),
        Err(e) => {
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
        Ok(Some(ch)) => success_response(StatusCode::OK, &trace_id, ch),
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
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "Channel deleted"),
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
        .routes(routes!(list_silence_windows, create_silence_window))
        .routes(routes!(delete_silence_window))
}
