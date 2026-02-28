use crate::api::pagination::{deserialize_optional_u64, PaginationParams};
use crate::api::{
    error_response, success_empty_response, success_paginated_response, success_response,
};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use oxmon_common::types::UpdateNotificationChannelRequest;
use oxmon_storage::{NotificationChannelRow, NotificationLogFilter, SilenceWindowFilter, SilenceWindowRow};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 通知渠道完整信息（含配置和收件人）
#[derive(Serialize, ToSchema)]
struct ChannelOverview {
    id: String,
    name: String,
    channel_type: String,
    description: Option<String>,
    min_severity: String,
    enabled: bool,
    config_json: String,
    recipient_type: Option<String>,
    recipients: Vec<String>,
    created_at: String,
    updated_at: String,
}

fn validate_time_format(time: &str) -> bool {
    let parts: Vec<&str> = time.split(':').collect();
    if parts.len() != 2 {
        return false;
    }
    if let (Ok(hour), Ok(minute)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
        hour < 24 && minute < 60
    } else {
        false
    }
}

async fn build_channel_overview(state: &AppState, ch: NotificationChannelRow) -> ChannelOverview {
    let recipients = state
        .cert_store
        .list_recipients_by_channel(&ch.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.value)
        .collect();
    let recipient_type = state
        .notifier
        .registry()
        .get_plugin(&ch.channel_type)
        .map(|p| p.recipient_type().to_string());
    ChannelOverview {
        id: ch.id.clone(),
        name: ch.name.clone(),
        channel_type: ch.channel_type.clone(),
        description: ch.description.clone(),
        min_severity: ch.min_severity.clone(),
        enabled: ch.enabled,
        config_json: ch.config_json.clone(),
        recipient_type,
        recipients,
        created_at: ch.created_at.to_rfc3339(),
        updated_at: ch.updated_at.to_rfc3339(),
    }
}

/// 通知渠道列表查询参数
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListChannelsParams {
    /// 渠道名称模糊匹配
    #[param(required = false, rename = "name__contains")]
    #[serde(rename = "name__contains")]
    name_contains: Option<String>,
    /// 渠道类型精确匹配（email / webhook / sms / dingtalk / weixin）
    #[param(required = false, rename = "channel_type__eq")]
    #[serde(rename = "channel_type__eq")]
    channel_type_eq: Option<String>,
    /// 是否启用精确匹配
    #[param(required = false, rename = "enabled__eq")]
    #[serde(rename = "enabled__eq")]
    enabled_eq: Option<bool>,
    /// 最低告警级别精确匹配（info / warning / critical）
    #[param(required = false, rename = "min_severity__eq")]
    #[serde(rename = "min_severity__eq")]
    min_severity_eq: Option<String>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    offset: Option<u64>,
}

/// 列出所有通知渠道配置（含收件人）。
#[utoipa::path(
    get,
    path = "/v1/notifications/channels",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(ListChannelsParams),
    responses(
        (status = 200, description = "通知渠道列表", body = Vec<ChannelOverview>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_channels(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListChannelsParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    let channel_filter = oxmon_storage::NotificationChannelFilter {
        name_contains: params.name_contains.clone(),
        channel_type_eq: params.channel_type_eq.clone(),
        enabled_eq: params.enabled_eq,
        min_severity_eq: params.min_severity_eq.clone(),
    };
    let total = match state
        .cert_store
        .count_notification_channels(&channel_filter)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count notification channels");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state
        .cert_store
        .list_notification_channels(&channel_filter, limit, offset)
        .await
    {
        Ok(channels) => {
            let mut result = Vec::with_capacity(channels.len());
            for ch in channels {
                result.push(build_channel_overview(&state, ch).await);
            }
            success_paginated_response(StatusCode::OK, &trace_id, result, total, limit, offset)
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

/// 获取单个通知渠道配置（含收件人）。
#[utoipa::path(
    get,
    path = "/v1/notifications/channels/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "渠道 ID")),
    responses(
        (status = 200, description = "通知渠道详情", body = ChannelOverview),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "渠道不存在", body = crate::api::ApiError)
    )
)]
async fn get_channel_by_id(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_notification_channel_by_id(&id).await {
        Ok(Some(ch)) => success_response(
            StatusCode::OK,
            &trace_id,
            build_channel_overview(&state, ch).await,
        ),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Channel not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get notification channel by id");
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
    let ch = match state.cert_store.get_notification_channel_by_id(&id).await {
        Ok(Some(ch)) => ch,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Channel not found",
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get channel");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    // 配置优先级: 渠道自身 config_json > 全局 system_config > 跳过
    let config = match oxmon_notify::manager::resolve_config(&state.cert_store, &ch) {
        Some(cfg) => cfg,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "no_config",
                "Channel has no valid config and no system config fallback",
            )
            .into_response();
        }
    };

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
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.value)
        .collect();

    let test_event = oxmon_common::types::AlertEvent {
        id: format!("test-{}", chrono::Utc::now().timestamp_millis()),
        rule_id: "test-rule".to_string(),
        rule_name: "Test Rule".to_string(),
        agent_id: "test-agent".to_string(),
        metric_name: "test.metric".to_string(),
        severity: oxmon_common::types::Severity::Info,
        message: "This is a test notification from oxmon.".to_string(),
        value: 0.0,
        threshold: 0.0,
        timestamp: chrono::Utc::now(),
        predicted_breach: None,
        status: 1,
        labels: std::collections::HashMap::new(),
        first_triggered_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let locale = state
        .cert_store
        .get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE)
        .await;
    let start = tokio::time::Instant::now();
    let result = channel.send(&test_event, &recipients, &locale).await;
    let duration_ms = start.elapsed().as_millis() as i64;

    // 记录通知发送日志（测试通知也纳入日志记录）
    let (send_result, response) = match &result {
        Ok(resp) => (Ok(()), Some(resp.clone())),
        Err(e) => (Err(anyhow::anyhow!("{e}")), None),
    };

    let ctx = oxmon_notify::manager::SendLogContext {
        channel_id: &ch.id,
        channel_name: &ch.name,
        channel_type: &ch.channel_type,
        duration_ms,
        recipient_count: recipients.len() as i32,
        response,
    };
    oxmon_notify::manager::NotificationManager::record_send_log(
        state.notifier.cert_store(),
        &test_event,
        &ctx,
        &send_result,
    )
    .await;

    match result {
        Ok(_) => success_empty_response(StatusCode::OK, &trace_id, "Test notification sent"),
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

/// 发送证书告警批量报告测试（读取真实监控域名数据）
#[utoipa::path(
    post,
    path = "/v1/notifications/test-cert-report",
    responses(
        (status = 200, description = "测试报告已发送"),
        (status = 500, description = "发送失败")
    )
)]
async fn test_cert_report(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    use oxmon_notify::cert_report_template::CertAlertDetail;

    let now = chrono::Utc::now();
    let report_date = now.format("%Y-%m-%d").to_string();

    // 读取所有已启用域名的最新检查结果（上限 1000 条）
    let all_results = match state
        .cert_store
        .query_latest_results(
            &oxmon_storage::CertStatusFilter {
                domain_contains: None,
                is_valid: None,
                days_until_expiry_lte: None,
            },
            1000,
            0,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Failed to query cert check results");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                &format!("Failed to query cert results: {e}"),
            )
            .into_response();
        }
    };

    let total_checked = all_results.len() as i32;

    // 过滤出需要告警的域名：证书无效 或 30 天内到期
    let alert_items: Vec<CertAlertDetail> = all_results
        .into_iter()
        .filter(|r| !r.is_valid || r.days_until_expiry.is_some_and(|d| d <= 30))
        .map(|r| {
            let days = r.days_until_expiry.unwrap_or(i64::MIN);
            let severity = if !r.is_valid && r.days_until_expiry.is_none() {
                // 无法连接或证书完全无效（无剩余天数）
                "critical"
            } else if days <= 7 {
                "critical"
            } else {
                "warning"
            };

            let message = if let Some(ref err) = r.error {
                err.clone()
            } else if days < 0 {
                format!("证书已过期 {} 天", days.abs())
            } else {
                format!("证书将在 {days} 天后到期")
            };

            let not_after = r.not_after.map(|dt| dt.format("%Y-%m-%d").to_string());

            CertAlertDetail {
                domain: r.domain,
                days_until_expiry: days,
                severity: severity.to_string(),
                not_after,
                issuer: r.issuer,
                message,
            }
        })
        .collect();

    let locale = state
        .cert_store
        .get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE)
        .await;

    tracing::info!(
        locale = %locale,
        total_checked,
        alert_count = alert_items.len(),
        "Sending test cert alert batch report with real domain data"
    );

    if alert_items.is_empty() {
        return success_empty_response(
            StatusCode::OK,
            &trace_id,
            &format!("No alerts found among {total_checked} checked domains"),
        );
    }

    state
        .notifier
        .send_cert_report(&alert_items, total_checked, &report_date, &locale)
        .await;

    success_empty_response(
        StatusCode::OK,
        &trace_id,
        &format!(
            "Cert report sent: {}/{total_checked} domains with alerts",
            alert_items.len()
        ),
    )
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

/// 创建通知渠道（含配置和收件人）。
#[utoipa::path(
    post,
    path = "/v1/notifications/channels",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    request_body = CreateChannelRequest,
    responses(
        (status = 201, description = "通知渠道已创建", body = crate::api::IdResponse),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 409, description = "渠道名称已存在", body = crate::api::ApiError)
    )
)]
async fn create_channel(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateChannelRequest>,
) -> impl IntoResponse {
    // 校验渠道类型是否已注册
    if !state.notifier.registry().has_plugin(&req.channel_type) {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "unknown_channel_type",
            &format!("Unknown channel type: {}", req.channel_type),
        )
        .into_response();
    }

    // 校验 config_json：如果有实际配置内容则校验，为空时允许走 system_config_id 回退
    let config_value: serde_json::Value = match serde_json::from_str(&req.config_json) {
        Ok(v) => v,
        Err(_) => serde_json::json!({}),
    };
    let has_own_config = oxmon_notify::manager::is_meaningful_config(&config_value);

    if has_own_config {
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
        }
    } else {
        // 无配置 — 创建后将无法发送通知
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "missing_config",
            "Channel must have a valid config_json",
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
    match state.cert_store.insert_notification_channel(&row).await {
        Ok(_ch) => {
            // 写入收件人
            if !req.recipients.is_empty() {
                let _ = state
                    .cert_store
                    .set_channel_recipients(&channel_id, &req.recipients)
                    .await;
            }
            // 触发热重载
            if let Err(e) = state.notifier.reload().await {
                tracing::warn!(error = %e, "Failed to reload channels after create");
            }
            // 返回渠道 ID
            crate::api::success_id_response(StatusCode::CREATED, &trace_id, channel_id)
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                error_response(
                    StatusCode::CONFLICT,
                    &trace_id,
                    "conflict",
                    "Channel name already exists",
                )
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

/// 更新通知渠道（含配置和收件人）。
#[utoipa::path(
    put,
    path = "/v1/notifications/channels/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "渠道 ID")),
    request_body = UpdateNotificationChannelRequest,
    responses(
        (status = 200, description = "通知渠道已更新", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "渠道不存在", body = crate::api::ApiError)
    )
)]
async fn update_channel(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateNotificationChannelRequest>,
) -> impl IntoResponse {
    // 如果提供了 recipients，先保存以便后续更新
    let recipients_to_update = req.recipients.clone();

    // 转换为存储层的更新类型
    let update = oxmon_storage::NotificationChannelUpdate {
        name: req.name,
        description: req.description,
        min_severity: req.min_severity,
        enabled: req.enabled,
        config_json: req.config_json,
        recipients: req.recipients,
    };

    match state.cert_store.update_notification_channel(&id, &update).await {
        Ok(Some(_ch)) => {
            // 如果提供了 recipients，同时更新收件人列表
            if let Some(recipients) = recipients_to_update {
                if let Err(e) = state.cert_store.set_channel_recipients(&id, &recipients).await {
                    tracing::warn!(
                        channel_id = %id,
                        error = %e,
                        "Failed to update recipients during channel config update"
                    );
                    // 收件人更新失败不影响通道配置更新成功
                }
            }

            if let Err(e) = state.notifier.reload().await {
                tracing::warn!(error = %e, "Failed to reload channels after update");
            }
            // 返回渠道 ID
            crate::api::success_id_response(StatusCode::OK, &trace_id, id)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Channel not found",
        )
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

/// 删除通知渠道。
#[utoipa::path(
    delete,
    path = "/v1/notifications/channels/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "渠道 ID")),
    responses(
        (status = 200, description = "通知渠道已删除", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "渠道不存在", body = crate::api::ApiError)
    )
)]
async fn delete_channel(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_notification_channel(&id).await {
        Ok(true) => {
            if let Err(e) = state.notifier.reload().await {
                tracing::warn!(error = %e, "Failed to reload channels after delete");
            }
            crate::api::success_id_response(StatusCode::OK, &trace_id, id)
        }
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Channel not found",
        )
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

/// 静默窗口列表查询参数
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListSilenceWindowsParams {
    /// 重复规则精确匹配（daily / weekly / monthly）
    #[param(required = false, rename = "recurrence__eq")]
    #[serde(rename = "recurrence__eq")]
    recurrence_eq: Option<String>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    offset: Option<u64>,
}

/// 列出持久化的静默窗口。
#[utoipa::path(
    get,
    path = "/v1/notifications/silence-windows",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(ListSilenceWindowsParams),
    responses(
        (status = 200, description = "静默窗口列表", body = Vec<serde_json::Value>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_silence_windows(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListSilenceWindowsParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);
    let recurrence = params.recurrence_eq.as_deref();

    let total = match state.cert_store.count_silence_windows(recurrence).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count silence windows");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state
        .cert_store
        .list_silence_windows(
            &SilenceWindowFilter { recurrence_eq: recurrence.map(|s| s.to_string()) },
            limit,
            offset,
        )
        .await
    {
        Ok(windows) => {
            success_paginated_response(StatusCode::OK, &trace_id, windows, total, limit, offset)
        }
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
        (status = 201, description = "静默窗口已创建", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn create_silence_window(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateSilenceWindowRequest>,
) -> impl IntoResponse {
    // Validate time format (HH:MM)
    if !validate_time_format(&req.start_time) {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "start_time must be in HH:MM format (00:00 to 23:59)",
        )
        .into_response();
    }
    if !validate_time_format(&req.end_time) {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "end_time must be in HH:MM format (00:00 to 23:59)",
        )
        .into_response();
    }

    // Validate start_time < end_time
    if req.start_time >= req.end_time {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "start_time must be earlier than end_time",
        )
        .into_response();
    }

    // Validate recurrence if provided
    if let Some(ref rec) = req.recurrence {
        let valid_recurrences = ["daily", "weekly", "monthly"];
        if !valid_recurrences.contains(&rec.as_str()) {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "recurrence must be one of: daily, weekly, monthly",
            )
            .into_response();
        }
    }

    let row = SilenceWindowRow {
        id: oxmon_common::id::next_id(),
        start_time: req.start_time,
        end_time: req.end_time,
        recurrence: req.recurrence,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    match state.cert_store.insert_silence_window(&row).await {
        Ok(sw) => crate::api::success_id_response(StatusCode::CREATED, &trace_id, sw.id),
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

/// 获取单个静默窗口详情（按 ID）。
#[utoipa::path(
    get,
    path = "/v1/notifications/silence-windows/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "静默窗口 ID")),
    responses(
        (status = 200, description = "静默窗口详情", body = serde_json::Value),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "静默窗口不存在", body = crate::api::ApiError)
    )
)]
async fn get_silence_window(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_silence_window_by_id(&id).await {
        Ok(Some(window)) => success_response(StatusCode::OK, &trace_id, window),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Silence window not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get silence window");
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

#[derive(Deserialize, utoipa::ToSchema)]
struct UpdateSilenceWindowRequest {
    start_time: Option<String>,
    end_time: Option<String>,
    recurrence: Option<Option<String>>,
}

/// 更新静默窗口（按 ID）。
#[utoipa::path(
    put,
    path = "/v1/notifications/silence-windows/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "静默窗口 ID")),
    request_body = UpdateSilenceWindowRequest,
    responses(
        (status = 200, description = "静默窗口已更新", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "静默窗口不存在", body = crate::api::ApiError)
    )
)]
async fn update_silence_window(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSilenceWindowRequest>,
) -> impl IntoResponse {
    // Validate time format if provided
    if let Some(ref st) = req.start_time {
        if !validate_time_format(st) {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "start_time must be in HH:MM format (00:00 to 23:59)",
            )
            .into_response();
        }
    }
    if let Some(ref et) = req.end_time {
        if !validate_time_format(et) {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "end_time must be in HH:MM format (00:00 to 23:59)",
            )
            .into_response();
        }
    }

    // Validate recurrence if provided
    if let Some(Some(ref rec)) = req.recurrence {
        let valid_recurrences = ["daily", "weekly", "monthly"];
        if !valid_recurrences.contains(&rec.as_str()) {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "recurrence must be one of: daily, weekly, monthly",
            )
            .into_response();
        }
    }

    // If both start_time and end_time are provided, validate their relationship
    if let (Some(ref st), Some(ref et)) = (&req.start_time, &req.end_time) {
        if st >= et {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "start_time must be earlier than end_time",
            )
            .into_response();
        }
    }

    // If only one time is provided, need to check against existing value
    if req.start_time.is_some() != req.end_time.is_some() {
        if let Ok(Some(existing)) = state.cert_store.get_silence_window_by_id(&id).await {
            let final_start = req.start_time.as_ref().unwrap_or(&existing.start_time);
            let final_end = req.end_time.as_ref().unwrap_or(&existing.end_time);
            if final_start >= final_end {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &trace_id,
                    "bad_request",
                    "start_time must be earlier than end_time",
                )
                .into_response();
            }
        }
    }

    let recurrence_ref: Option<Option<&str>> = req
        .recurrence
        .as_ref()
        .map(|r| r.as_deref());
    match state
        .cert_store
        .update_silence_window(
            &id,
            req.start_time.as_deref(),
            req.end_time.as_deref(),
            recurrence_ref,
        )
        .await
    {
        Ok(Some(window)) => crate::api::success_id_response(StatusCode::OK, &trace_id, window.id),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Silence window not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update silence window");
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
        (status = 200, description = "静默窗口已删除", body = crate::api::IdResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "静默窗口不存在", body = crate::api::ApiError)
    )
)]
async fn delete_silence_window(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_silence_window(&id).await {
        Ok(true) => crate::api::success_id_response(StatusCode::OK, &trace_id, id),
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

// ---- Notification logs ----

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct NotificationLogQuery {
    /// 渠道 ID
    #[param(required = false)]
    channel_id: Option<String>,
    /// 渠道类型
    #[param(required = false)]
    channel_type: Option<String>,
    /// 状态（success / failed）
    #[param(required = false)]
    status: Option<String>,
    /// 告警事件 ID
    #[param(required = false)]
    alert_event_id: Option<String>,
    /// 规则 ID
    #[param(required = false)]
    rule_id: Option<String>,
    /// Agent ID
    #[param(required = false)]
    agent_id: Option<String>,
    /// 开始时间（Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    start_time: Option<u64>,
    /// 结束时间（Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    end_time: Option<u64>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    offset: Option<u64>,
}

#[derive(Serialize, ToSchema)]
struct NotificationLogItem {
    id: String,
    alert_event_id: String,
    rule_id: String,
    rule_name: String,
    agent_id: String,
    channel_id: String,
    channel_name: String,
    channel_type: String,
    status: String,
    error_message: Option<String>,
    duration_ms: i64,
    recipient_count: i32,
    severity: String,
    created_at: String,
    http_status_code: Option<i32>,
    response_body: Option<String>,
    request_body: Option<String>,
    retry_count: i32,
    recipient_details: Option<String>,
    api_message_id: Option<String>,
    api_error_code: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct NotificationLogListResponse {
    items: Vec<NotificationLogItem>,
    total: u64,
}

/// 分页查询通知发送日志。
#[utoipa::path(
    get,
    path = "/v1/notifications/logs",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(NotificationLogQuery),
    responses(
        (status = 200, description = "通知日志列表", body = NotificationLogListResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_notification_logs(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(query): Query<NotificationLogQuery>,
) -> impl IntoResponse {
    let filter = NotificationLogFilter {
        channel_id: query.channel_id,
        channel_type: query.channel_type,
        status: query.status,
        alert_event_id: query.alert_event_id,
        rule_id: query.rule_id,
        agent_id: query.agent_id,
        start_time: query.start_time.map(|v| v as i64),
        end_time: query.end_time.map(|v| v as i64),
    };

    let limit = PaginationParams::resolve_limit(query.limit);
    let offset = PaginationParams::resolve_offset(query.offset);

    let total = match state.cert_store.count_notification_logs(&filter).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count notification logs");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state
        .cert_store
        .list_notification_logs(&filter, limit, offset)
        .await
    {
        Ok(rows) => {
            let items: Vec<NotificationLogItem> = rows
                .into_iter()
                .map(|r| NotificationLogItem {
                    id: r.id,
                    alert_event_id: r.alert_event_id,
                    rule_id: r.rule_id,
                    rule_name: r.rule_name,
                    agent_id: r.agent_id,
                    channel_id: r.channel_id,
                    channel_name: r.channel_name,
                    channel_type: r.channel_type,
                    status: r.status,
                    error_message: r.error_message,
                    duration_ms: r.duration_ms,
                    recipient_count: r.recipient_count,
                    severity: r.severity,
                    created_at: r.created_at.to_rfc3339(),
                    http_status_code: r.http_status_code,
                    response_body: r.response_body,
                    request_body: r.request_body,
                    retry_count: r.retry_count,
                    recipient_details: r.recipient_details,
                    api_message_id: r.api_message_id,
                    api_error_code: r.api_error_code,
                })
                .collect();
            success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list notification logs");
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

/// 获取单个通知日志详情（按 ID）。
#[utoipa::path(
    get,
    path = "/v1/notifications/logs/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "通知日志 ID")),
    responses(
        (status = 200, description = "通知日志详情", body = NotificationLogItem),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "通知日志不存在", body = crate::api::ApiError)
    )
)]
async fn get_notification_log(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_notification_log_by_id(&id).await {
        Ok(Some(r)) => {
            let item = NotificationLogItem {
                id: r.id,
                alert_event_id: r.alert_event_id,
                rule_id: r.rule_id,
                rule_name: r.rule_name,
                agent_id: r.agent_id,
                channel_id: r.channel_id,
                channel_name: r.channel_name,
                channel_type: r.channel_type,
                status: r.status,
                error_message: r.error_message,
                duration_ms: r.duration_ms,
                recipient_count: r.recipient_count,
                severity: r.severity,
                created_at: r.created_at.to_rfc3339(),
                http_status_code: r.http_status_code,
                response_body: r.response_body,
                request_body: r.request_body,
                retry_count: r.retry_count,
                recipient_details: r.recipient_details,
                api_message_id: r.api_message_id,
                api_error_code: r.api_error_code,
            };
            success_response(StatusCode::OK, &trace_id, item)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Notification log not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get notification log");
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

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct NotificationLogSummaryQuery {
    /// 渠道 ID
    #[param(required = false)]
    channel_id: Option<String>,
    /// 渠道类型
    #[param(required = false)]
    channel_type: Option<String>,
    /// 开始时间（Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    start_time: Option<u64>,
    /// 结束时间（Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    end_time: Option<u64>,
}

#[derive(Serialize, ToSchema)]
struct NotificationLogSummaryResponse {
    total: u64,
    success: u64,
    failed: u64,
}

/// 通知发送日志统计摘要。
#[utoipa::path(
    get,
    path = "/v1/notifications/logs/summary",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(NotificationLogSummaryQuery),
    responses(
        (status = 200, description = "通知日志统计摘要", body = NotificationLogSummaryResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn notification_log_summary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(query): Query<NotificationLogSummaryQuery>,
) -> impl IntoResponse {
    let base_filter = NotificationLogFilter {
        channel_id: query.channel_id.clone(),
        channel_type: query.channel_type.clone(),
        status: None,
        alert_event_id: None,
        rule_id: None,
        agent_id: None,
        start_time: query.start_time.map(|v| v as i64),
        end_time: query.end_time.map(|v| v as i64),
    };

    let total = match state.cert_store.count_notification_logs(&base_filter).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count notification logs");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    let success_filter = NotificationLogFilter {
        status: Some("success".to_string()),
        ..base_filter
    };
    let success = match state.cert_store.count_notification_logs(&success_filter).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count success notification logs");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    let failed = total.saturating_sub(success);

    success_response(
        StatusCode::OK,
        &trace_id,
        NotificationLogSummaryResponse {
            total,
            success,
            failed,
        },
    )
}

pub fn notification_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_channels, create_channel))
        .routes(routes!(get_channel_by_id, update_channel, delete_channel))
        .routes(routes!(test_channel))
        .routes(routes!(test_cert_report))
        .routes(routes!(list_silence_windows, create_silence_window))
        .routes(routes!(
            get_silence_window,
            update_silence_window,
            delete_silence_window
        ))
        .routes(routes!(list_notification_logs))
        .routes(routes!(get_notification_log))
        .routes(routes!(notification_log_summary))
}
