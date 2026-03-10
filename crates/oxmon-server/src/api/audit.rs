use crate::api::pagination::{deserialize_optional_u64, PaginationParams};
use crate::api::{error_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{Duration, Timelike, Utc};
use oxmon_storage::AuditLogFilter;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 审计日志列表条目
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditLogItem {
    /// 日志 ID
    pub id: String,
    /// 操作用户 ID
    pub user_id: String,
    /// 操作用户名
    pub username: String,
    /// 操作动作：CREATE / UPDATE / DELETE
    pub action: String,
    /// 资源类型（路径第一段，如 alerts、notifications 等）
    pub resource_type: String,
    /// 资源 ID（可为空）
    pub resource_id: Option<String>,
    /// HTTP 方法
    pub method: String,
    /// 请求路径
    pub path: String,
    /// HTTP 状态码
    pub status_code: i32,
    /// 客户端 IP
    pub ip_address: Option<String>,
    /// User-Agent
    pub user_agent: Option<String>,
    /// 链路追踪 ID
    pub trace_id: Option<String>,
    /// 请求耗时（毫秒）
    pub duration_ms: i64,
    /// 创建时间（ISO 8601）
    pub created_at: String,
}

/// 审计日志详情
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditLogDetail {
    /// 日志 ID
    pub id: String,
    /// 操作用户 ID
    pub user_id: String,
    /// 操作用户名
    pub username: String,
    /// 操作动作：CREATE / UPDATE / DELETE
    pub action: String,
    /// 资源类型（路径第一段，如 alerts、notifications 等）
    pub resource_type: String,
    /// 资源 ID（可为空）
    pub resource_id: Option<String>,
    /// HTTP 方法
    pub method: String,
    /// 请求路径
    pub path: String,
    /// HTTP 状态码
    pub status_code: i32,
    /// 客户端 IP
    pub ip_address: Option<String>,
    /// User-Agent
    pub user_agent: Option<String>,
    /// 链路追踪 ID
    pub trace_id: Option<String>,
    /// 请求参数/请求体快照
    pub request_body: Option<String>,
    /// 请求耗时（毫秒）
    pub duration_ms: i64,
    /// 创建时间（ISO 8601）
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct AuditSecurityTopItem {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct AuditSecuritySummary {
    pub hours: u64,
    pub window_start: String,
    pub login_success_count: u64,
    pub login_failed_count: u64,
    pub lock_triggered_count: u64,
    pub unique_failed_ips: u64,
    pub unique_failed_usernames: u64,
    pub top_failed_ips: Vec<AuditSecurityTopItem>,
    pub top_failed_usernames: Vec<AuditSecurityTopItem>,
}

#[derive(Debug, Serialize, ToSchema)]
struct AuditSecurityTimeseriesPoint {
    pub hour: String,
    pub login_success_count: u64,
    pub login_failed_count: u64,
    pub lock_triggered_count: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct AuditSecurityTimeseries {
    pub hours: u64,
    pub window_start: String,
    pub points: Vec<AuditSecurityTimeseriesPoint>,
}

/// 审计日志列表查询参数
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AuditSecuritySummaryParams {
    /// 统计窗口小时数（默认 24）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub hours: Option<u64>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AuditSecurityTimeseriesParams {
    /// 统计窗口小时数（默认 24）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub hours: Option<u64>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListAuditLogsParams {
    /// 过滤用户 ID
    pub user_id: Option<String>,
    /// 用户名包含匹配（可选）
    #[serde(rename = "username__contains")]
    pub username_contains: Option<String>,
    /// 过滤操作动作（如 LOGIN / LOGIN_FAILED / LOGOUT / CREATE / UPDATE / DELETE）
    pub action: Option<String>,
    /// 过滤资源类型
    pub resource_type: Option<String>,
    /// 过滤客户端 IP（精确匹配）
    pub ip_address: Option<String>,
    /// 请求路径包含匹配（可选）
    #[serde(rename = "path__contains")]
    pub path_contains: Option<String>,
    /// 过滤 HTTP 状态码（可选）
    pub status_code: Option<i32>,
    /// 开始时间（ISO 8601，如 2026-01-01T00:00:00Z）
    pub start_time: Option<String>,
    /// 结束时间（ISO 8601）
    pub end_time: Option<String>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub offset: Option<u64>,
}

impl From<ListAuditLogsParams> for (AuditLogFilter, PaginationParams) {
    fn from(p: ListAuditLogsParams) -> Self {
        let filter = AuditLogFilter {
            user_id: p.user_id,
            username_contains: p.username_contains,
            action: p.action,
            resource_type: p.resource_type,
            ip_address: p.ip_address,
            path_contains: p.path_contains,
            status_code: p.status_code,
            start_time: p.start_time,
            end_time: p.end_time,
        };
        let pagination = PaginationParams {
            limit: p.limit,
            offset: p.offset,
        };
        (filter, pagination)
    }
}

/// 获取审计日志列表（分页）
#[utoipa::path(
    get,
    path = "/v1/audit/logs",
    tag = "Audit",
    security(("bearer_auth" = [])),
    params(ListAuditLogsParams),
    responses(
        (status = 200, description = "审计日志列表"),
        (status = 401, description = "未授权")
    )
)]
async fn list_audit_logs(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListAuditLogsParams>,
) -> impl IntoResponse {
    let (filter, pagination) = (params).into();
    let limit = pagination.limit();
    let offset = pagination.offset();

    let (items_result, total_result) = tokio::join!(
        state
            .cert_store
            .list_audit_logs(&filter, limit as u64, offset as u64),
        state.cert_store.count_audit_logs(&filter),
    );

    let items = match items_result {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list audit logs");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "failed to query audit logs",
            );
        }
    };

    let total = match total_result {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count audit logs");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "failed to count audit logs",
            );
        }
    };

    let dto: Vec<AuditLogItem> = items
        .into_iter()
        .map(|r| AuditLogItem {
            id: r.id,
            user_id: r.user_id,
            username: r.username,
            action: r.action,
            resource_type: r.resource_type,
            resource_id: r.resource_id,
            method: r.method,
            path: r.path,
            status_code: r.status_code,
            ip_address: r.ip_address,
            user_agent: r.user_agent,
            trace_id: r.trace_id,
            duration_ms: r.duration_ms,
            created_at: r.created_at,
        })
        .collect();

    success_paginated_response(StatusCode::OK, &trace_id, dto, total, limit, offset)
}

/// 获取登录安全趋势（按小时聚合）。
#[utoipa::path(
    get,
    path = "/v1/audit/logs/security-summary/timeseries",
    tag = "Audit",
    security(("bearer_auth" = [])),
    params(AuditSecurityTimeseriesParams),
    responses(
        (status = 200, description = "登录安全趋势", body = AuditSecurityTimeseries),
        (status = 401, description = "未授权")
    )
)]
async fn get_audit_security_timeseries(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<AuditSecurityTimeseriesParams>,
) -> impl IntoResponse {
    let hours = params.hours.unwrap_or(24).max(1);
    let now = Utc::now();
    let current_hour = now
        .with_minute(0)
        .and_then(|dt| dt.with_second(0))
        .and_then(|dt| dt.with_nanosecond(0))
        .unwrap_or(now);
    let start_dt = current_hour - Duration::hours(hours as i64 - 1);
    let window_start = start_dt.to_rfc3339();
    let rows = match state
        .cert_store
        .list_login_security_audit_logs(&window_start)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "Failed to query audit security timeseries");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "failed to query audit security timeseries",
            );
        }
    };

    let mut buckets: std::collections::BTreeMap<String, AuditSecurityTimeseriesPoint> =
        std::collections::BTreeMap::new();
    for offset in 0..hours {
        let bucket_start = start_dt + Duration::hours(offset as i64);
        let hour = bucket_start.format("%Y-%m-%dT%H:00:00Z").to_string();
        buckets.insert(
            hour.clone(),
            AuditSecurityTimeseriesPoint {
                hour,
                login_success_count: 0,
                login_failed_count: 0,
                lock_triggered_count: 0,
            },
        );
    }

    for row in rows {
        let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&row.created_at) else {
            continue;
        };
        let hour = dt
            .with_timezone(&Utc)
            .format("%Y-%m-%dT%H:00:00Z")
            .to_string();
        let Some(point) = buckets.get_mut(&hour) else {
            continue;
        };
        match row.action.as_str() {
            "LOGIN" => point.login_success_count += 1,
            "LOGIN_FAILED" => {
                point.login_failed_count += 1;
                if row.status_code == 429 {
                    point.lock_triggered_count += 1;
                }
            }
            _ => {}
        }
    }

    success_response(
        StatusCode::OK,
        &trace_id,
        AuditSecurityTimeseries {
            hours,
            window_start,
            points: buckets.into_values().collect(),
        },
    )
}

/// 按 ID 获取单条审计日志
#[utoipa::path(
    get,
    path = "/v1/audit/logs/{id}",
    tag = "Audit",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "审计日志 ID")
    ),
    responses(
        (status = 200, description = "审计日志详情"),
        (status = 404, description = "未找到"),
        (status = 401, description = "未授权")
    )
)]
async fn get_audit_log(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_audit_log(&id).await {
        Ok(Some(row)) => {
            let item = AuditLogDetail {
                id: row.id,
                user_id: row.user_id,
                username: row.username,
                action: row.action,
                resource_type: row.resource_type,
                resource_id: row.resource_id,
                method: row.method,
                path: row.path,
                status_code: row.status_code,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                trace_id: row.trace_id,
                request_body: row.request_body,
                duration_ms: row.duration_ms,
                created_at: row.created_at,
            };
            success_response(StatusCode::OK, &trace_id, item)
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "audit log not found",
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get audit log");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "failed to get audit log",
            )
        }
    }
}

/// 获取登录安全审计概览。
#[utoipa::path(
    get,
    path = "/v1/audit/logs/security-summary",
    tag = "Audit",
    security(("bearer_auth" = [])),
    params(AuditSecuritySummaryParams),
    responses(
        (status = 200, description = "登录安全审计概览", body = AuditSecuritySummary),
        (status = 401, description = "未授权")
    )
)]
async fn get_audit_security_summary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<AuditSecuritySummaryParams>,
) -> impl IntoResponse {
    let hours = params.hours.unwrap_or(24).max(1);
    let window_start = (Utc::now() - Duration::hours(hours as i64)).to_rfc3339();
    let rows = match state
        .cert_store
        .list_login_security_audit_logs(&window_start)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "Failed to query audit security summary");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "failed to query audit security summary",
            );
        }
    };

    let mut login_success_count = 0_u64;
    let mut login_failed_count = 0_u64;
    let mut lock_triggered_count = 0_u64;
    let mut failed_ip_counts: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    let mut failed_username_counts: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();

    for row in &rows {
        match row.action.as_str() {
            "LOGIN" => login_success_count += 1,
            "LOGIN_FAILED" => {
                login_failed_count += 1;
                if row.status_code == 429 {
                    lock_triggered_count += 1;
                }
                if let Some(ip_address) = row.ip_address.as_deref() {
                    *failed_ip_counts.entry(ip_address.to_string()).or_insert(0) += 1;
                }
                if !row.username.is_empty() {
                    *failed_username_counts
                        .entry(row.username.clone())
                        .or_insert(0) += 1;
                }
            }
            _ => {}
        }
    }

    let mut top_failed_ips: Vec<AuditSecurityTopItem> = failed_ip_counts
        .into_iter()
        .map(|(key, count)| AuditSecurityTopItem { key, count })
        .collect();
    top_failed_ips.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    top_failed_ips.truncate(10);

    let mut top_failed_usernames: Vec<AuditSecurityTopItem> = failed_username_counts
        .into_iter()
        .map(|(key, count)| AuditSecurityTopItem { key, count })
        .collect();
    top_failed_usernames.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    top_failed_usernames.truncate(10);

    success_response(
        StatusCode::OK,
        &trace_id,
        AuditSecuritySummary {
            hours,
            window_start,
            login_success_count,
            login_failed_count,
            lock_triggered_count,
            unique_failed_ips: top_failed_ips.len() as u64,
            unique_failed_usernames: top_failed_usernames.len() as u64,
            top_failed_ips,
            top_failed_usernames,
        },
    )
}

pub fn audit_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_audit_logs))
        .routes(routes!(get_audit_security_summary))
        .routes(routes!(get_audit_security_timeseries))
        .routes(routes!(get_audit_log))
}
