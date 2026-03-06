use crate::api::pagination::{deserialize_optional_u64, PaginationParams};
use crate::api::{error_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use oxmon_storage::AuditLogFilter;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 审计日志条目
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

/// 审计日志列表查询参数
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListAuditLogsParams {
    /// 过滤用户 ID
    pub user_id: Option<String>,
    /// 过滤操作动作（CREATE / UPDATE / DELETE）
    pub action: Option<String>,
    /// 过滤资源类型
    pub resource_type: Option<String>,
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
            action: p.action,
            resource_type: p.resource_type,
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
            let item = AuditLogItem {
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
                duration_ms: row.duration_ms,
                created_at: row.created_at,
            };
            success_response(StatusCode::OK, &trace_id, item)
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, &trace_id, "not_found", "audit log not found"),
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

pub fn audit_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_audit_logs))
        .routes(routes!(get_audit_log))
}
