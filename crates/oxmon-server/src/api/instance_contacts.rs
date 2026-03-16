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
use oxmon_storage::{InstanceContactFilter, InstanceContactRow, InstanceContactUpdate};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

// ---- Request / Response types ----

#[derive(Deserialize, ToSchema)]
struct CreateInstanceContactRequest {
    /// JSON 数组，多个 glob pattern，如 ["prod-web-*","cloud:tencent:ins-*"]
    agent_patterns: Vec<String>,
    contact_name: String,
    #[serde(default)]
    contact_email: Option<String>,
    #[serde(default)]
    contact_phone: Option<String>,
    #[serde(default)]
    contact_dingtalk: Option<String>,
    #[serde(default)]
    contact_webhook: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct UpdateInstanceContactRequest {
    agent_patterns: Option<Vec<String>>,
    contact_name: Option<String>,
    contact_email: Option<Option<String>>,
    contact_phone: Option<Option<String>>,
    contact_dingtalk: Option<Option<String>>,
    contact_webhook: Option<Option<String>>,
    enabled: Option<bool>,
    description: Option<Option<String>>,
}

#[derive(Deserialize, ToSchema, IntoParams)]
struct ListInstanceContactsParams {
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    limit: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    offset: Option<u64>,
    contact_name_contains: Option<String>,
    enabled_eq: Option<bool>,
}

#[derive(Serialize, ToSchema)]
struct InstanceContactItem {
    id: String,
    agent_patterns: Vec<String>,
    contact_name: String,
    contact_email: Option<String>,
    contact_phone: Option<String>,
    contact_dingtalk: Option<String>,
    contact_webhook: Option<String>,
    enabled: bool,
    description: Option<String>,
    created_at: String,
    updated_at: String,
}

fn row_to_item(row: InstanceContactRow) -> InstanceContactItem {
    let patterns: Vec<String> =
        serde_json::from_str(&row.agent_patterns).unwrap_or_default();
    InstanceContactItem {
        id: row.id,
        agent_patterns: patterns,
        contact_name: row.contact_name,
        contact_email: row.contact_email,
        contact_phone: row.contact_phone,
        contact_dingtalk: row.contact_dingtalk,
        contact_webhook: row.contact_webhook,
        enabled: row.enabled,
        description: row.description,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

// ---- Handlers ----

/// 列出实例联系人。
#[utoipa::path(
    get,
    path = "/v1/instance-contacts",
    tag = "InstanceContacts",
    security(("bearer_auth" = [])),
    params(ListInstanceContactsParams),
    responses(
        (status = 200, description = "实例联系人列表", body = Vec<InstanceContactItem>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_instance_contacts(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListInstanceContactsParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    let filter = InstanceContactFilter {
        contact_name_contains: params.contact_name_contains,
        enabled_eq: params.enabled_eq,
    };

    let total = match state.cert_store.count_instance_contacts(&filter).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count instance contacts");
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
        .list_instance_contacts(&filter, limit, offset)
        .await
    {
        Ok(rows) => {
            let items: Vec<_> = rows.into_iter().map(row_to_item).collect();
            success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list instance contacts");
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

/// 创建实例联系人。
#[utoipa::path(
    post,
    path = "/v1/instance-contacts",
    tag = "InstanceContacts",
    security(("bearer_auth" = [])),
    request_body = CreateInstanceContactRequest,
    responses(
        (status = 201, description = "实例联系人已创建", body = crate::api::IdResponse),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn create_instance_contact(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateInstanceContactRequest>,
) -> impl IntoResponse {
    if req.contact_name.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_param",
            "contact_name is required",
        )
        .into_response();
    }
    if req.agent_patterns.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_param",
            "agent_patterns must not be empty",
        )
        .into_response();
    }
    // 至少需要一种联系方式
    if req.contact_email.is_none()
        && req.contact_phone.is_none()
        && req.contact_dingtalk.is_none()
        && req.contact_webhook.is_none()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_param",
            "At least one contact method (email/phone/dingtalk/webhook) is required",
        )
        .into_response();
    }

    let row = InstanceContactRow {
        id: oxmon_common::id::next_id(),
        agent_patterns: serde_json::to_string(&req.agent_patterns).unwrap_or_default(),
        contact_name: req.contact_name,
        contact_email: req.contact_email,
        contact_phone: req.contact_phone,
        contact_dingtalk: req.contact_dingtalk,
        contact_webhook: req.contact_webhook,
        enabled: true,
        description: req.description,
        created_at: String::new(), // 由 storage 层设置
        updated_at: String::new(),
    };

    match state.cert_store.insert_instance_contact(&row).await {
        Ok(created) => {
            crate::api::success_id_response(StatusCode::CREATED, &trace_id, created.id)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to create instance contact");
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

/// 获取实例联系人详情。
#[utoipa::path(
    get,
    path = "/v1/instance-contacts/{id}",
    tag = "InstanceContacts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "联系人 ID")),
    responses(
        (status = 200, description = "实例联系人详情", body = InstanceContactItem),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "未找到", body = crate::api::ApiError)
    )
)]
async fn get_instance_contact(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_instance_contact_by_id(&id).await {
        Ok(Some(row)) => success_response(StatusCode::OK, &trace_id, row_to_item(row)),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Instance contact not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get instance contact");
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

/// 更新实例联系人。
#[utoipa::path(
    put,
    path = "/v1/instance-contacts/{id}",
    tag = "InstanceContacts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "联系人 ID")),
    request_body = UpdateInstanceContactRequest,
    responses(
        (status = 200, description = "更新成功", body = InstanceContactItem),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "未找到", body = crate::api::ApiError)
    )
)]
async fn update_instance_contact(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateInstanceContactRequest>,
) -> impl IntoResponse {
    let upd = InstanceContactUpdate {
        agent_patterns: req
            .agent_patterns
            .map(|p| serde_json::to_string(&p).unwrap_or_default()),
        contact_name: req.contact_name,
        contact_email: req.contact_email,
        contact_phone: req.contact_phone,
        contact_dingtalk: req.contact_dingtalk,
        contact_webhook: req.contact_webhook,
        enabled: req.enabled,
        description: req.description,
    };

    match state.cert_store.update_instance_contact(&id, &upd).await {
        Ok(Some(row)) => success_response(StatusCode::OK, &trace_id, row_to_item(row)),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Instance contact not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update instance contact");
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

/// 删除实例联系人。
#[utoipa::path(
    delete,
    path = "/v1/instance-contacts/{id}",
    tag = "InstanceContacts",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "联系人 ID")),
    responses(
        (status = 200, description = "删除成功"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "未找到", body = crate::api::ApiError)
    )
)]
async fn delete_instance_contact(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_instance_contact(&id).await {
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "Deleted"),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Instance contact not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete instance contact");
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

/// 查询指定实例匹配的联系人。
#[utoipa::path(
    get,
    path = "/v1/instance-contacts/match/{agent_id}",
    tag = "InstanceContacts",
    security(("bearer_auth" = [])),
    params(("agent_id" = String, Path, description = "Agent ID 或云实例虚拟 ID")),
    responses(
        (status = 200, description = "匹配的联系人列表", body = Vec<InstanceContactItem>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn match_instance_contacts(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.find_contacts_for_agent(&agent_id).await {
        Ok(rows) => {
            let items: Vec<_> = rows.into_iter().map(row_to_item).collect();
            success_response(StatusCode::OK, &trace_id, items)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to match instance contacts");
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

// ---- Routes ----

pub fn instance_contact_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_instance_contacts, create_instance_contact))
        .routes(routes!(
            get_instance_contact,
            update_instance_contact,
            delete_instance_contact
        ))
        .routes(routes!(match_instance_contacts))
}
