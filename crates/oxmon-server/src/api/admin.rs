use crate::api::pagination::{deserialize_optional_u64, PaginationParams};
use crate::api::{
    error_response, success_empty_response, success_id_response, success_paginated_response,
    success_response,
};
use crate::auth::Claims;
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use oxmon_common::types::{
    AdminUserResponse, CreateAdminUserRequest, ResetAdminPasswordRequest,
    UnlockLoginThrottleRequest, UpdateAdminUserRequest,
};
use oxmon_storage::auth::hash_token;
use oxmon_storage::{AuditLogRow, StorageEngine};
use serde::{Deserialize, Serialize};
use utoipa_axum::{router::OpenApiRouter, routes};

fn to_admin_user_response(user: oxmon_common::types::User) -> AdminUserResponse {
    AdminUserResponse {
        id: user.id,
        username: user.username,
        status: user.status,
        avatar: user.avatar,
        phone: user.phone,
        email: user.email,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}
fn first_non_empty_csv_value(raw: &str) -> Option<String> {
    raw.split(',')
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(first_non_empty_csv_value)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
}

async fn write_unlock_login_throttle_audit_log(
    state: &AppState,
    trace_id: &str,
    claims: &Claims,
    headers: &HeaderMap,
    req: &UnlockLoginThrottleRequest,
    affected_count: u64,
    duration_ms: i64,
) {
    let request_body = serde_json::json!({
        "method": "POST",
        "path": "/v1/admin/users/unlock-login-throttle",
        "query": serde_json::Value::Null,
        "body": {
            "username": req.username,
            "ip_address": req.ip_address,
        },
        "meta": {
            "capture": "handler",
            "affected_count": affected_count,
            "content_type": headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
        }
    })
    .to_string();

    let row = AuditLogRow {
        id: oxmon_common::id::next_id(),
        user_id: claims.sub.to_string(),
        username: claims.username.to_string(),
        action: "UNLOCK_LOGIN_THROTTLE".to_string(),
        resource_type: "auth".to_string(),
        resource_id: Some(req.username.clone()),
        method: "POST".to_string(),
        path: "/v1/admin/users/unlock-login-throttle".to_string(),
        status_code: StatusCode::OK.as_u16() as i32,
        ip_address: extract_client_ip(headers),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string()),
        trace_id: Some(trace_id.to_string()),
        request_body: Some(request_body),
        duration_ms,
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    };

    if let Err(error) = state.cert_store.insert_audit_log(row).await {
        tracing::warn!(error = %error, "Failed to write unlock login throttle audit log");
    }
}

async fn write_reset_admin_password_audit_log(
    state: &AppState,
    trace_id: &str,
    claims: &Claims,
    headers: &HeaderMap,
    target_user_id: &str,
    duration_ms: i64,
) {
    let request_body = serde_json::json!({
        "method": "POST",
        "path": format!("/v1/admin/users/{target_user_id}/password"),
        "query": serde_json::Value::Null,
        "body": {
            "encrypted_new_password": "***"
        },
        "meta": {
            "capture": "handler",
            "content_type": headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
        }
    })
    .to_string();

    let row = AuditLogRow {
        id: oxmon_common::id::next_id(),
        user_id: claims.sub.to_string(),
        username: claims.username.to_string(),
        action: "RESET_ADMIN_PASSWORD".to_string(),
        resource_type: "auth".to_string(),
        resource_id: Some(target_user_id.to_string()),
        method: "POST".to_string(),
        path: format!("/v1/admin/users/{target_user_id}/password"),
        status_code: StatusCode::OK.as_u16() as i32,
        ip_address: extract_client_ip(headers),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string()),
        trace_id: Some(trace_id.to_string()),
        request_body: Some(request_body),
        duration_ms,
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    };

    if let Err(error) = state.cert_store.insert_audit_log(row).await {
        tracing::warn!(error = %error, "Failed to write reset admin password audit log");
    }
}

async fn write_delete_admin_user_audit_log(
    state: &AppState,
    trace_id: &str,
    claims: &Claims,
    headers: &HeaderMap,
    target_user_id: &str,
    duration_ms: i64,
) {
    let request_body = serde_json::json!({
        "method": "DELETE",
        "path": format!("/v1/admin/users/{target_user_id}"),
        "query": serde_json::Value::Null,
        "body": serde_json::Value::Null,
        "meta": {
            "capture": "handler"
        }
    })
    .to_string();

    let row = AuditLogRow {
        id: oxmon_common::id::next_id(),
        user_id: claims.sub.to_string(),
        username: claims.username.to_string(),
        action: "DELETE_ADMIN_USER".to_string(),
        resource_type: "auth".to_string(),
        resource_id: Some(target_user_id.to_string()),
        method: "DELETE".to_string(),
        path: format!("/v1/admin/users/{target_user_id}"),
        status_code: StatusCode::OK.as_u16() as i32,
        ip_address: extract_client_ip(headers),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string()),
        trace_id: Some(trace_id.to_string()),
        request_body: Some(request_body),
        duration_ms,
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    };

    if let Err(error) = state.cert_store.insert_audit_log(row).await {
        tracing::warn!(error = %error, "Failed to write delete admin user audit log");
    }
}

async fn write_create_admin_user_audit_log(
    state: &AppState,
    trace_id: &str,
    claims: &Claims,
    headers: &HeaderMap,
    req: &CreateAdminUserRequest,
    target_user_id: &str,
    duration_ms: i64,
) {
    let request_body = serde_json::json!({
        "method": "POST",
        "path": "/v1/admin/users",
        "query": serde_json::Value::Null,
        "body": {
            "username": req.username,
            "encrypted_password": "***",
            "status": req.status,
            "avatar": req.avatar,
            "phone": req.phone,
            "email": req.email,
        },
        "meta": {
            "capture": "handler",
            "content_type": headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
        }
    })
    .to_string();

    let row = AuditLogRow {
        id: oxmon_common::id::next_id(),
        user_id: claims.sub.to_string(),
        username: claims.username.to_string(),
        action: "CREATE_ADMIN_USER".to_string(),
        resource_type: "auth".to_string(),
        resource_id: Some(target_user_id.to_string()),
        method: "POST".to_string(),
        path: "/v1/admin/users".to_string(),
        status_code: StatusCode::CREATED.as_u16() as i32,
        ip_address: extract_client_ip(headers),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string()),
        trace_id: Some(trace_id.to_string()),
        request_body: Some(request_body),
        duration_ms,
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    };

    if let Err(error) = state.cert_store.insert_audit_log(row).await {
        tracing::warn!(error = %error, "Failed to write create admin user audit log");
    }
}

async fn write_update_admin_user_audit_log(
    state: &AppState,
    trace_id: &str,
    claims: &Claims,
    headers: &HeaderMap,
    target_user_id: &str,
    req: &UpdateAdminUserRequest,
    duration_ms: i64,
) {
    let request_body = serde_json::json!({
        "method": "PUT",
        "path": format!("/v1/admin/users/{target_user_id}"),
        "query": serde_json::Value::Null,
        "body": {
            "status": req.status,
            "avatar": req.avatar,
            "phone": req.phone,
            "email": req.email,
        },
        "meta": {
            "capture": "handler",
            "content_type": headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
        }
    })
    .to_string();

    let row = AuditLogRow {
        id: oxmon_common::id::next_id(),
        user_id: claims.sub.to_string(),
        username: claims.username.to_string(),
        action: "UPDATE_ADMIN_USER".to_string(),
        resource_type: "auth".to_string(),
        resource_id: Some(target_user_id.to_string()),
        method: "PUT".to_string(),
        path: format!("/v1/admin/users/{target_user_id}"),
        status_code: StatusCode::OK.as_u16() as i32,
        ip_address: extract_client_ip(headers),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string()),
        trace_id: Some(trace_id.to_string()),
        request_body: Some(request_body),
        duration_ms,
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    };

    if let Err(error) = state.cert_store.insert_audit_log(row).await {
        tracing::warn!(error = %error, "Failed to write update admin user audit log");
    }
}

/// 管理员用户列表查询参数
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct AdminUserListParams {
    /// 用户名包含匹配（可选）
    #[param(required = false)]
    #[serde(rename = "username__contains")]
    username_contains: Option<String>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    offset: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct LoginThrottleItem {
    pub id: String,
    pub username: String,
    pub ip_address: String,
    pub failure_count: i32,
    pub last_failed_at: String,
    pub locked_until: Option<String>,
    pub updated_at: String,
}
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct LoginThrottleListData {
    pub items: Vec<LoginThrottleItem>,
    pub total: u64,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct LoginThrottleListResponse {
    pub err_code: i32,
    pub err_msg: String,
    pub trace_id: String,
    pub data: LoginThrottleListData,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct LoginThrottleListParams {
    /// 用户名精确匹配（可选）
    #[param(required = false)]
    username: Option<String>,
    /// IP 精确匹配（可选）
    #[param(required = false)]
    ip_address: Option<String>,
    /// 是否仅返回当前仍被锁定的记录（默认 true）
    #[param(required = false)]
    locked_only: Option<bool>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    offset: Option<u64>,
}

/// 获取当前登录锁定列表。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/admin/users/login-throttles",
    tag = "Admin",
    security(("bearer_auth" = [])),
    params(LoginThrottleListParams),
    responses(
        (status = 200, description = "登录锁定列表", body = LoginThrottleListResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_login_throttles(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<LoginThrottleListParams>,
) -> impl IntoResponse {
    let pagination = PaginationParams {
        limit: params.limit,
        offset: params.offset,
    };
    let limit = pagination.limit();
    let offset = pagination.offset();
    let filter = oxmon_storage::LoginThrottleFilter {
        username: params.username,
        ip_address: params.ip_address,
        locked_only: params.locked_only.unwrap_or(true),
    };

    let (rows, total) = match tokio::try_join!(
        state
            .cert_store
            .list_login_throttles(&filter, limit as u64, offset as u64),
        state.cert_store.count_login_throttles(&filter),
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list login throttles");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    };

    let items: Vec<LoginThrottleItem> = rows
        .into_iter()
        .map(|row| LoginThrottleItem {
            id: row.id,
            username: row.username,
            ip_address: row.ip_address,
            failure_count: row.failure_count,
            last_failed_at: row.last_failed_at,
            locked_until: row.locked_until,
            updated_at: row.updated_at,
        })
        .collect();

    success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
}

/// 获取管理员用户列表。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/admin/users",
    tag = "Admin",
    security(("bearer_auth" = [])),
    params(AdminUserListParams),
    responses(
        (status = 200, description = "用户列表", body = Vec<AdminUserResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_admin_users(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<AdminUserListParams>,
) -> impl IntoResponse {
    let pagination = PaginationParams {
        limit: params.limit,
        offset: params.offset,
    };
    let limit = pagination.limit();
    let offset = pagination.offset();
    let username_contains = params.username_contains.as_deref();

    let (users, total) = match tokio::try_join!(
        state
            .cert_store
            .list_users(username_contains, limit as u64, offset as u64),
        state.cert_store.count_users_filtered(username_contains),
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list admin users");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    };

    let items: Vec<AdminUserResponse> = users.into_iter().map(to_admin_user_response).collect();
    success_paginated_response(
        StatusCode::OK,
        &trace_id,
        items,
        total as u64,
        limit,
        offset,
    )
}

/// 创建管理员用户。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/admin/users",
    tag = "Admin",
    security(("bearer_auth" = [])),
    request_body = CreateAdminUserRequest,
    responses(
        (status = 201, description = "创建成功，返回用户 ID"),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 409, description = "用户名已存在", body = crate::api::ApiError)
    )
)]
async fn create_admin_user(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<CreateAdminUserRequest>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    if req.username.is_empty() || req.encrypted_password.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "username and encrypted_password are required",
        );
    }

    // 校验 status 值
    if let Some(ref s) = req.status {
        if s != "active" && s != "disabled" {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "status must be 'active' or 'disabled'",
            );
        }
    }

    // 解密密码
    let password = match state
        .password_encryptor
        .decrypt_password(&req.encrypted_password)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to decrypt password for new admin user");
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "invalid encrypted password",
            );
        }
    };

    if password.len() < 8 {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "password must be at least 8 characters long",
        );
    }

    // 检查用户名是否已存在
    match state.cert_store.get_user_by_username(&req.username).await {
        Ok(Some(_)) => {
            return error_response(
                StatusCode::CONFLICT,
                &trace_id,
                "conflict",
                "username already exists",
            );
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "Failed to check username existence");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    }

    let password_hash = match hash_token(&password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "Failed to hash password");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    };

    match state
        .cert_store
        .create_user(
            &req.username,
            &password_hash,
            req.status.as_deref(),
            req.avatar.as_deref(),
            req.phone.as_deref(),
            req.email.as_deref(),
        )
        .await
    {
        Ok(id) => {
            write_create_admin_user_audit_log(
                &state,
                &trace_id,
                &claims,
                &headers,
                &req,
                &id,
                start.elapsed().as_millis() as i64,
            )
            .await;
            success_id_response(StatusCode::CREATED, &trace_id, id)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to create admin user");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

/// 获取单个管理员用户详情。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/admin/users/{id}",
    tag = "Admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "用户 ID")
    ),
    responses(
        (status = 200, description = "用户详情", body = AdminUserResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "用户不存在", body = crate::api::ApiError)
    )
)]
async fn get_admin_user(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_user_by_id(&id).await {
        Ok(Some(user)) => success_response(StatusCode::OK, &trace_id, to_admin_user_response(user)),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "user not found",
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get admin user");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

/// 更新管理员用户信息（status / avatar / phone / email）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    put,
    path = "/v1/admin/users/{id}",
    tag = "Admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "用户 ID")
    ),
    request_body = UpdateAdminUserRequest,
    responses(
        (status = 200, description = "更新成功", body = AdminUserResponse),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "用户不存在", body = crate::api::ApiError)
    )
)]
async fn update_admin_user(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAdminUserRequest>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    // 校验 status 值
    if let Some(ref s) = req.status {
        if s != "active" && s != "disabled" {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "status must be 'active' or 'disabled'",
            );
        }
    }

    match state
        .cert_store
        .update_user(
            &id,
            req.status.as_deref(),
            req.avatar.as_deref(),
            req.phone.as_deref(),
            req.email.as_deref(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "user not found",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to update admin user");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    }

    // 返回更新后的用户信息
    match state.cert_store.get_user_by_id(&id).await {
        Ok(Some(user)) => {
            write_update_admin_user_audit_log(
                &state,
                &trace_id,
                &claims,
                &headers,
                &id,
                &req,
                start.elapsed().as_millis() as i64,
            )
            .await;
            success_response(StatusCode::OK, &trace_id, to_admin_user_response(user))
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "user not found",
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to fetch updated admin user");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

/// 手动清除某个账号的登录失败锁定。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/admin/users/unlock-login-throttle",
    tag = "Admin",
    security(("bearer_auth" = [])),
    request_body = UnlockLoginThrottleRequest,
    responses(
        (status = 200, description = "解锁成功", body = crate::api::EmptySuccessResponse),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 500, description = "服务器内部错误", body = crate::api::ApiError)
    )
)]
async fn unlock_login_throttle(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(req): Json<UnlockLoginThrottleRequest>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    if req.username.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "username is required",
        );
    }

    let affected = if let Some(ip_address) = req.ip_address.as_deref() {
        vec![(req.username.clone(), ip_address.to_string())]
    } else {
        match state
            .cert_store
            .list_login_throttles(
                &oxmon_storage::LoginThrottleFilter {
                    username: Some(req.username.clone()),
                    ip_address: None,
                    locked_only: false,
                },
                1000,
                0,
            )
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|row| (row.username, row.ip_address))
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "Failed to query login throttles for unlock");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "internal_error",
                    "internal error",
                );
            }
        }
    };

    let result = if let Some(ip_address) = req.ip_address.as_deref() {
        state
            .cert_store
            .clear_login_failures(&req.username, Some(ip_address))
            .await
            .map(|_| 1)
    } else {
        state
            .cert_store
            .clear_login_failures_by_username(&req.username)
            .await
    };

    match result {
        Ok(affected_count) => {
            for (username, ip_address) in affected {
                let alert_id = crate::auth::login_lock_alert_id(&username, &ip_address);
                let _ = state.storage.resolve_alert(&alert_id).await;
            }
            write_unlock_login_throttle_audit_log(
                &state,
                &trace_id,
                &claims,
                &headers,
                &req,
                affected_count,
                start.elapsed().as_millis() as i64,
            )
            .await;
            success_empty_response(StatusCode::OK, &trace_id, "unlock success")
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to clear login throttle");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

/// 重置指定管理员用户密码。
/// 鉴权：需要 Bearer Token。
/// 密码使用 RSA-OAEP(SHA-256) 加密后以 Base64 传输。
/// 重置后该用户所有 JWT 立即失效，需重新登录。
#[utoipa::path(
    post,
    path = "/v1/admin/users/{id}/password",
    tag = "Admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "用户 ID")
    ),
    request_body = ResetAdminPasswordRequest,
    responses(
        (status = 200, description = "密码重置成功", body = crate::api::EmptySuccessResponse),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "用户不存在", body = crate::api::ApiError)
    )
)]
async fn reset_admin_user_password(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(id): Path<String>,
    Json(req): Json<ResetAdminPasswordRequest>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    if req.encrypted_new_password.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "encrypted_new_password is required",
        );
    }

    let new_password = match state
        .password_encryptor
        .decrypt_password(&req.encrypted_new_password)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to decrypt new password for reset");
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "invalid encrypted password",
            );
        }
    };

    if new_password.len() < 8 {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "new_password must be at least 8 characters long",
        );
    }

    let new_password_hash = match hash_token(&new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "Failed to hash new password");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    };

    match state
        .cert_store
        .update_user_password_hash(&id, &new_password_hash)
        .await
    {
        Ok(true) => {
            write_reset_admin_password_audit_log(
                &state,
                &trace_id,
                &claims,
                &headers,
                &id,
                start.elapsed().as_millis() as i64,
            )
            .await;
            success_empty_response(StatusCode::OK, &trace_id, "password reset successfully")
        }
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "user not found",
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to reset admin user password");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

/// 删除管理员用户。
/// 鉴权：需要 Bearer Token。
/// 不允许删除当前登录用户自身。
#[utoipa::path(
    delete,
    path = "/v1/admin/users/{id}",
    tag = "Admin",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "用户 ID")
    ),
    responses(
        (status = 200, description = "删除成功", body = crate::api::EmptySuccessResponse),
        (status = 400, description = "不能删除自身", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "用户不存在", body = crate::api::ApiError)
    )
)]
async fn delete_admin_user(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    // 防止删除自身
    if claims.sub == id {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "cannot delete your own account",
        );
    }

    match state.cert_store.delete_user(&id).await {
        Ok(true) => {
            write_delete_admin_user_audit_log(
                &state,
                &trace_id,
                &claims,
                &headers,
                &id,
                start.elapsed().as_millis() as i64,
            )
            .await;
            success_empty_response(StatusCode::OK, &trace_id, "user deleted")
        }
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "user not found",
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete admin user");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

pub fn admin_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_admin_users, create_admin_user))
        .routes(routes!(list_login_throttles, unlock_login_throttle))
        .routes(routes!(
            get_admin_user,
            update_admin_user,
            delete_admin_user
        ))
        .routes(routes!(reset_admin_user_password))
}
