use crate::api::pagination::{deserialize_optional_u64, PaginationParams};
use crate::api::{
    error_response, success_empty_response, success_id_response, success_paginated_response,
    success_response,
};
use crate::auth::Claims;
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use oxmon_common::types::{
    AdminUserResponse, CreateAdminUserRequest, ResetAdminPasswordRequest,
};
use oxmon_storage::auth::hash_token;
use serde::Deserialize;
use utoipa_axum::{router::OpenApiRouter, routes};

fn to_admin_user_response(user: oxmon_common::types::User) -> AdminUserResponse {
    AdminUserResponse {
        id: user.id,
        username: user.username,
        created_at: user.created_at,
        updated_at: user.updated_at,
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
        state
            .cert_store
            .count_users_filtered(username_contains),
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
    Json(req): Json<CreateAdminUserRequest>,
) -> impl IntoResponse {
    if req.username.is_empty() || req.encrypted_password.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "username and encrypted_password are required",
        );
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
        .create_user(&req.username, &password_hash)
        .await
    {
        Ok(id) => success_id_response(StatusCode::CREATED, &trace_id, id),
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
        Ok(Some(user)) => success_response(
            StatusCode::OK,
            &trace_id,
            to_admin_user_response(user),
        ),
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
        (status = 200, description = "密码重置成功"),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "用户不存在", body = crate::api::ApiError)
    )
)]
async fn reset_admin_user_password(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ResetAdminPasswordRequest>,
) -> impl IntoResponse {
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
        Ok(true) => success_empty_response(
            StatusCode::OK,
            &trace_id,
            "password reset successfully",
        ),
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
        (status = 200, description = "删除成功"),
        (status = 400, description = "不能删除自身", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "用户不存在", body = crate::api::ApiError)
    )
)]
async fn delete_admin_user(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Path(id): Path<String>,
) -> impl IntoResponse {
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
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "user deleted"),
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
        .routes(routes!(get_admin_user, delete_admin_user))
        .routes(routes!(reset_admin_user_password))
}
