use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use oxmon_common::types::{ChangePasswordRequest, LoginRequest, LoginResponse, PublicKeyResponse};
use oxmon_storage::auth::{hash_token, verify_token};
use serde::{Deserialize, Serialize};

use crate::api::{error_response, success_empty_response, success_response, ApiError};
use crate::logging::TraceId;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use oxmon_storage::AuditLogRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub token_version: i64,
    pub iat: u64,
    pub exp: u64,
}

pub fn create_token(
    secret: &str,
    user_id: &str,
    username: &str,
    token_version: i64,
    expire_secs: u64,
) -> anyhow::Result<String> {
    let now = chrono::Utc::now().timestamp() as u64;
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        token_version,
        iat: now,
        exp: now + expire_secs,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

pub fn validate_token(secret: &str, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

fn auth_error(trace_id: &str, code: &str, msg: &str) -> axum::response::Response {
    error_response(StatusCode::UNAUTHORIZED, trace_id, code, msg)
}

fn auth_error_with_status(
    status: StatusCode,
    trace_id: &str,
    code: &str,
    msg: &str,
) -> axum::response::Response {
    error_response(status, trace_id, code, msg)
}

/// JWT 鉴权中间件
pub async fn jwt_auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    // Extract trace_id from request extensions (set by logging middleware)
    let trace_id = req
        .extensions()
        .get::<TraceId>()
        .map(|t| t.0.clone())
        .unwrap_or_default();

    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        None => {
            return auth_error(&trace_id, "unauthorized", "missing authorization header");
        }
        Some(header) => {
            if let Some(token) = header.strip_prefix("Bearer ") {
                if token.is_empty() {
                    return auth_error(&trace_id, "unauthorized", "invalid authorization header");
                }
                token
            } else {
                return auth_error(&trace_id, "unauthorized", "invalid authorization header");
            }
        }
    };

    match validate_token(&state.jwt_secret, token) {
        Ok(claims) => {
            let user = match state
                .cert_store
                .get_user_by_username(&claims.username)
                .await
            {
                Ok(Some(user)) => user,
                Ok(None) => {
                    return auth_error(&trace_id, "unauthorized", "invalid token");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to query user for token validation");
                    return auth_error(&trace_id, "unauthorized", "invalid token");
                }
            };

            if user.token_version != claims.token_version {
                return auth_error(&trace_id, "unauthorized", "token revoked");
            }

            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => {
            let msg = if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                return auth_error(&trace_id, "token_expired", "token expired");
            } else {
                "invalid token"
            };
            auth_error(&trace_id, "unauthorized", msg)
        }
    }
}

/// 获取 RSA 公钥（用于前端加密密码）。
/// 鉴权：无需 Bearer Token，但需要 ox-app-id 请求头（如果在配置中启用）。
#[utoipa::path(
    get,
    path = "/v1/auth/public-key",
    tag = "Auth",
    security(("app_id_auth" = [])),
    responses(
        (status = 200, description = "RSA 公钥", body = PublicKeyResponse),
        (status = 403, description = "缺少或无效的 ox-app-id", body = ApiError)
    )
)]
pub async fn get_public_key(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    success_response(
        StatusCode::OK,
        &trace_id,
        PublicKeyResponse {
            public_key: state.password_encryptor.public_key_pem().to_string(),
            algorithm: "RSA-OAEP-SHA256".to_string(),
        },
    )
}

fn first_non_empty_csv_value(raw: &str) -> Option<String> {
    raw.split(',')
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_login_ip(headers: &HeaderMap) -> Option<String> {
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

fn lock_until_message(locked_until: DateTime<Utc>) -> String {
    format!(
        "too many failed login attempts, account is locked until {}",
        locked_until.format("%Y-%m-%dT%H:%M:%SZ")
    )
}

async fn write_login_success_audit_log(
    state: &AppState,
    trace_id: &str,
    username: &str,
    user_id: &str,
    headers: &HeaderMap,
    duration_ms: i64,
) {
    let request_body = serde_json::json!({
        "method": "POST",
        "path": "/v1/auth/login",
        "query": serde_json::Value::Null,
        "body": {
            "username": username,
            "encrypted_password": "***"
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
        user_id: user_id.to_string(),
        username: username.to_string(),
        action: "LOGIN".to_string(),
        resource_type: "auth".to_string(),
        resource_id: Some(user_id.to_string()),
        method: "POST".to_string(),
        path: "/v1/auth/login".to_string(),
        status_code: StatusCode::OK.as_u16() as i32,
        ip_address: extract_login_ip(headers),
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
        tracing::warn!(error = %error, "Failed to write login success audit log");
    }
}

async fn write_login_failure_audit_log(
    state: &AppState,
    trace_id: &str,
    username: &str,
    headers: &HeaderMap,
    status_code: StatusCode,
    failure_reason: &str,
    duration_ms: i64,
) {
    let request_body = serde_json::json!({
        "method": "POST",
        "path": "/v1/auth/login",
        "query": serde_json::Value::Null,
        "body": {
            "username": username,
            "encrypted_password": "***"
        },
        "meta": {
            "capture": "handler",
            "content_type": headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            "failure_reason": failure_reason
        }
    })
    .to_string();

    let row = AuditLogRow {
        id: oxmon_common::id::next_id(),
        user_id: String::new(),
        username: username.to_string(),
        action: "LOGIN_FAILED".to_string(),
        resource_type: "auth".to_string(),
        resource_id: None,
        method: "POST".to_string(),
        path: "/v1/auth/login".to_string(),
        status_code: status_code.as_u16() as i32,
        ip_address: extract_login_ip(headers),
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
        tracing::warn!(error = %error, "Failed to write login failure audit log");
    }
}

/// 用户登录并获取 JWT。
/// 鉴权：无需 Bearer Token，但需要 ox-app-id 请求头（如果在配置中启用）。
/// 密码需使用 RSA-OAEP(SHA-256) 加密后以 Base64 传输。
#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "Auth",
    security(("app_id_auth" = [])),
    request_body = LoginRequest,
    responses(
        (status = 200, description = "登录结果", body = LoginResponse),
        (status = 400, description = "请求参数错误", body = ApiError),
        (status = 401, description = "认证失败（用户名或密码错误或用户被禁用）", body = ApiError),
        (status = 403, description = "缺少或无效的 ox-app-id", body = ApiError),
        (status = 429, description = "登录失败次数过多，已被临时锁定", body = ApiError)
    )
)]
pub async fn login(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let ip_address = extract_login_ip(&headers);
    let start = std::time::Instant::now();

    if req.username.is_empty() || req.encrypted_password.is_empty() {
        write_login_failure_audit_log(
            &state,
            &trace_id,
            &req.username,
            &headers,
            StatusCode::BAD_REQUEST,
            "missing_credentials",
            start.elapsed().as_millis() as i64,
        )
        .await;
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "username and encrypted_password are required",
        );
    }

    let locked_until = match state
        .cert_store
        .get_login_lock_until(
            &req.username,
            ip_address.as_deref(),
            state.config.auth.login_lock_duration_hours,
        )
        .await
    {
        Ok(value) => value,
        Err(e) => {
            tracing::error!(error = %e, "Failed to query login throttle");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    };
    if let Some(locked_until) = locked_until {
        write_login_failure_audit_log(
            &state,
            &trace_id,
            &req.username,
            &headers,
            StatusCode::TOO_MANY_REQUESTS,
            "locked",
            start.elapsed().as_millis() as i64,
        )
        .await;
        return auth_error_with_status(
            StatusCode::TOO_MANY_REQUESTS,
            &trace_id,
            "too_many_attempts",
            &lock_until_message(locked_until),
        );
    }

    // Decrypt password
    let password = match state
        .password_encryptor
        .decrypt_password(&req.encrypted_password)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to decrypt login password");
            write_login_failure_audit_log(
                &state,
                &trace_id,
                &req.username,
                &headers,
                StatusCode::BAD_REQUEST,
                "decrypt_failed",
                start.elapsed().as_millis() as i64,
            )
            .await;
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "invalid encrypted password",
            );
        }
    };

    let user = match state.cert_store.get_user_by_username(&req.username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            let locked_until = match state
                .cert_store
                .register_login_failure(
                    &req.username,
                    ip_address.as_deref(),
                    state.config.auth.login_failure_threshold,
                    state.config.auth.login_lock_duration_hours,
                )
                .await
            {
                Ok(value) => value,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to persist login failure");
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &trace_id,
                        "internal_error",
                        "internal error",
                    );
                }
            };
            if let Some(locked_until) = locked_until {
                write_login_failure_audit_log(
                    &state,
                    &trace_id,
                    &req.username,
                    &headers,
                    StatusCode::TOO_MANY_REQUESTS,
                    "locked_after_failure",
                    start.elapsed().as_millis() as i64,
                )
                .await;
                return auth_error_with_status(
                    StatusCode::TOO_MANY_REQUESTS,
                    &trace_id,
                    "too_many_attempts",
                    &lock_until_message(locked_until),
                );
            }
            write_login_failure_audit_log(
                &state,
                &trace_id,
                &req.username,
                &headers,
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                start.elapsed().as_millis() as i64,
            )
            .await;
            return error_response(
                StatusCode::UNAUTHORIZED,
                &trace_id,
                "unauthorized",
                "invalid credentials",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to query user");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    };

    if user.status != "active" {
        write_login_failure_audit_log(
            &state,
            &trace_id,
            &user.username,
            &headers,
            StatusCode::UNAUTHORIZED,
            "user_disabled",
            start.elapsed().as_millis() as i64,
        )
        .await;
        return error_response(
            StatusCode::UNAUTHORIZED,
            &trace_id,
            "unauthorized",
            "user is disabled",
        );
    }

    match verify_token(&password, &user.password_hash) {
        Ok(true) => {
            if let Err(e) = state
                .cert_store
                .clear_login_failures(&user.username, ip_address.as_deref())
                .await
            {
                tracing::error!(error = %e, "Failed to clear login throttle");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "internal_error",
                    "internal error",
                );
            }
        }
        _ => {
            let locked_until = match state
                .cert_store
                .register_login_failure(
                    &user.username,
                    ip_address.as_deref(),
                    state.config.auth.login_failure_threshold,
                    state.config.auth.login_lock_duration_hours,
                )
                .await
            {
                Ok(value) => value,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to persist login failure");
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &trace_id,
                        "internal_error",
                        "internal error",
                    );
                }
            };
            if let Some(locked_until) = locked_until {
                write_login_failure_audit_log(
                    &state,
                    &trace_id,
                    &user.username,
                    &headers,
                    StatusCode::TOO_MANY_REQUESTS,
                    "locked_after_failure",
                    start.elapsed().as_millis() as i64,
                )
                .await;
                return auth_error_with_status(
                    StatusCode::TOO_MANY_REQUESTS,
                    &trace_id,
                    "too_many_attempts",
                    &lock_until_message(locked_until),
                );
            }
            write_login_failure_audit_log(
                &state,
                &trace_id,
                &user.username,
                &headers,
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                start.elapsed().as_millis() as i64,
            )
            .await;
            return error_response(
                StatusCode::UNAUTHORIZED,
                &trace_id,
                "unauthorized",
                "invalid credentials",
            );
        }
    }

    match create_token(
        &state.jwt_secret,
        &user.id,
        &user.username,
        user.token_version,
        state.token_expire_secs,
    ) {
        Ok(token) => {
            write_login_success_audit_log(
                &state,
                &trace_id,
                &user.username,
                &user.id,
                &headers,
                start.elapsed().as_millis() as i64,
            )
            .await;

            success_response(
                StatusCode::OK,
                &trace_id,
                LoginResponse {
                    access_token: token,
                    expires_in: state.token_expire_secs,
                },
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to create token");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

/// 当前登录用户登出。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "登出成功", body = ApiError),
        (status = 401, description = "未授权", body = ApiError),
        (status = 500, description = "服务器内部错误", body = ApiError)
    )
)]
pub async fn logout(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
) -> impl IntoResponse {
    match state.cert_store.bump_user_token_version(&claims.sub).await {
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "logout success"),
        Ok(false) => error_response(
            StatusCode::UNAUTHORIZED,
            &trace_id,
            "unauthorized",
            "invalid token",
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to logout user");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

/// 修改当前登录用户密码。
/// 鉴权：需要 Bearer Token。
/// 密码需使用 RSA-OAEP(SHA-256) 加密后以 Base64 传输。
#[utoipa::path(
    post,
    path = "/v1/auth/password",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "密码修改成功（需重新登录）", body = ApiError),
        (status = 400, description = "请求参数错误", body = ApiError),
        (status = 401, description = "认证失败或当前密码错误", body = ApiError),
        (status = 500, description = "服务器内部错误", body = ApiError)
    )
)]
pub async fn change_password(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(body): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    if body.encrypted_current_password.is_empty() || body.encrypted_new_password.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "encrypted_current_password and encrypted_new_password are required",
        );
    }

    // Decrypt current password
    let current_password = match state
        .password_encryptor
        .decrypt_password(&body.encrypted_current_password)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to decrypt current password");
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "invalid encrypted password",
            );
        }
    };

    // Decrypt new password
    let new_password = match state
        .password_encryptor
        .decrypt_password(&body.encrypted_new_password)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to decrypt new password");
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

    let user = match state
        .cert_store
        .get_user_by_username(&claims.username)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                &trace_id,
                "unauthorized",
                "invalid credentials",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to query user");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
    };

    match verify_token(&current_password, &user.password_hash) {
        Ok(true) => {}
        _ => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                &trace_id,
                "unauthorized",
                "invalid credentials",
            );
        }
    }

    let new_password_hash = match hash_token(&new_password) {
        Ok(hash) => hash,
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
        .update_user_password_hash(&user.id, &new_password_hash)
        .await
    {
        Ok(true) => success_empty_response(
            StatusCode::OK,
            &trace_id,
            "password changed, please login again",
        ),
        Ok(false) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &trace_id,
            "internal_error",
            "internal error",
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update password");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}
