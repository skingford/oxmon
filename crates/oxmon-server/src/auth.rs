use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{Request, StatusCode};
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
        (status = 401, description = "认证失败（用户名或密码错误）", body = ApiError),
        (status = 403, description = "缺少或无效的 ox-app-id", body = ApiError)
    )
)]
pub async fn login(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    if req.username.is_empty() || req.encrypted_password.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "bad_request",
            "username and encrypted_password are required",
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

    match verify_token(&password, &user.password_hash) {
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

    match create_token(
        &state.jwt_secret,
        &user.id,
        &user.username,
        user.token_version,
        state.token_expire_secs,
    ) {
        Ok(token) => success_response(
            StatusCode::OK,
            &trace_id,
            LoginResponse {
                access_token: token,
                expires_in: state.token_expire_secs,
            },
        ),
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
