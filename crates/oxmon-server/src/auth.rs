use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Json;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use oxmon_common::types::{ChangePasswordRequest, LoginRequest, LoginResponse};
use oxmon_storage::auth::{hash_token, verify_token};
use serde::{Deserialize, Serialize};

use crate::api::ApiError;
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

fn auth_error(code: &str, msg: &str) -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiError {
            error: msg.to_string(),
            code: code.to_string(),
        }),
    )
        .into_response()
}

/// JWT 鉴权中间件
pub async fn jwt_auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        None => {
            return auth_error("UNAUTHORIZED", "missing authorization header");
        }
        Some(header) => {
            if let Some(token) = header.strip_prefix("Bearer ") {
                if token.is_empty() {
                    return auth_error("UNAUTHORIZED", "invalid authorization header");
                }
                token
            } else {
                return auth_error("UNAUTHORIZED", "invalid authorization header");
            }
        }
    };

    match validate_token(&state.jwt_secret, token) {
        Ok(claims) => {
            let user = match state.cert_store.get_user_by_username(&claims.username) {
                Ok(Some(user)) => user,
                Ok(None) => {
                    return auth_error("UNAUTHORIZED", "invalid token");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to query user for token validation");
                    return auth_error("UNAUTHORIZED", "invalid token");
                }
            };

            if user.token_version != claims.token_version {
                return auth_error("UNAUTHORIZED", "token revoked");
            }

            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(e) => {
            let msg = if matches!(
                e.kind(),
                jsonwebtoken::errors::ErrorKind::ExpiredSignature
            ) {
                return auth_error("TOKEN_EXPIRED", "token expired");
            } else {
                "invalid token"
            };
            auth_error("UNAUTHORIZED", msg)
        }
    }
}

/// 用户登录并获取 JWT。
/// 鉴权：无需 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "Auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "登录结果", body = LoginResponse),
        (status = 400, description = "请求参数错误", body = ApiError),
        (status = 401, description = "认证失败（用户名或密码错误）", body = ApiError)
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    if req.username.is_empty() || req.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "username and password are required".to_string(),
                code: "BAD_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    let user = match state.cert_store.get_user_by_username(&req.username) {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "invalid credentials".to_string(),
                    code: "UNAUTHORIZED".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to query user");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "internal error".to_string(),
                    code: "INTERNAL_ERROR".to_string(),
                }),
            )
                .into_response();
        }
    };

    match verify_token(&req.password, &user.password_hash) {
        Ok(true) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "invalid credentials".to_string(),
                    code: "UNAUTHORIZED".to_string(),
                }),
            )
                .into_response();
        }
    }

    match create_token(
        &state.jwt_secret,
        &user.id,
        &user.username,
        user.token_version,
        state.token_expire_secs,
    ) {
        Ok(token) => Json(LoginResponse {
            token,
            expires_in: state.token_expire_secs,
        })
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to create token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "internal error".to_string(),
                    code: "INTERNAL_ERROR".to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// 修改当前登录用户密码。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/auth/password",
    tag = "Auth",
    security(("bearer_auth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "密码修改成功"),
        (status = 400, description = "请求参数错误", body = ApiError),
        (status = 401, description = "认证失败或当前密码错误", body = ApiError),
        (status = 500, description = "服务器内部错误", body = ApiError)
    )
)]
pub async fn change_password(
    State(state): State<AppState>,
    axum::Extension(claims): axum::Extension<Claims>,
    Json(body): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    if body.current_password.is_empty() || body.new_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "current_password and new_password are required".to_string(),
                code: "BAD_REQUEST".to_string(),
            }),
        )
            .into_response();
    }

    let user = match state.cert_store.get_user_by_username(&claims.username) {
        Ok(Some(user)) => user,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "invalid credentials".to_string(),
                    code: "UNAUTHORIZED".to_string(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to query user");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "internal error".to_string(),
                    code: "INTERNAL_ERROR".to_string(),
                }),
            )
                .into_response();
        }
    };

    match verify_token(&body.current_password, &user.password_hash) {
        Ok(true) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "invalid credentials".to_string(),
                    code: "UNAUTHORIZED".to_string(),
                }),
            )
                .into_response();
        }
    }

    let new_password_hash = match hash_token(&body.new_password) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!(error = %e, "Failed to hash password");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "internal error".to_string(),
                    code: "INTERNAL_ERROR".to_string(),
                }),
            )
                .into_response();
        }
    };

    match state
        .cert_store
        .update_user_password_hash(&user.id, &new_password_hash)
    {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: "internal error".to_string(),
                code: "INTERNAL_ERROR".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update password");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "internal error".to_string(),
                    code: "INTERNAL_ERROR".to_string(),
                }),
            )
                .into_response()
        }
    }
}
