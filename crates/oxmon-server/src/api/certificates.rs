use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use oxmon_common::types::{CertificateDetails, CertificateDetailsFilter};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

/// 证书列表查询参数
#[derive(Debug, Deserialize, IntoParams)]
struct CertificateListQuery {
    /// 过滤即将过期的证书（天数内）
    expiring_within_days: Option<i64>,
    /// 按 IP 地址过滤
    ip_address: Option<String>,
    /// 按颁发者过滤
    issuer: Option<String>,
    /// 每页数量
    #[serde(default = "default_limit")]
    limit: usize,
    /// 偏移量
    #[serde(default)]
    offset: usize,
}

fn default_limit() -> usize {
    100
}

/// 获取指定证书详情（按 ID）
#[utoipa::path(
    get,
    path = "/v1/certificates/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "证书唯一标识")
    ),
    responses(
        (status = 200, description = "证书详情", body = CertificateDetails),
        (status = 401, description = "未认证"),
        (status = 404, description = "证书不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Certificates"
)]
async fn get_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<CertificateDetails>, (StatusCode, Json<serde_json::Value>)> {
    let details = state
        .cert_store
        .get_certificate_details_by_id(&id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get certificate details");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Certificate with id '{}' not found", id)})),
            )
        })?;

    Ok(Json(details))
}

/// 列出证书（支持过滤）
#[utoipa::path(
    get,
    path = "/v1/certificates",
    security(("bearer_auth" = [])),
    params(
        CertificateListQuery
    ),
    responses(
        (status = 200, description = "证书列表", body = Vec<CertificateDetails>),
        (status = 401, description = "未认证"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Certificates"
)]
async fn list_certificates(
    State(state): State<AppState>,
    Query(query): Query<CertificateListQuery>,
) -> Result<Json<Vec<CertificateDetails>>, (StatusCode, Json<serde_json::Value>)> {
    let filter = CertificateDetailsFilter {
        expiring_within_days: query.expiring_within_days,
        ip_address: query.ip_address,
        issuer: query.issuer,
    };

    let certificates = state
        .cert_store
        .list_certificate_details(&filter, query.limit, query.offset)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list certificates");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?;

    Ok(Json(certificates))
}

/// 证书链信息
#[derive(Debug, Serialize, ToSchema)]
struct CertificateChainInfo {
    /// 证书唯一标识
    id: String,
    /// 域名
    domain: String,
    /// 证书链是否有效
    chain_valid: bool,
    /// 证书链错误信息
    chain_error: Option<String>,
    /// 最后检查时间
    last_checked: chrono::DateTime<chrono::Utc>,
}

/// 获取证书链验证详情（按 ID）
#[utoipa::path(
    get,
    path = "/v1/certificates/{id}/chain",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "证书唯一标识")
    ),
    responses(
        (status = 200, description = "证书链信息", body = CertificateChainInfo),
        (status = 401, description = "未认证"),
        (status = 404, description = "证书不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Certificates"
)]
async fn get_certificate_chain(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<CertificateChainInfo>, (StatusCode, Json<serde_json::Value>)> {
    let details = state
        .cert_store
        .get_certificate_details_by_id(&id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get certificate details");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Certificate with id '{}' not found", id)})),
            )
        })?;

    Ok(Json(CertificateChainInfo {
        id: details.id,
        domain: details.domain,
        chain_valid: details.chain_valid,
        chain_error: details.chain_error,
        last_checked: details.last_checked,
    }))
}

pub fn certificates_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_certificate))
        .routes(routes!(list_certificates))
        .routes(routes!(get_certificate_chain))
}
