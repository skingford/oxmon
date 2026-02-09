use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_response};
use crate::state::AppState;
use axum::response::IntoResponse;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
};
use oxmon_common::types::{CertificateDetails, CertificateDetailsFilter};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

/// 证书列表查询参数
#[derive(Debug, Deserialize, IntoParams)]
struct CertificateListQuery {
    /// 证书过期时间上界（not_after__lte，可选，Unix 秒级时间戳）
    #[serde(rename = "not_after__lte")]
    not_after_lte: Option<i64>,
    /// IP 包含匹配（ip_address__contains，可选）
    #[serde(rename = "ip_address__contains")]
    ip_address_contains: Option<String>,
    /// 颁发者包含匹配（issuer__contains，可选）
    #[serde(rename = "issuer__contains")]
    issuer_contains: Option<String>,
    #[serde(flatten)]
    pagination: PaginationParams,
}

/// 获取指定证书详情（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/certificates/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "证书 ID（路径参数）")
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
) -> impl IntoResponse {
    let details = match state
        .cert_store
        .get_certificate_details_by_id(&id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get certificate details");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            )
        }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("Certificate with id '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    success_response(StatusCode::OK, details)
}

/// 分页查询证书详情列表（支持过滤）。
/// 默认排序：`not_after` 升序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/certificates",
    security(("bearer_auth" = [])),
    params(
        CertificateListQuery
    ),
    responses(
        (status = 200, description = "证书详情分页列表", body = Vec<CertificateDetails>),
        (status = 401, description = "未认证"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Certificates"
)]
async fn list_certificates(
    State(state): State<AppState>,
    Query(query): Query<CertificateListQuery>,
) -> impl IntoResponse {
    let filter = CertificateDetailsFilter {
        not_after_lte: query.not_after_lte,
        ip_address_contains: query.ip_address_contains,
        issuer_contains: query.issuer_contains,
    };

    let certificates = match state
        .cert_store
        .list_certificate_details(&filter, query.pagination.limit(), query.pagination.offset())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list certificates");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            )
        }) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    success_response(StatusCode::OK, certificates)
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

/// 获取指定证书的证书链验证详情（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/certificates/{id}/chain",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "证书 ID（路径参数）")
    ),
    responses(
        (status = 200, description = "证书链验证详情", body = CertificateChainInfo),
        (status = 401, description = "未认证"),
        (status = 404, description = "证书不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Certificates"
)]
async fn get_certificate_chain(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let details = match state
        .cert_store
        .get_certificate_details_by_id(&id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get certificate details");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Database error",
            )
        }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("Certificate with id '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    success_response(
        StatusCode::OK,
        CertificateChainInfo {
            id: details.id,
            domain: details.domain,
            chain_valid: details.chain_valid,
            chain_error: details.chain_error,
            last_checked: details.last_checked,
        },
    )
}

pub fn certificates_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_certificate))
        .routes(routes!(list_certificates))
        .routes(routes!(get_certificate_chain))
}
