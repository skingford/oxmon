use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::response::IntoResponse;
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
};
use oxmon_common::types::{CertificateDetails, CertificateDetailsFilter};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

static CERTIFICATE_DOMAINS_BACKFILL_ONCE: OnceLock<()> = OnceLock::new();

/// 证书列表查询参数
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct CertificateListQuery {
    /// 域名包含匹配（domain__contains，可选）
    #[param(required = false)]
    #[serde(rename = "domain__contains")]
    domain_contains: Option<String>,
    /// 证书过期时间上界（not_after__lte，可选，Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(rename = "not_after__lte")]
    not_after_lte: Option<i64>,
    /// 证书过期时间下界（not_after__gte，可选，Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(rename = "not_after__gte")]
    not_after_gte: Option<i64>,
    /// 证书链是否有效（chain_valid__eq，可选）
    #[param(required = false)]
    #[serde(rename = "chain_valid__eq")]
    chain_valid_eq: Option<bool>,
    /// 证书是否有效（is_valid__eq，可选；证书列表语义，等价 chain_valid）
    #[param(required = false)]
    #[serde(rename = "is_valid__eq")]
    is_valid_eq: Option<bool>,
    /// 证书链错误精确匹配（chain_error__eq，可选）
    #[param(required = false)]
    #[serde(rename = "chain_error__eq")]
    chain_error_eq: Option<String>,
    /// 最后检查时间下界（last_checked__gte，可选，Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(rename = "last_checked__gte")]
    last_checked_gte: Option<i64>,
    /// 最后检查时间上界（last_checked__lte，可选，Unix 秒级时间戳）
    #[param(required = false)]
    #[serde(rename = "last_checked__lte")]
    last_checked_lte: Option<i64>,
    /// IP 包含匹配（ip_address__contains，可选）
    #[param(required = false)]
    #[serde(rename = "ip_address__contains")]
    ip_address_contains: Option<String>,
    /// 颁发者包含匹配（issuer__contains，可选）
    #[param(required = false)]
    #[serde(rename = "issuer__contains")]
    issuer_contains: Option<String>,
    /// TLS 版本精确匹配（tls_version__eq，可选）
    #[param(required = false)]
    #[serde(rename = "tls_version__eq")]
    tls_version_eq: Option<String>,
    /// 每页条数（默认 20）
    #[param(required = false)]
    #[serde(
        default,
        deserialize_with = "crate::api::pagination::deserialize_optional_u64"
    )]
    limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(
        default,
        deserialize_with = "crate::api::pagination::deserialize_optional_u64"
    )]
    offset: Option<u64>,
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
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let details = match state
        .cert_store
        .get_certificate_details_by_id(&id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get certificate details");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                &format!("Certificate with id '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    success_response(StatusCode::OK, &trace_id, details)
}

/// 分页查询证书详情列表（支持过滤）。
/// 默认排序：`not_after` 升序；默认分页：`limit=20&offset=0`。
/// 仅返回当前仍在“监控域名（cert_domains）”中的证书详情，避免展示历史孤儿证书记录。
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
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(query): Query<CertificateListQuery>,
) -> impl IntoResponse {
    if let (Some(chain_valid), Some(is_valid)) = (query.chain_valid_eq, query.is_valid_eq) {
        if chain_valid != is_valid {
            return error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "bad_request",
                "chain_valid__eq and is_valid__eq conflict",
            );
        }
    }

    // Fallback self-heal (once per process): if startup backfill was skipped or unavailable,
    // perform one lazy backfill on the first certificates list request only.
    if CERTIFICATE_DOMAINS_BACKFILL_ONCE.get().is_none() {
        match state
            .cert_store
            .sync_missing_monitored_domains_from_certificate_details()
            .await
        {
            Ok(inserted) => {
                if inserted > 0 {
                    tracing::info!(
                        inserted,
                        "Lazy one-time backfill of monitored domains from certificate details completed"
                    );
                }
                let _ = CERTIFICATE_DOMAINS_BACKFILL_ONCE.set(());
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed lazy one-time backfill of monitored domains from certificate details"
                );
                // Continue serving the request; list/count still operate on current consistent data.
            }
        }
    }

    let filter = CertificateDetailsFilter {
        domain_contains: query.domain_contains.clone(),
        not_after_lte: query.not_after_lte,
        not_after_gte: query.not_after_gte,
        chain_valid_eq: query.chain_valid_eq,
        is_valid_eq: query.is_valid_eq,
        chain_error_eq: query.chain_error_eq.clone(),
        last_checked_gte: query.last_checked_gte,
        last_checked_lte: query.last_checked_lte,
        ip_address_contains: query.ip_address_contains.clone(),
        issuer_contains: query.issuer_contains.clone(),
        tls_version_eq: query.tls_version_eq.clone(),
    };

    let limit = PaginationParams::resolve_limit(query.limit);
    let offset = PaginationParams::resolve_offset(query.offset);

    let total = match state.cert_store.count_certificate_details(&filter).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count certificates");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            );
        }
    };

    let certificates = match state
        .cert_store
        .list_certificate_details(&filter, limit, offset)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list certificates");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    success_paginated_response(
        StatusCode::OK,
        &trace_id,
        certificates,
        total,
        limit,
        offset,
    )
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
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let details = match state
        .cert_store
        .get_certificate_details_by_id(&id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get certificate details");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        }) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                &format!("Certificate with id '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    success_response(
        StatusCode::OK,
        &trace_id,
        CertificateChainInfo {
            id: details.id,
            domain: details.domain,
            chain_valid: details.chain_valid,
            chain_error: details.chain_error,
            last_checked: details.last_checked,
        },
    )
}

/// 证书健康摘要。
#[utoipa::path(
    get,
    path = "/v1/certs/summary",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "证书健康摘要"),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn cert_summary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.cert_store.cert_summary().await {
        Ok(summary) => success_response(StatusCode::OK, &trace_id, summary),
        Err(e) => {
            tracing::error!(error = %e, "Failed to query cert summary");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response()
        }
    }
}

pub fn certificates_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_certificate))
        .routes(routes!(list_certificates))
        .routes(routes!(get_certificate_chain))
        .routes(routes!(cert_summary))
}
