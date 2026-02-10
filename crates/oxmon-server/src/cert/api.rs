use crate::api::pagination::PaginationParams;
use crate::api::{error_response as common_error_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use oxmon_common::types::{
    BatchCreateDomainsRequest, CertCheckResult, CertDomain, CreateDomainRequest, MetricBatch,
    MetricDataPoint, UpdateDomainRequest,
};
use serde::Deserialize;
use std::collections::HashMap;
use utoipa_axum::{router::OpenApiRouter, routes};

use oxmon_storage::StorageEngine;

use super::checker::check_certificate;

/// 新增证书监控域名。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/certs/domains",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    request_body = CreateDomainRequest,
    responses(
        (status = 201, description = "新增监控域名结果", body = CertDomain),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未授权", body = crate::api::ApiError),
        (status = 409, description = "域名已存在", body = crate::api::ApiError)
    )
)]
async fn create_domain(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateDomainRequest>,
) -> impl IntoResponse {
    if req.domain.is_empty() {
        return common_error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_domain",
            "Domain cannot be empty",
        )
        .into_response();
    }
    if let Some(port) = req.port {
        if !(1..=65535).contains(&port) {
            return common_error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "invalid_port",
                "Port must be between 1 and 65535",
            )
            .into_response();
        }
    }

    // Check for duplicate
    match state.cert_store.get_domain_by_name(&req.domain) {
        Ok(Some(_)) => {
            return common_error_response(
                StatusCode::CONFLICT,
                &trace_id,
                "duplicate_domain",
                &format!("Domain '{}' already exists", req.domain),
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Storage operation failed");
            return common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal storage error",
            )
            .into_response();
        }
        _ => {}
    }

    match state.cert_store.insert_domain(&req) {
        Ok(domain) => success_response(StatusCode::CREATED, &trace_id, domain),
        Err(e) => {
            tracing::error!(error = %e, "Storage operation failed");
            common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal storage error",
            )
            .into_response()
        }
    }
}

/// 批量新增证书监控域名。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/certs/domains/batch",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    request_body = BatchCreateDomainsRequest,
    responses(
        (status = 201, description = "批量新增监控域名结果", body = Vec<CertDomain>),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未授权", body = crate::api::ApiError),
        (status = 409, description = "域名重复", body = crate::api::ApiError)
    )
)]
async fn create_domains_batch(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<BatchCreateDomainsRequest>,
) -> impl IntoResponse {
    if req.domains.is_empty() {
        return common_error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "empty_batch",
            "Domains list cannot be empty",
        )
        .into_response();
    }
    for d in &req.domains {
        if d.domain.is_empty() {
            return common_error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "invalid_domain",
                "Domain cannot be empty",
            )
            .into_response();
        }
        if let Some(port) = d.port {
            if !(1..=65535).contains(&port) {
                return common_error_response(
                    StatusCode::BAD_REQUEST,
                    &trace_id,
                    "invalid_port",
                    &format!("Port must be between 1 and 65535 for domain '{}'", d.domain),
                )
                .into_response();
            }
        }
    }

    match state.cert_store.insert_domains_batch(&req.domains) {
        Ok(domains) => success_response(StatusCode::CREATED, &trace_id, domains),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                common_error_response(
                    StatusCode::CONFLICT,
                    &trace_id,
                    "duplicate_domain",
                    "One or more domains already exist",
                )
                .into_response()
            } else {
                tracing::error!(error = %e, "Batch create domains failed");
                common_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "storage_error",
                    "Internal storage error",
                )
                .into_response()
            }
        }
    }
}

// GET /v1/certs/domains
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListDomainsParams {
    /// 启用状态精确匹配（enabled__eq，可选）
    #[param(required = false)]
    #[serde(rename = "enabled__eq")]
    enabled_eq: Option<bool>,
    /// 域名包含匹配（domain__contains，可选）
    #[param(required = false)]
    #[serde(rename = "domain__contains")]
    domain_contains: Option<String>,
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

/// 分页查询监控域名列表（支持按 enabled__eq、domain__contains 过滤）。
/// 默认排序：`created_at` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/certs/domains",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    params(ListDomainsParams),
    responses(
        (status = 200, description = "监控域名分页列表", body = Vec<CertDomain>),
        (status = 401, description = "未授权", body = crate::api::ApiError)
    )
)]
async fn list_domains(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListDomainsParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);
    match state.cert_store.query_domains(
        params.enabled_eq,
        params.domain_contains.as_deref(),
        limit,
        offset,
    ) {
        Ok(domains) => success_response(StatusCode::OK, &trace_id, domains),
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response()
        }
    }
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct CertStatusListParams {
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

/// 获取监控域名详情（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/certs/domains/{id}",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "监控域名 ID（路径参数）")
    ),
    responses(
        (status = 200, description = "监控域名详情", body = CertDomain),
        (status = 401, description = "未授权", body = crate::api::ApiError),
        (status = 404, description = "域名不存在", body = crate::api::ApiError)
    )
)]
async fn get_domain(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_domain_by_id(&id) {
        Ok(Some(domain)) => success_response(StatusCode::OK, &trace_id, domain),
        Ok(None) => common_error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Domain not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response()
        }
    }
}

/// 更新监控域名配置（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    put,
    path = "/v1/certs/domains/{id}",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "监控域名 ID（路径参数）")
    ),
    request_body = UpdateDomainRequest,
    responses(
        (status = 200, description = "更新监控域名结果", body = CertDomain),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未授权", body = crate::api::ApiError),
        (status = 404, description = "域名不存在", body = crate::api::ApiError)
    )
)]
async fn update_domain(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> impl IntoResponse {
    if let Some(port) = req.port {
        if !(1..=65535).contains(&port) {
            return common_error_response(
                StatusCode::BAD_REQUEST,
                &trace_id,
                "invalid_port",
                "Port must be between 1 and 65535",
            )
            .into_response();
        }
    }

    match state.cert_store.update_domain(
        &id,
        req.port,
        req.enabled,
        req.check_interval_secs,
        req.note,
    ) {
        Ok(Some(domain)) => success_response(StatusCode::OK, &trace_id, domain),
        Ok(None) => common_error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Domain not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Update failed");
            common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal update error",
            )
            .into_response()
        }
    }
}

/// 删除监控域名（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    delete,
    path = "/v1/certs/domains/{id}",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "监控域名 ID（路径参数）")
    ),
    responses(
        (status = 200, description = "删除成功"),
        (status = 401, description = "未授权", body = crate::api::ApiError),
        (status = 404, description = "域名不存在", body = crate::api::ApiError)
    )
)]
async fn delete_domain(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_domain(&id) {
        Ok(true) => success_response(
            StatusCode::OK,
            &trace_id,
            serde_json::json!({ "deleted": true }),
        ),
        Ok(false) => common_error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Domain not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Delete failed");
            common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal delete error",
            )
            .into_response()
        }
    }
}

/// 分页查询所有域名的最新证书检查结果。
/// 默认排序：`checked_at` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/certs/status",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    params(CertStatusListParams),
    responses(
        (status = 200, description = "域名证书状态分页列表", body = Vec<CertCheckResult>),
        (status = 401, description = "未授权", body = crate::api::ApiError)
    )
)]
async fn cert_status_all(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<CertStatusListParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    match state.cert_store.query_latest_results(limit, offset) {
        Ok(results) => success_response(StatusCode::OK, &trace_id, results),
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response()
        }
    }
}

/// 获取指定域名的最新证书检查结果。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/certs/status/{domain}",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    params(
        ("domain" = String, Path, description = "监控域名（路径参数）")
    ),
    responses(
        (status = 200, description = "域名最新证书检查结果", body = CertCheckResult),
        (status = 401, description = "未授权", body = crate::api::ApiError),
        (status = 404, description = "域名不存在", body = crate::api::ApiError)
    )
)]
async fn cert_status_by_domain(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_domain_by_name(&domain) {
        Ok(None) => {
            return common_error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Domain is not being monitored",
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            return common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response();
        }
        _ => {}
    }

    match state.cert_store.query_result_by_domain(&domain) {
        Ok(Some(result)) => success_response(StatusCode::OK, &trace_id, result),
        Ok(None) => common_error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "no_results",
            "No check results yet for this domain",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response()
        }
    }
}

/// 手动触发指定域名证书检查（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/certs/domains/{id}/check",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "监控域名 ID（路径参数）")
    ),
    responses(
        (status = 200, description = "手动证书检查结果", body = CertCheckResult),
        (status = 401, description = "未授权", body = crate::api::ApiError),
        (status = 404, description = "域名不存在", body = crate::api::ApiError)
    )
)]
async fn check_single_domain(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let domain = match state.cert_store.get_domain_by_id(&id) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return common_error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Domain not found",
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            return common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response();
        }
    };

    let result = check_certificate(
        &domain.domain,
        domain.port,
        &domain.id,
        state.connect_timeout_secs,
    )
    .await;

    if let Err(e) = store_check_result(&state, &domain.id, &domain.domain, &result) {
        tracing::error!(domain = %domain.domain, error = %e, "Failed to store manual check result");
    }

    success_response(StatusCode::OK, &trace_id, result)
}

/// 手动触发所有已启用域名证书检查。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/certs/check",
    tag = "Certificates",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "手动批量证书检查结果", body = Vec<CertCheckResult>),
        (status = 401, description = "未授权", body = crate::api::ApiError)
    )
)]
async fn check_all_domains(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let domains = match state.cert_store.query_domains(Some(true), None, 10000, 0) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "Query failed");
            return common_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Internal query error",
            )
            .into_response();
        }
    };

    if domains.is_empty() {
        return success_response(
            StatusCode::OK,
            &trace_id,
            Vec::<oxmon_common::types::CertCheckResult>::new(),
        );
    }

    let mut results = Vec::with_capacity(domains.len());
    for domain in &domains {
        let result = check_certificate(
            &domain.domain,
            domain.port,
            &domain.id,
            state.connect_timeout_secs,
        )
        .await;

        if let Err(e) = store_check_result(&state, &domain.id, &domain.domain, &result) {
            tracing::error!(domain = %domain.domain, error = %e, "Failed to store manual check result");
        }

        results.push(result);
    }

    success_response(StatusCode::OK, &trace_id, results)
}

fn store_check_result(
    state: &AppState,
    domain_id: &str,
    domain_name: &str,
    result: &oxmon_common::types::CertCheckResult,
) -> anyhow::Result<()> {
    state.cert_store.insert_check_result(result)?;
    state
        .cert_store
        .update_last_checked_at(domain_id, Utc::now())?;

    // Emit metrics
    let now = Utc::now();
    let agent_id = "cert-checker".to_string();
    let mut labels = HashMap::new();
    labels.insert("domain".to_string(), domain_name.to_string());

    let mut data_points = Vec::new();
    data_points.push(MetricDataPoint {
        id: oxmon_common::id::next_id(),
        timestamp: now,
        agent_id: agent_id.clone(),
        metric_name: "certificate.is_valid".to_string(),
        value: if result.is_valid { 1.0 } else { 0.0 },
        labels: labels.clone(),
        created_at: now,
        updated_at: now,
    });

    if let Some(days) = result.days_until_expiry {
        data_points.push(MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now,
            agent_id: agent_id.clone(),
            metric_name: "certificate.days_until_expiry".to_string(),
            value: days as f64,
            labels,
            created_at: now,
            updated_at: now,
        });
    }

    let batch = MetricBatch {
        agent_id,
        timestamp: now,
        data_points,
    };

    state.storage.write_batch(&batch)?;
    Ok(())
}

pub fn cert_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create_domain, list_domains))
        .routes(routes!(create_domains_batch))
        .routes(routes!(get_domain, update_domain, delete_domain))
        .routes(routes!(check_single_domain))
        .routes(routes!(check_all_domains))
        .routes(routes!(cert_status_all))
        .routes(routes!(cert_status_by_domain))
}
