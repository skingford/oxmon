use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use oxmon_common::types::{
    BatchCreateDomainsRequest, CreateDomainRequest, MetricBatch, MetricDataPoint,
    UpdateDomainRequest,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use oxmon_storage::StorageEngine;

use super::checker::check_certificate;

#[derive(Serialize)]
struct ApiError {
    error: String,
    code: String,
}

fn error_response(status: StatusCode, code: &str, msg: &str) -> impl IntoResponse {
    (
        status,
        Json(ApiError {
            error: msg.to_string(),
            code: code.to_string(),
        }),
    )
}

// POST /api/v1/certs/domains
async fn create_domain(
    State(state): State<AppState>,
    Json(req): Json<CreateDomainRequest>,
) -> impl IntoResponse {
    if req.domain.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_domain",
            "Domain cannot be empty",
        )
        .into_response();
    }
    if let Some(port) = req.port {
        if !(1..=65535).contains(&port) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_port",
                "Port must be between 1 and 65535",
            )
            .into_response();
        }
    }

    // Check for duplicate
    match state.cert_store.get_domain_by_name(&req.domain) {
        Ok(Some(_)) => {
            return error_response(
                StatusCode::CONFLICT,
                "duplicate_domain",
                &format!("Domain '{}' already exists", req.domain),
            )
            .into_response();
        }
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Storage error: {e}"),
            )
            .into_response();
        }
        _ => {}
    }

    match state.cert_store.insert_domain(&req) {
        Ok(domain) => (StatusCode::CREATED, Json(domain)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Failed to create domain: {e}"),
        )
        .into_response(),
    }
}

// POST /api/v1/certs/domains/batch
async fn create_domains_batch(
    State(state): State<AppState>,
    Json(req): Json<BatchCreateDomainsRequest>,
) -> impl IntoResponse {
    if req.domains.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "empty_batch",
            "Domains list cannot be empty",
        )
        .into_response();
    }
    for d in &req.domains {
        if d.domain.is_empty() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_domain",
                "Domain cannot be empty",
            )
            .into_response();
        }
        if let Some(port) = d.port {
            if !(1..=65535).contains(&port) {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_port",
                    &format!("Port must be between 1 and 65535 for domain '{}'", d.domain),
                )
                .into_response();
            }
        }
    }

    match state.cert_store.insert_domains_batch(&req.domains) {
        Ok(domains) => (StatusCode::CREATED, Json(domains)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                error_response(StatusCode::CONFLICT, "duplicate_domain", &msg).into_response()
            } else {
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage_error",
                    &format!("Failed to create domains: {e}"),
                )
                .into_response()
            }
        }
    }
}

// GET /api/v1/certs/domains
#[derive(Deserialize)]
struct ListDomainsParams {
    enabled: Option<bool>,
    search: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn list_domains(
    State(state): State<AppState>,
    Query(params): Query<ListDomainsParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);
    let offset = params.offset.unwrap_or(0);
    match state
        .cert_store
        .query_domains(params.enabled, params.search.as_deref(), limit, offset)
    {
        Ok(domains) => Json(domains).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Query failed: {e}"),
        )
        .into_response(),
    }
}

// GET /api/v1/certs/domains/:id
async fn get_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_domain_by_id(&id) {
        Ok(Some(domain)) => Json(domain).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "not_found", "Domain not found")
            .into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Query failed: {e}"),
        )
        .into_response(),
    }
}

// PUT /api/v1/certs/domains/:id
async fn update_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDomainRequest>,
) -> impl IntoResponse {
    if let Some(port) = req.port {
        if !(1..=65535).contains(&port) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_port",
                "Port must be between 1 and 65535",
            )
            .into_response();
        }
    }

    match state
        .cert_store
        .update_domain(&id, req.port, req.enabled, req.check_interval_secs, req.note)
    {
        Ok(Some(domain)) => Json(domain).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "not_found", "Domain not found")
            .into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Update failed: {e}"),
        )
        .into_response(),
    }
}

// DELETE /api/v1/certs/domains/:id
async fn delete_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_domain(&id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "not_found", "Domain not found")
            .into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Delete failed: {e}"),
        )
        .into_response(),
    }
}

// GET /api/v1/certs/status
async fn cert_status_all(State(state): State<AppState>) -> impl IntoResponse {
    match state.cert_store.query_latest_results() {
        Ok(results) => Json(results).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Query failed: {e}"),
        )
        .into_response(),
    }
}

// GET /api/v1/certs/status/:domain
async fn cert_status_by_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    // Check if domain is monitored
    match state.cert_store.get_domain_by_name(&domain) {
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Domain is not being monitored",
            )
            .into_response();
        }
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Query failed: {e}"),
            )
            .into_response();
        }
        _ => {}
    }

    match state.cert_store.query_result_by_domain(&domain) {
        Ok(Some(result)) => Json(result).into_response(),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "no_results",
            "No check results yet for this domain",
        )
        .into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            &format!("Query failed: {e}"),
        )
        .into_response(),
    }
}

// POST /api/v1/certs/domains/:id/check
async fn check_single_domain(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let domain = match state.cert_store.get_domain_by_id(&id) {
        Ok(Some(d)) => d,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "not_found", "Domain not found")
                .into_response();
        }
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Query failed: {e}"),
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

    Json(result).into_response()
}

// POST /api/v1/certs/check
async fn check_all_domains(State(state): State<AppState>) -> impl IntoResponse {
    let domains = match state.cert_store.query_domains(Some(true), None, 10000, 0) {
        Ok(d) => d,
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_error",
                &format!("Query failed: {e}"),
            )
            .into_response();
        }
    };

    if domains.is_empty() {
        return Json(Vec::<oxmon_common::types::CertCheckResult>::new()).into_response();
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

    Json(results).into_response()
}

fn store_check_result(
    state: &AppState,
    domain_id: &str,
    domain_name: &str,
    result: &oxmon_common::types::CertCheckResult,
) -> anyhow::Result<()> {
    state.cert_store.insert_check_result(result)?;
    state.cert_store.update_last_checked_at(domain_id, Utc::now())?;

    // Emit metrics
    let now = Utc::now();
    let agent_id = "cert-checker".to_string();
    let mut labels = HashMap::new();
    labels.insert("domain".to_string(), domain_name.to_string());

    let mut data_points = Vec::new();
    data_points.push(MetricDataPoint {
        timestamp: now,
        agent_id: agent_id.clone(),
        metric_name: "certificate.is_valid".to_string(),
        value: if result.is_valid { 1.0 } else { 0.0 },
        labels: labels.clone(),
    });

    if let Some(days) = result.days_until_expiry {
        data_points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.clone(),
            metric_name: "certificate.days_until_expiry".to_string(),
            value: days as f64,
            labels,
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

pub fn cert_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/certs/domains", post(create_domain).get(list_domains))
        .route("/api/v1/certs/domains/batch", post(create_domains_batch))
        .route(
            "/api/v1/certs/domains/:id",
            get(get_domain).put(update_domain).delete(delete_domain),
        )
        .route("/api/v1/certs/domains/:id/check", post(check_single_domain))
        .route("/api/v1/certs/check", post(check_all_domains))
        .route("/api/v1/certs/status", get(cert_status_all))
        .route("/api/v1/certs/status/:domain", get(cert_status_by_domain))
}
