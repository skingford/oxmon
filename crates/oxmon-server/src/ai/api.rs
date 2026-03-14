use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use oxmon_common::types::AIReportRow;
use oxmon_storage::AIAccountUpdate;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::pagination::{deserialize_optional_u64, PaginationParams};
use crate::api::{error_response, success_id_response, success_paginated_response};
use crate::logging::TraceId;
use crate::state::AppState;

/// AI 模块的 OpenAPI 文档
#[derive(OpenApi)]
#[openapi(
    paths(
        list_ai_accounts,
        get_ai_account,
        create_ai_account,
        update_ai_account,
        delete_ai_account,
        trigger_ai_report,
        list_ai_reports,
        get_ai_report,
        view_ai_report_html,
        list_report_instances,
    ),
    components(schemas(
        ListAIAccountsQuery,
        AIAccountResponse,
        CreateAIAccountRequest,
        UpdateAIAccountRequest,
        TriggerAIReportResponse,
        ListAIReportsQuery,
        AIReportListItem,
        ListReportInstancesQuery,
        AIReportInstanceItem,
    ))
)]
pub struct AIApiDoc;

pub fn ai_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_ai_accounts, create_ai_account))
        .routes(routes!(
            get_ai_account,
            update_ai_account,
            delete_ai_account
        ))
        .routes(routes!(trigger_ai_report))
        .routes(routes!(list_ai_reports))
        .routes(routes!(get_ai_report))
        .routes(routes!(view_ai_report_html))
        .routes(routes!(list_report_instances))
}

// ===== 数据结构 =====

/// GET /v1/ai/reports/{id} 查询参数
#[derive(Debug, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct GetAIReportQuery {
    /// 是否排除 html_content 和 raw_metrics_json 大字段（默认 false）
    #[param(required = false)]
    pub exclude_content: Option<bool>,
}

/// GET /v1/ai/reports/{id}/instances 查询参数
#[derive(Debug, Default, Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListReportInstancesQuery {
    /// 按风险等级过滤：high / medium / low / normal（可选）
    #[param(required = false)]
    pub risk_level: Option<String>,
    /// 每页记录数（默认 20，最大 1000）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub offset: Option<u64>,
}

/// 报告实例分页条目
#[derive(Debug, Serialize, ToSchema)]
pub struct AIReportInstanceItem {
    pub agent_id: String,
    pub instance_name: Option<String>,
    pub agent_type: String,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub disk_usage: Option<f64>,
    /// 风险等级：high / medium / low / normal
    pub risk_level: String,
    pub timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListAIAccountsQuery {
    /// 按 provider 过滤 (zhipu, kimi, minimax, claude, codex, custom)
    #[param(required = false)]
    pub provider: Option<String>,
    /// 按启用状态过滤
    #[param(required = false)]
    pub enabled: Option<bool>,
    /// 每页记录数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub offset: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AIAccountResponse {
    pub id: String,
    pub config_key: String,
    pub provider: String,
    pub display_name: String,
    pub description: Option<String>,
    pub api_key: String,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_mode: Option<String>,
    pub timeout_secs: Option<i32>,
    pub max_tokens: Option<i32>,
    pub temperature: Option<f32>,
    pub collection_interval_secs: Option<i32>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAIAccountRequest {
    pub config_key: String,
    pub provider: String,
    pub display_name: String,
    pub description: Option<String>,
    pub api_key: String,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_mode: Option<String>,
    pub timeout_secs: Option<i32>,
    pub max_tokens: Option<i32>,
    pub temperature: Option<f32>,
    pub collection_interval_secs: Option<i32>,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAIAccountRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_mode: Option<String>,
    pub timeout_secs: Option<i32>,
    pub max_tokens: Option<i32>,
    pub temperature: Option<f32>,
    pub collection_interval_secs: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListAIReportsQuery {
    /// 按日期过滤 (YYYY-MM-DD)
    #[param(required = false)]
    pub report_date: Option<String>,
    /// 按风险等级过滤 (high, medium, low, normal)
    #[param(required = false)]
    pub risk_level: Option<String>,
    /// 每页记录数（默认 20）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub limit: Option<u64>,
    /// 偏移量（默认 0）
    #[param(required = false)]
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub offset: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AIReportListItem {
    pub id: String,
    pub report_date: String,
    pub ai_account_id: String,
    pub ai_provider: String,
    pub ai_model: String,
    pub total_agents: i32,
    pub risk_level: String,
    pub notified: bool,
    pub created_at: String,
}

fn row_to_response(row: oxmon_storage::AIAccountRow) -> AIAccountResponse {
    AIAccountResponse {
        id: row.id,
        config_key: row.config_key,
        provider: row.provider,
        display_name: row.display_name,
        description: row.description,
        api_key: row.api_key,
        model: row.model,
        base_url: row.base_url,
        api_mode: row.api_mode,
        timeout_secs: row.timeout_secs,
        max_tokens: row.max_tokens,
        temperature: row.temperature,
        collection_interval_secs: row.collection_interval_secs,
        enabled: row.enabled,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}

// ===== API 处理函数 =====

/// 列出 AI 账号
#[utoipa::path(
    get,
    path = "/v1/ai/accounts",
    params(ListAIAccountsQuery),
    responses(
        (status = 200, description = "AI 账号列表", body = Vec<AIAccountResponse>),
    ),
    tag = "AI 管理"
)]
async fn list_ai_accounts(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(query): Query<ListAIAccountsQuery>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(query.limit);
    let offset = PaginationParams::resolve_offset(query.offset);

    let total = match state
        .cert_store
        .count_ai_accounts(query.provider.as_deref(), query.enabled)
        .await
    {
        Ok(count) => count,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count AI accounts");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Failed to count AI accounts",
            );
        }
    };

    let rows = match state
        .cert_store
        .list_ai_accounts(query.provider.as_deref(), query.enabled, limit, offset)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list AI accounts");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Failed to list AI accounts",
            );
        }
    };

    let accounts: Vec<AIAccountResponse> = rows.into_iter().map(row_to_response).collect();
    success_paginated_response(StatusCode::OK, &trace_id, accounts, total, limit, offset)
}

/// 获取单个 AI 账号
#[utoipa::path(
    get,
    path = "/v1/ai/accounts/{id}",
    params(
        ("id" = String, Path, description = "AI 账号 ID")
    ),
    responses(
        (status = 200, description = "AI 账号详情", body = AIAccountResponse),
        (status = 404, description = "AI 账号不存在"),
    ),
    tag = "AI 管理"
)]
async fn get_ai_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AIAccountResponse>, AppError> {
    let row = state
        .cert_store
        .get_ai_account_by_id(&id)
        .await?
        .ok_or(AppError::NotFound("AI account not found".into()))?;

    Ok(Json(row_to_response(row)))
}

/// 创建 AI 账号
#[utoipa::path(
    post,
    path = "/v1/ai/accounts",
    request_body = CreateAIAccountRequest,
    responses(
        (status = 201, description = "AI 账号创建成功", body = AIAccountResponse),
    ),
    tag = "AI 管理"
)]
async fn create_ai_account(
    State(state): State<AppState>,
    Json(req): Json<CreateAIAccountRequest>,
) -> Result<(StatusCode, Json<AIAccountResponse>), AppError> {
    let row = oxmon_storage::AIAccountRow {
        id: oxmon_common::id::next_id(),
        config_key: req.config_key,
        provider: req.provider,
        display_name: req.display_name,
        description: req.description,
        api_key: req.api_key,
        model: req.model,
        base_url: req.base_url,
        api_mode: req.api_mode,
        timeout_secs: req.timeout_secs,
        max_tokens: req.max_tokens,
        temperature: req.temperature,
        collection_interval_secs: req.collection_interval_secs,
        enabled: req.enabled,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let inserted = state.cert_store.insert_ai_account(&row).await?;
    Ok((StatusCode::CREATED, Json(row_to_response(inserted))))
}

/// 更新 AI 账号
#[utoipa::path(
    put,
    path = "/v1/ai/accounts/{id}",
    params(
        ("id" = String, Path, description = "AI 账号 ID")
    ),
    request_body = UpdateAIAccountRequest,
    responses(
        (status = 200, description = "AI 账号更新成功", body = crate::api::IdResponse),
        (status = 404, description = "AI 账号不存在", body = crate::api::ApiError),
    ),
    tag = "AI 管理"
)]
async fn update_ai_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAIAccountRequest>,
) -> impl IntoResponse {
    match state.cert_store.get_ai_account_by_id(&id).await {
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "AI account not found",
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get AI account");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            );
        }
        Ok(Some(_)) => {}
    }

    let upd = AIAccountUpdate {
        display_name: req.display_name,
        description: req.description,
        api_key: req.api_key,
        model: req.model,
        base_url: req.base_url,
        api_mode: req.api_mode,
        timeout_secs: req.timeout_secs,
        max_tokens: req.max_tokens,
        temperature: req.temperature,
        collection_interval_secs: req.collection_interval_secs,
        enabled: req.enabled,
    };

    match state.cert_store.update_ai_account(&id, upd).await {
        Ok(_) => success_id_response(StatusCode::OK, &trace_id, id),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update AI account");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "internal error",
            )
        }
    }
}

/// 删除 AI 账号
#[utoipa::path(
    delete,
    path = "/v1/ai/accounts/{id}",
    params(
        ("id" = String, Path, description = "AI 账号 ID")
    ),
    responses(
        (status = 204, description = "AI 账号删除成功"),
        (status = 404, description = "AI 账号不存在"),
    ),
    tag = "AI 管理"
)]
async fn delete_ai_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let deleted = state.cert_store.delete_ai_account(&id).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound("AI account not found".into()))
    }
}

/// 手动触发 AI 报告生成
#[derive(Debug, Serialize, ToSchema)]
pub struct TriggerAIReportResponse {
    pub report_id: String,
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/v1/ai/accounts/{id}/trigger",
    params(
        ("id" = String, Path, description = "AI 账号 ID")
    ),
    responses(
        (status = 200, description = "AI 报告触发成功", body = TriggerAIReportResponse),
        (status = 404, description = "AI 账号不存在"),
        (status = 400, description = "AI 账号未启用"),
    ),
    tag = "AI 管理"
)]
async fn trigger_ai_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TriggerAIReportResponse>, AppError> {
    let account = state
        .cert_store
        .get_ai_account_by_id(&id)
        .await?
        .ok_or_else(|| AppError::NotFound("AI account not found".into()))?;

    if !account.enabled {
        return Err(AppError::BadRequest(format!(
            "AI account '{}' is disabled, please enable it first",
            account.config_key
        )));
    }

    let report_id = crate::ai::report::generate_report_for_account(
        &account,
        &state.storage,
        &state.cert_store,
        &state.notifier,
    )
    .await?;

    Ok(Json(TriggerAIReportResponse {
        report_id: report_id.clone(),
        message: format!(
            "AI report generated successfully for account '{}'. Report ID: {}",
            account.config_key, report_id
        ),
    }))
}

/// 列出 AI 报告
#[utoipa::path(
    get,
    path = "/v1/ai/reports",
    params(ListAIReportsQuery),
    responses(
        (status = 200, description = "AI 报告列表", body = Vec<AIReportListItem>),
    ),
    tag = "AI 报告"
)]
async fn list_ai_reports(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(query): Query<ListAIReportsQuery>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(query.limit);
    let offset = PaginationParams::resolve_offset(query.offset);

    let total = match state
        .cert_store
        .count_ai_reports(query.report_date.as_deref(), query.risk_level.as_deref())
        .await
    {
        Ok(count) => count,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count AI reports");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Failed to count AI reports",
            );
        }
    };

    let rows = match state
        .cert_store
        .list_ai_reports(
            query.report_date.as_deref(),
            query.risk_level.as_deref(),
            limit,
            offset,
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list AI reports");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Failed to list AI reports",
            );
        }
    };

    let items: Vec<AIReportListItem> = rows
        .into_iter()
        .map(|row| AIReportListItem {
            id: row.id,
            report_date: row.report_date,
            ai_account_id: row.ai_account_id,
            ai_provider: row.ai_provider,
            ai_model: row.ai_model,
            total_agents: row.total_agents,
            risk_level: row.risk_level,
            notified: row.notified,
            created_at: row.created_at.to_rfc3339(),
        })
        .collect();

    success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
}

/// 获取 AI 报告详情 (JSON)
#[utoipa::path(
    get,
    path = "/v1/ai/reports/{id}",
    params(
        ("id" = String, Path, description = "报告 ID"),
        ("exclude_content" = Option<bool>, Query, description = "是否排除 html_content 和 raw_metrics_json 大字段（默认 false）"),
    ),
    responses(
        (status = 200, description = "AI 报告详情", body = AIReportRow),
        (status = 404, description = "报告不存在"),
    ),
    tag = "AI 报告"
)]
async fn get_ai_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<GetAIReportQuery>,
) -> Result<Json<AIReportRow>, AppError> {
    let mut report = state
        .cert_store
        .get_ai_report_by_id(&id)
        .await?
        .ok_or(AppError::NotFound("Report not found".into()))?;

    if query.exclude_content.unwrap_or(false) {
        report.html_content = String::new();
        report.raw_metrics_json = String::new();
    }

    Ok(Json(report))
}

/// 查看 AI 报告 HTML (用于浏览器访问)
#[utoipa::path(
    get,
    path = "/v1/ai/reports/{id}/view",
    params(
        ("id" = String, Path, description = "报告 ID")
    ),
    responses(
        (status = 200, description = "HTML 报告页面", content_type = "text/html"),
        (status = 404, description = "报告不存在"),
    ),
    tag = "AI 报告"
)]
async fn view_ai_report_html(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Html<String>, AppError> {
    let report = state
        .cert_store
        .get_ai_report_by_id(&id)
        .await?
        .ok_or(AppError::NotFound("Report not found".into()))?;

    Ok(Html(report.html_content))
}

/// 分页获取报告中的实例指标列表
///
/// 从报告的 raw_metrics_json 中解析实例数据并分页返回，支持按风险等级过滤。
#[utoipa::path(
    get,
    path = "/v1/ai/reports/{id}/instances",
    params(
        ("id" = String, Path, description = "报告 ID"),
        ListReportInstancesQuery,
    ),
    responses(
        (status = 200, description = "实例列表（分页）", body = Vec<AIReportInstanceItem>),
        (status = 404, description = "报告不存在"),
    ),
    tag = "AI 报告"
)]
async fn list_report_instances(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Extension(trace_id): Extension<TraceId>,
    Query(query): Query<ListReportInstancesQuery>,
) -> Response {
    let report = match state.cert_store.get_ai_report_by_id(&id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Report not found",
            )
        }
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                &format!("Failed to get report: {e}"),
            )
        }
    };

    let metrics: Vec<crate::ai::report::LatestMetric> =
        match serde_json::from_str(&report.raw_metrics_json) {
            Ok(m) => m,
            Err(e) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "parse_error",
                    &format!("Failed to parse metrics: {e}"),
                )
            }
        };

    // 计算每个实例的风险等级并过滤
    let filter_level = query.risk_level.as_deref().map(|s| s.trim().to_lowercase());
    let all_items: Vec<AIReportInstanceItem> = metrics
        .into_iter()
        .map(|m| {
            let level = compute_risk_level(m.cpu_usage, m.memory_usage, m.disk_usage);
            AIReportInstanceItem {
                agent_id: m.agent_id,
                instance_name: m.instance_name,
                agent_type: m.agent_type,
                cpu_usage: m.cpu_usage,
                memory_usage: m.memory_usage,
                disk_usage: m.disk_usage,
                risk_level: level,
                timestamp: m.timestamp,
            }
        })
        .filter(|item| filter_level.as_deref().is_none_or(|f| item.risk_level == f))
        .collect();

    let total = all_items.len() as u64;
    let limit = query.limit.unwrap_or(20).min(1000) as usize;
    let offset = query.offset.unwrap_or(0) as usize;

    let items: Vec<AIReportInstanceItem> = all_items.into_iter().skip(offset).take(limit).collect();

    success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
}

/// 根据 CPU/内存/磁盘使用率计算风险等级字符串。
fn compute_risk_level(cpu: Option<f64>, mem: Option<f64>, disk: Option<f64>) -> String {
    let is_high = cpu.is_some_and(|v| v > 85.0)
        || mem.is_some_and(|v| v > 85.0)
        || disk.is_some_and(|v| v > 85.0);
    if is_high {
        return "high".to_string();
    }
    let is_medium = cpu.is_some_and(|v| v > 80.0)
        || mem.is_some_and(|v| v > 80.0)
        || disk.is_some_and(|v| v > 80.0);
    if is_medium {
        return "medium".to_string();
    }
    let is_low = cpu.is_some_and(|v| v >= 60.0)
        || mem.is_some_and(|v| v >= 60.0)
        || disk.is_some_and(|v| v >= 60.0);
    if is_low {
        return "low".to_string();
    }
    "normal".to_string()
}

// ===== 错误处理 =====

#[derive(Debug)]
enum AppError {
    Internal(anyhow::Error),
    NotFound(String),
    BadRequest(String),
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Internal(err) => {
                tracing::error!(error = %err, "Internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
