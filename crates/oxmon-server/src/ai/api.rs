use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use oxmon_common::types::AIReportRow;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::api::pagination::{deserialize_optional_u64, PaginationParams};
use crate::api::{error_response, success_paginated_response};
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
        list_ai_reports,
        get_ai_report,
        view_ai_report_html,
    ),
    components(schemas(
        ListAIAccountsQuery,
        AIAccountResponse,
        CreateAIAccountRequest,
        UpdateAIAccountRequest,
        ListAIReportsQuery,
        AIReportListItem,
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
        .routes(routes!(list_ai_reports))
        .routes(routes!(get_ai_report))
        .routes(routes!(view_ai_report_html))
}

// ===== 数据结构 =====

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
    pub provider: Option<String>,
    pub display_name: String,
    pub description: Option<String>,
    pub enabled: bool,
    /// 敏感字段已脱敏的配置 JSON
    pub config_json: serde_json::Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAIAccountRequest {
    pub config_key: String,
    pub provider: String,
    pub display_name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateAIAccountRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
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

    // 获取总数
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

    // 获取列表数据
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

    let accounts: Vec<AIAccountResponse> = rows
        .into_iter()
        .map(|row| {
            // 构建 config_json（脱敏处理）
            let mut config = json!({});
            if let Some(obj) = config.as_object_mut() {
                obj.insert("api_key".to_string(), json!("***REDACTED***"));
                if row.api_secret.is_some() {
                    obj.insert("secret_key".to_string(), json!("***REDACTED***"));
                }
                if let Some(model) = &row.model {
                    obj.insert("model".to_string(), json!(model));
                }
                if let Some(extra) = &row.extra_config {
                    if let Ok(extra_json) = serde_json::from_str::<serde_json::Value>(extra) {
                        if let Some(extra_obj) = extra_json.as_object() {
                            for (k, v) in extra_obj {
                                obj.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
            }

            AIAccountResponse {
                id: row.id,
                config_key: row.config_key,
                provider: Some(row.provider),
                display_name: row.display_name,
                description: row.description,
                enabled: row.enabled,
                config_json: config,
                created_at: row.created_at.to_rfc3339(),
                updated_at: row.updated_at.to_rfc3339(),
            }
        })
        .collect();

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

    // 构建 config_json（脱敏处理）
    let mut config = json!({});
    if let Some(obj) = config.as_object_mut() {
        obj.insert("api_key".to_string(), json!("***REDACTED***"));
        if row.api_secret.is_some() {
            obj.insert("secret_key".to_string(), json!("***REDACTED***"));
        }
        if let Some(model) = &row.model {
            obj.insert("model".to_string(), json!(model));
        }
        if let Some(extra) = &row.extra_config {
            if let Ok(extra_json) = serde_json::from_str::<serde_json::Value>(extra) {
                if let Some(extra_obj) = extra_json.as_object() {
                    for (k, v) in extra_obj {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    Ok(Json(AIAccountResponse {
        id: row.id,
        config_key: row.config_key,
        provider: Some(row.provider),
        display_name: row.display_name,
        description: row.description,
        enabled: row.enabled,
        config_json: config,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }))
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
    // 从 config JSON 中提取字段
    let api_key = req
        .config
        .get("api_key")
        .and_then(|v| v.as_str())
        .ok_or(AppError::BadRequest("api_key is required in config".into()))?
        .to_string();

    let api_secret = req
        .config
        .get("secret_key")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let model = req
        .config
        .get("model")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // 提取其他额外配置
    let mut extra_fields = req.config.clone();
    if let Some(obj) = extra_fields.as_object_mut() {
        obj.remove("api_key");
        obj.remove("secret_key");
        obj.remove("model");
    }
    let extra_config = if extra_fields
        .as_object()
        .map(|o| o.is_empty())
        .unwrap_or(true)
    {
        None
    } else {
        Some(extra_fields.to_string())
    };

    let row = oxmon_storage::AIAccountRow {
        id: oxmon_common::id::next_id(),
        config_key: req.config_key,
        provider: req.provider,
        display_name: req.display_name,
        description: req.description,
        api_key,
        api_secret,
        model,
        extra_config,
        enabled: req.enabled,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let inserted = state.cert_store.insert_ai_account(&row).await?;

    // 构建响应配置（脱敏）
    let config = req.config;

    Ok((
        StatusCode::CREATED,
        Json(AIAccountResponse {
            id: inserted.id,
            config_key: inserted.config_key,
            provider: Some(inserted.provider),
            display_name: inserted.display_name,
            description: inserted.description,
            enabled: inserted.enabled,
            config_json: config,
            created_at: inserted.created_at.to_rfc3339(),
            updated_at: inserted.updated_at.to_rfc3339(),
        }),
    ))
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
        (status = 200, description = "AI 账号更新成功", body = AIAccountResponse),
        (status = 404, description = "AI 账号不存在"),
    ),
    tag = "AI 管理"
)]
async fn update_ai_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAIAccountRequest>,
) -> Result<Json<AIAccountResponse>, AppError> {
    // 验证账号存在
    state
        .cert_store
        .get_ai_account_by_id(&id)
        .await?
        .ok_or(AppError::NotFound("AI account not found".into()))?;

    // 从 config JSON 中提取字段（如果提供）
    let (api_key, api_secret, model, extra_config) = if let Some(config) = &req.config {
        let api_key = config
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let api_secret = config
            .get("secret_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let model = config
            .get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // 提取其他额外配置
        let mut extra_fields = config.clone();
        if let Some(obj) = extra_fields.as_object_mut() {
            obj.remove("api_key");
            obj.remove("secret_key");
            obj.remove("model");
        }
        let extra_config = if extra_fields
            .as_object()
            .map(|o| o.is_empty())
            .unwrap_or(true)
        {
            None
        } else {
            Some(extra_fields.to_string())
        };

        (api_key, api_secret, model, extra_config)
    } else {
        (None, None, None, None)
    };

    // 更新账号
    state
        .cert_store
        .update_ai_account(
            &id,
            req.display_name,
            req.description,
            api_key,
            api_secret,
            model,
            extra_config,
            req.enabled,
        )
        .await?;

    let updated = state
        .cert_store
        .get_ai_account_by_id(&id)
        .await?
        .ok_or(AppError::NotFound(
            "AI account not found after update".into(),
        ))?;

    // 构建响应配置（脱敏）
    let mut config = json!({});
    if let Some(obj) = config.as_object_mut() {
        obj.insert("api_key".to_string(), json!("***REDACTED***"));
        if updated.api_secret.is_some() {
            obj.insert("secret_key".to_string(), json!("***REDACTED***"));
        }
        if let Some(model) = &updated.model {
            obj.insert("model".to_string(), json!(model));
        }
        if let Some(extra) = &updated.extra_config {
            if let Ok(extra_json) = serde_json::from_str::<serde_json::Value>(extra) {
                if let Some(extra_obj) = extra_json.as_object() {
                    for (k, v) in extra_obj {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    Ok(Json(AIAccountResponse {
        id: updated.id,
        config_key: updated.config_key,
        provider: Some(updated.provider),
        display_name: updated.display_name,
        description: updated.description,
        enabled: updated.enabled,
        config_json: config,
        created_at: updated.created_at.to_rfc3339(),
        updated_at: updated.updated_at.to_rfc3339(),
    }))
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

    // 获取总数（带过滤）
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

    // 获取列表数据（带过滤）
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
        ("id" = String, Path, description = "报告 ID")
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
) -> Result<Json<AIReportRow>, AppError> {
    let report = state
        .cert_store
        .get_ai_report_by_id(&id)
        .await?
        .ok_or(AppError::NotFound("Report not found".into()))?;

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
