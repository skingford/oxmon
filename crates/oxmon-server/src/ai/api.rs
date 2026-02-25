use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use oxmon_common::types::AIReportRow;
use oxmon_storage::cert_store::SystemConfigRow;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};

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
pub struct ListAIAccountsQuery {
    /// 按 provider 过滤 (zhipu, kimi, minimax, claude, codex, custom)
    pub provider: Option<String>,
    /// 按启用状态过滤
    pub enabled: Option<bool>,
    /// 每页记录数
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// 偏移量
    #[serde(default)]
    pub offset: usize,
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
pub struct ListAIReportsQuery {
    /// 按日期过滤 (YYYY-MM-DD)
    pub report_date: Option<String>,
    /// 按风险等级过滤 (high, medium, low, normal)
    pub risk_level: Option<String>,
    /// 每页记录数
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// 偏移量
    #[serde(default)]
    pub offset: usize,
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

fn default_limit() -> usize {
    50
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
    State(state): State<AppState>,
    Query(query): Query<ListAIAccountsQuery>,
) -> Result<Json<Vec<AIAccountResponse>>, AppError> {
    let rows = state.cert_store.list_system_configs(
        Some("ai_account"),
        query.provider.as_deref(),
        query.enabled,
        query.limit,
        query.offset,
    )?;

    let accounts: Vec<AIAccountResponse> = rows
        .into_iter()
        .map(|row| {
            let mut config = serde_json::from_str::<serde_json::Value>(&row.config_json)
                .unwrap_or_else(|_| json!({}));

            // 脱敏处理: 隐藏 API Key
            if let Some(obj) = config.as_object_mut() {
                if obj.contains_key("api_key") {
                    obj.insert("api_key".to_string(), json!("***REDACTED***"));
                }
                if obj.contains_key("secret_key") {
                    obj.insert("secret_key".to_string(), json!("***REDACTED***"));
                }
            }

            AIAccountResponse {
                id: row.id,
                config_key: row.config_key,
                provider: row.provider,
                display_name: row.display_name,
                description: row.description,
                enabled: row.enabled,
                config_json: config,
                created_at: row.created_at.to_rfc3339(),
                updated_at: row.updated_at.to_rfc3339(),
            }
        })
        .collect();

    Ok(Json(accounts))
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
        .get_system_config_by_id(&id)?
        .ok_or(AppError::NotFound("AI account not found".into()))?;

    if row.config_type != "ai_account" {
        return Err(AppError::NotFound("AI account not found".into()));
    }

    let mut config =
        serde_json::from_str::<serde_json::Value>(&row.config_json).unwrap_or_else(|_| json!({}));

    // 脱敏处理
    if let Some(obj) = config.as_object_mut() {
        if obj.contains_key("api_key") {
            obj.insert("api_key".to_string(), json!("***REDACTED***"));
        }
        if obj.contains_key("secret_key") {
            obj.insert("secret_key".to_string(), json!("***REDACTED***"));
        }
    }

    Ok(Json(AIAccountResponse {
        id: row.id,
        config_key: row.config_key,
        provider: row.provider,
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
    let row = SystemConfigRow {
        id: oxmon_common::id::next_id(),
        config_key: req.config_key,
        config_type: "ai_account".to_string(),
        provider: Some(req.provider),
        display_name: req.display_name,
        description: req.description,
        config_json: req.config.to_string(),
        enabled: req.enabled,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let inserted = state.cert_store.insert_system_config(&row)?;

    let mut config = req.config;
    if let Some(obj) = config.as_object_mut() {
        if obj.contains_key("api_key") {
            obj.insert("api_key".to_string(), json!("***REDACTED***"));
        }
        if obj.contains_key("secret_key") {
            obj.insert("secret_key".to_string(), json!("***REDACTED***"));
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(AIAccountResponse {
            id: inserted.id,
            config_key: inserted.config_key,
            provider: inserted.provider,
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
    let row = state
        .cert_store
        .get_system_config_by_id(&id)?
        .ok_or(AppError::NotFound("AI account not found".into()))?;

    if row.config_type != "ai_account" {
        return Err(AppError::NotFound("AI account not found".into()));
    }

    let update = oxmon_storage::cert_store::SystemConfigUpdate {
        display_name: req.display_name,
        description: req.description.map(Some),
        config_json: req.config.map(|c| c.to_string()),
        enabled: req.enabled,
    };

    let updated = state
        .cert_store
        .update_system_config(&id, &update)?
        .ok_or(AppError::NotFound("AI account not found".into()))?;

    let mut config = serde_json::from_str::<serde_json::Value>(&updated.config_json)
        .unwrap_or_else(|_| json!({}));

    if let Some(obj) = config.as_object_mut() {
        if obj.contains_key("api_key") {
            obj.insert("api_key".to_string(), json!("***REDACTED***"));
        }
        if obj.contains_key("secret_key") {
            obj.insert("secret_key".to_string(), json!("***REDACTED***"));
        }
    }

    Ok(Json(AIAccountResponse {
        id: updated.id,
        config_key: updated.config_key,
        provider: updated.provider,
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
    let deleted = state.cert_store.delete_system_config(&id)?;
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
    State(state): State<AppState>,
    Query(query): Query<ListAIReportsQuery>,
) -> Result<Json<Vec<AIReportListItem>>, AppError> {
    let rows = state
        .cert_store
        .list_ai_reports(query.limit, query.offset)?;

    // 过滤
    let mut filtered: Vec<AIReportRow> = rows;
    if let Some(date) = &query.report_date {
        filtered.retain(|r| r.report_date == *date);
    }
    if let Some(level) = &query.risk_level {
        filtered.retain(|r| r.risk_level == *level);
    }

    let items: Vec<AIReportListItem> = filtered
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

    Ok(Json(items))
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
        .get_ai_report_by_id(&id)?
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
        .get_ai_report_by_id(&id)?
        .ok_or(AppError::NotFound("Report not found".into()))?;

    Ok(Html(report.html_content))
}

// ===== 错误处理 =====

#[derive(Debug)]
enum AppError {
    Internal(anyhow::Error),
    NotFound(String),
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
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
