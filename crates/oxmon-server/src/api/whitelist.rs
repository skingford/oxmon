use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use oxmon_common::types::{AddAgentRequest, AddAgentResponse, AgentWhitelistEntry};
use oxmon_storage::auth::{generate_token, hash_token};
use serde_json::json;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 添加 Agent 到白名单
#[utoipa::path(
    post,
    path = "/api/v1/agents/whitelist",
    request_body = AddAgentRequest,
    responses(
        (status = 200, description = "Agent 添加成功", body = AddAgentResponse),
        (status = 409, description = "Agent ID 已存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn add_agent(
    State(state): State<AppState>,
    Json(req): Json<AddAgentRequest>,
) -> Result<Json<AddAgentResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 检查 agent_id 是否已存在
    let exists = state
        .cert_store
        .get_agent_token_hash(&req.agent_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check agent existence");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?
        .is_some();

    if exists {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": format!("Agent '{}' already exists", req.agent_id)})),
        ));
    }

    // 生成 token
    let token = generate_token();
    let token_hash = hash_token(&token).map_err(|e| {
        tracing::error!(error = %e, "Failed to hash token");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Token generation error"})),
        )
    })?;

    // 存储到数据库
    let created_at = Utc::now();
    state
        .cert_store
        .add_agent_to_whitelist(&req.agent_id, &token_hash, req.description.as_deref())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to add agent to whitelist");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?;

    tracing::info!(agent_id = %req.agent_id, "Agent added to whitelist");

    Ok(Json(AddAgentResponse {
        agent_id: req.agent_id,
        token,
        created_at,
    }))
}

/// 列出所有白名单中的 Agent
#[utoipa::path(
    get,
    path = "/api/v1/agents/whitelist",
    responses(
        (status = 200, description = "Agent 列表", body = Vec<AgentWhitelistEntry>),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn list_agents(
    State(state): State<AppState>,
) -> Result<Json<Vec<AgentWhitelistEntry>>, (StatusCode, Json<serde_json::Value>)> {
    let agents = state.cert_store.list_agents().map_err(|e| {
        tracing::error!(error = %e, "Failed to list agents");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?;

    Ok(Json(agents))
}

/// 从白名单中删除 Agent
#[utoipa::path(
    delete,
    path = "/api/v1/agents/whitelist/{agent_id}",
    params(
        ("agent_id" = String, Path, description = "Agent 唯一标识")
    ),
    responses(
        (status = 200, description = "Agent 删除成功"),
        (status = 404, description = "Agent 不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn delete_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let deleted = state
        .cert_store
        .delete_agent_from_whitelist(&agent_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to delete agent");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?;

    if !deleted {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Agent '{}' not found", agent_id)})),
        ));
    }

    tracing::info!(agent_id = %agent_id, "Agent removed from whitelist");
    Ok(StatusCode::OK)
}

pub fn whitelist_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(add_agent))
        .routes(routes!(list_agents))
        .routes(routes!(delete_agent))
}
