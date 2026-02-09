use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use oxmon_common::types::{
    AddAgentRequest, AddAgentResponse, AgentWhitelistDetail, RegenerateTokenResponse,
    UpdateAgentRequest,
};
use oxmon_storage::auth::{generate_token, hash_token};
use serde_json::json;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 添加 Agent 到白名单
#[utoipa::path(
    post,
    path = "/v1/agents/whitelist",
    request_body = AddAgentRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Agent 添加成功", body = AddAgentResponse),
        (status = 401, description = "未认证"),
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
    let id = state
        .cert_store
        .add_agent_to_whitelist(&req.agent_id, &token, &token_hash, req.description.as_deref())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to add agent to whitelist");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?;

    tracing::info!(agent_id = %req.agent_id, id = %id, "Agent added to whitelist");

    Ok(Json(AddAgentResponse {
        id,
        agent_id: req.agent_id,
        token,
        created_at,
    }))
}

/// 列出所有白名单中的 Agent（包含在线状态）
#[utoipa::path(
    get,
    path = "/v1/agents/whitelist",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Agent 列表", body = Vec<AgentWhitelistDetail>),
        (status = 401, description = "未认证"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn list_agents(
    State(state): State<AppState>,
) -> Result<Json<Vec<AgentWhitelistDetail>>, (StatusCode, Json<serde_json::Value>)> {
    let agents = state.cert_store.list_agents().map_err(|e| {
        tracing::error!(error = %e, "Failed to list agents");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?;

    let registry = state.agent_registry.lock().unwrap();
    let details: Vec<AgentWhitelistDetail> = agents
        .into_iter()
        .map(|entry| {
            let agent_info = registry.get_agent(&entry.agent_id);
            AgentWhitelistDetail {
                id: entry.id,
                agent_id: entry.agent_id,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
                description: entry.description,
                token: entry.token,
                last_seen: agent_info.as_ref().map(|a| a.last_seen),
                status: match &agent_info {
                    Some(a) if a.active => "active".to_string(),
                    Some(_) => "inactive".to_string(),
                    None => "unknown".to_string(),
                },
            }
        })
        .collect();

    Ok(Json(details))
}

/// 更新 Agent 白名单信息
#[utoipa::path(
    put,
    path = "/v1/agents/whitelist/{id}",
    request_body = UpdateAgentRequest,
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent 白名单唯一标识")
    ),
    responses(
        (status = 200, description = "Agent 更新成功", body = AgentWhitelistDetail),
        (status = 401, description = "未认证"),
        (status = 404, description = "Agent 不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn update_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> Result<Json<AgentWhitelistDetail>, (StatusCode, Json<serde_json::Value>)> {
    let updated = state
        .cert_store
        .update_agent_whitelist(&id, req.description.as_deref())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update agent");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?;

    if !updated {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Agent with id '{}' not found", id)})),
        ));
    }

    // 重新查询获取完整信息
    let entry = state
        .cert_store
        .get_agent_by_id(&id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query agent");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Agent with id '{}' not found", id)})),
            )
        })?;

    let registry = state.agent_registry.lock().unwrap();
    let agent_info = registry.get_agent(&entry.agent_id);

    tracing::info!(id = %id, agent_id = %entry.agent_id, "Agent whitelist entry updated");

    Ok(Json(AgentWhitelistDetail {
        id: entry.id,
        agent_id: entry.agent_id,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        description: entry.description,
        token: entry.token,
        last_seen: agent_info.as_ref().map(|a| a.last_seen),
        status: match &agent_info {
            Some(a) if a.active => "active".to_string(),
            Some(_) => "inactive".to_string(),
            None => "unknown".to_string(),
        },
    }))
}

/// 重新生成 Agent 认证 Token
#[utoipa::path(
    post,
    path = "/v1/agents/whitelist/{id}/token",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent 白名单唯一标识")
    ),
    responses(
        (status = 200, description = "Token 重新生成成功", body = RegenerateTokenResponse),
        (status = 401, description = "未认证"),
        (status = 404, description = "Agent 不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn regenerate_token(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RegenerateTokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 检查 agent 是否存在
    let entry = state
        .cert_store
        .get_agent_by_id(&id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check agent existence");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("Agent with id '{}' not found", id)})),
            )
        })?;

    // 生成新 token
    let token = generate_token();
    let token_hash = hash_token(&token).map_err(|e| {
        tracing::error!(error = %e, "Failed to hash token");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Token generation error"})),
        )
    })?;

    // 更新数据库
    state
        .cert_store
        .update_agent_token_hash(&id, &token, &token_hash)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update agent token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?;

    tracing::info!(id = %id, agent_id = %entry.agent_id, "Agent token regenerated");

    Ok(Json(RegenerateTokenResponse {
        agent_id: entry.agent_id,
        token,
    }))
}

/// 删除 Agent（从白名单和内存注册表中移除）
#[utoipa::path(
    delete,
    path = "/v1/agents/whitelist/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "Agent 白名单唯一标识")
    ),
    responses(
        (status = 200, description = "Agent 删除成功"),
        (status = 401, description = "未认证"),
        (status = 404, description = "Agent 不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn delete_agent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    // 先查询获取 agent_id 用于从内存注册表中删除
    let entry = state
        .cert_store
        .get_agent_by_id(&id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query agent");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?;

    // 从白名单中删除
    let deleted_from_whitelist = state
        .cert_store
        .delete_agent_from_whitelist(&id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to delete agent");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
        })?;

    // 从内存注册表中删除
    let deleted_from_registry = if let Some(entry) = &entry {
        state
            .agent_registry
            .lock()
            .unwrap()
            .remove_agent(&entry.agent_id)
    } else {
        false
    };

    if !deleted_from_whitelist && !deleted_from_registry {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Agent with id '{}' not found", id)})),
        ));
    }

    tracing::info!(
        id = %id,
        agent_id = entry.as_ref().map(|e| e.agent_id.as_str()).unwrap_or("unknown"),
        whitelist = deleted_from_whitelist,
        registry = deleted_from_registry,
        "Agent removed"
    );
    Ok(StatusCode::OK)
}

pub fn whitelist_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(add_agent))
        .routes(routes!(list_agents))
        .routes(routes!(update_agent))
        .routes(routes!(regenerate_token))
        .routes(routes!(delete_agent))
}
