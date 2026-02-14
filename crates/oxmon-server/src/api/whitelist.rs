use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_empty_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::response::IntoResponse;
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use oxmon_common::types::{
    AddAgentRequest, AddAgentResponse, AgentWhitelistDetail, RegenerateTokenResponse,
    UpdateAgentRequest,
};
use oxmon_storage::auth::{generate_token, hash_token};
use utoipa_axum::{router::OpenApiRouter, routes};

/// 新增白名单 Agent。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/agents/whitelist",
    request_body = AddAgentRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 201, description = "新增白名单 Agent 结果", body = AddAgentResponse),
        (status = 401, description = "未认证"),
        (status = 409, description = "Agent ID 已存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn add_agent(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<AddAgentRequest>,
) -> impl IntoResponse {
    // 检查 agent_id 是否已存在
    let exists = state
        .cert_store
        .get_agent_token_hash(&req.agent_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check agent existence");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        });

    let exists = match exists {
        Ok(v) => v,
        Err(resp) => return resp,
    }
    .is_some();

    if exists {
        return error_response(
            StatusCode::CONFLICT,
            &trace_id,
            "conflict",
            &format!("Agent '{}' already exists", req.agent_id),
        );
    }

    // 生成 token
    let token = generate_token();
    let token_hash = match hash_token(&token).map_err(|e| {
        tracing::error!(error = %e, "Failed to hash token");
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &trace_id,
            "internal_error",
            "Token generation error",
        )
    }) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // 存储到白名单表（不包含 collection_interval_secs）
    let created_at = Utc::now();
    let id = match state
        .cert_store
        .add_agent_to_whitelist(
            &req.agent_id,
            &token,
            &token_hash,
            req.description.as_deref(),
        )
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to add agent to whitelist");
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

    // 初始化 agent 到 agents 表（包含 collection_interval_secs）
    if let Err(resp) = state
        .cert_store
        .upsert_agent(&req.agent_id)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to initialize agent");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        })
    {
        return resp;
    }

    // 更新 agents 表的配置（collection_interval_secs）
    if let Err(resp) = state
        .cert_store
        .update_agent_config(
            &req.agent_id,
            req.collection_interval_secs,
            req.description.as_deref(),
        )
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update agent config");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        })
    {
        return resp;
    }

    tracing::info!(agent_id = %req.agent_id, id = %id, "Agent added to whitelist");

    success_response(
        StatusCode::CREATED,
        &trace_id,
        AddAgentResponse {
            id,
            agent_id: req.agent_id,
            token,
            created_at,
        },
    )
}

/// 分页查询白名单 Agent 列表（包含在线状态）。
/// 默认排序：`created_at` 倒序；默认分页：`limit=20&offset=0`。
#[utoipa::path(
    get,
    path = "/v1/agents/whitelist",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "白名单 Agent 分页列表", body = Vec<AgentWhitelistDetail>),
        (status = 401, description = "未认证"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn list_whitelist_agents(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();

    let total = match state.cert_store.count_agents().map_err(|e| {
        tracing::error!(error = %e, "Failed to count agents");
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

    let agents = match state.cert_store.list_agents(limit, offset).map_err(|e| {
        tracing::error!(error = %e, "Failed to list agents");
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

    let registry = state
        .agent_registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let items: Vec<AgentWhitelistDetail> = agents
        .into_iter()
        .map(|entry| {
            let agent_info = registry.get_agent(&entry.agent_id);
            AgentWhitelistDetail {
                id: entry.id,
                agent_id: entry.agent_id,
                created_at: entry.created_at,
                updated_at: entry.updated_at,
                description: entry.description,
                token: None, // Never expose tokens in list responses
                collection_interval_secs: entry.collection_interval_secs,
                last_seen: agent_info.as_ref().map(|a| a.last_seen),
                status: match &agent_info {
                    Some(a) if a.active => "active".to_string(),
                    Some(_) => "inactive".to_string(),
                    None => "unknown".to_string(),
                },
            }
        })
        .collect();

    success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
}

/// 获取单个白名单 Agent 详情（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    get,
    path = "/v1/agents/whitelist/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "白名单条目 ID（路径参数）")
    ),
    responses(
        (status = 200, description = "白名单 Agent 详情", body = AgentWhitelistDetail),
        (status = 401, description = "未认证"),
        (status = 404, description = "Agent 不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn get_whitelist_agent(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let entry = match state.cert_store.get_agent_by_id(&id).map_err(|e| {
        tracing::error!(error = %e, "Failed to get agent");
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
                &format!("Agent with id '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    let registry = state
        .agent_registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let agent_info = registry.get_agent(&entry.agent_id);

    let detail = AgentWhitelistDetail {
        id: entry.id,
        agent_id: entry.agent_id,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        description: entry.description,
        token: None, // Never expose tokens in responses
        collection_interval_secs: entry.collection_interval_secs,
        last_seen: agent_info.as_ref().map(|a| a.last_seen),
        status: match &agent_info {
            Some(a) if a.active => "active".to_string(),
            Some(_) => "inactive".to_string(),
            None => "unknown".to_string(),
        },
    };

    success_response(StatusCode::OK, &trace_id, detail)
}

/// 更新白名单 Agent 信息（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    put,
    path = "/v1/agents/whitelist/{id}",
    request_body = UpdateAgentRequest,
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "白名单条目 ID（路径参数）")
    ),
    responses(
        (status = 200, description = "更新白名单 Agent 结果", body = AgentWhitelistDetail),
        (status = 401, description = "未认证"),
        (status = 404, description = "Agent 不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn update_agent(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> impl IntoResponse {
    // 获取白名单条目以获取 agent_id
    let entry = match state.cert_store.get_agent_by_id(&id).map_err(|e| {
        tracing::error!(error = %e, "Failed to query agent");
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
                &format!("Agent with id '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    // 更新白名单表（只更新 description）
    if let Err(resp) = state
        .cert_store
        .update_agent_whitelist(&id, req.description.as_deref())
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update agent whitelist");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        })
    {
        return resp;
    }

    // 更新 agents 表（collection_interval_secs 和 description）
    if let Err(resp) = state
        .cert_store
        .update_agent_config(
            &entry.agent_id,
            req.collection_interval_secs,
            req.description.as_deref(),
        )
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update agent config");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        })
    {
        return resp;
    }

    // 重新查询获取完整信息
    let entry = match state.cert_store.get_agent_by_id(&id).map_err(|e| {
        tracing::error!(error = %e, "Failed to query agent");
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
                &format!("Agent with id '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    let registry = state
        .agent_registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let agent_info = registry.get_agent(&entry.agent_id);

    tracing::info!(id = %id, agent_id = %entry.agent_id, "Agent whitelist entry updated");

    success_response(
        StatusCode::OK,
        &trace_id,
        AgentWhitelistDetail {
            id: entry.id,
            agent_id: entry.agent_id,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
            description: entry.description,
            token: None, // Never expose tokens in update responses
            collection_interval_secs: entry.collection_interval_secs,
            last_seen: agent_info.as_ref().map(|a| a.last_seen),
            status: match &agent_info {
                Some(a) if a.active => "active".to_string(),
                Some(_) => "inactive".to_string(),
                None => "unknown".to_string(),
            },
        },
    )
}

/// 重新生成白名单 Agent 的认证 Token（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    post,
    path = "/v1/agents/whitelist/{id}/token",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "白名单条目 ID（路径参数）")
    ),
    responses(
        (status = 200, description = "重新生成 Token 结果", body = RegenerateTokenResponse),
        (status = 401, description = "未认证"),
        (status = 404, description = "Agent 不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn regenerate_token(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 检查 agent 是否存在
    let entry = match state.cert_store.get_agent_by_id(&id).map_err(|e| {
        tracing::error!(error = %e, "Failed to check agent existence");
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
                &format!("Agent with id '{}' not found", id),
            )
        }
        Err(resp) => return resp,
    };

    // 生成新 token
    let token = generate_token();
    let token_hash = match hash_token(&token).map_err(|e| {
        tracing::error!(error = %e, "Failed to hash token");
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &trace_id,
            "internal_error",
            "Token generation error",
        )
    }) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // 更新数据库
    if let Err(resp) = state
        .cert_store
        .update_agent_token_hash(&id, &token, &token_hash)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update agent token");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "internal_error",
                "Database error",
            )
        })
    {
        return resp;
    }

    tracing::info!(id = %id, agent_id = %entry.agent_id, "Agent token regenerated");

    success_response(
        StatusCode::OK,
        &trace_id,
        RegenerateTokenResponse {
            agent_id: entry.agent_id,
            token,
        },
    )
}

/// 删除白名单 Agent（按 ID）。
/// 鉴权：需要 Bearer Token。
#[utoipa::path(
    delete,
    path = "/v1/agents/whitelist/{id}",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "白名单条目 ID（路径参数）")
    ),
    responses(
        (status = 200, description = "删除成功"),
        (status = 401, description = "未认证"),
        (status = 404, description = "Agent 不存在"),
        (status = 500, description = "服务器错误")
    ),
    tag = "Agents"
)]
async fn delete_agent(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 先查询获取 agent_id 用于从内存注册表中删除
    let entry = match state.cert_store.get_agent_by_id(&id).map_err(|e| {
        tracing::error!(error = %e, "Failed to query agent");
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

    // 从白名单中删除
    let deleted_from_whitelist =
        match state
            .cert_store
            .delete_agent_from_whitelist(&id)
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete agent");
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

    // 从内存注册表中删除
    let deleted_from_registry = if let Some(entry) = &entry {
        state
            .agent_registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove_agent(&entry.agent_id)
    } else {
        false
    };

    if !deleted_from_whitelist && !deleted_from_registry {
        return error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            &format!("Agent with id '{}' not found", id),
        );
    }

    tracing::info!(
        id = %id,
        agent_id = entry.as_ref().map(|e| e.agent_id.as_str()).unwrap_or("unknown"),
        whitelist = deleted_from_whitelist,
        registry = deleted_from_registry,
        "Agent removed"
    );
    success_empty_response(StatusCode::OK, &trace_id, "success")
}

pub fn whitelist_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(add_agent))
        .routes(routes!(list_whitelist_agents))
        .routes(routes!(get_whitelist_agent, update_agent))
        .routes(routes!(regenerate_token))
        .routes(routes!(delete_agent))
}
