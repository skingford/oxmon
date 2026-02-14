use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_empty_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use oxmon_common::types::{
    CreateDictionaryRequest, CreateDictionaryTypeRequest, DictionaryItem, DictionaryType,
    DictionaryTypeSummary, UpdateDictionaryRequest, UpdateDictionaryTypeRequest,
};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

#[derive(Deserialize, IntoParams)]
struct ListByTypeQuery {
    /// 是否仅返回启用的条目（默认 false）
    #[serde(default)]
    enabled_only: bool,
}

/// 获取所有字典类型摘要。
#[utoipa::path(
    get,
    path = "/v1/dictionaries/types",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(PaginationParams),
    responses(
        (status = 200, description = "字典类型列表", body = Vec<DictionaryTypeSummary>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_dict_types(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();

    let total = match state.cert_store.count_all_dict_types() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count dictionary types");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state.cert_store.list_all_dict_types(limit, offset) {
        Ok(types) => success_paginated_response(StatusCode::OK, &trace_id, types, total, limit, offset),
        Err(e) => {
            tracing::error!(error = %e, "Failed to list dictionary types");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 获取指定类型下的所有字典条目。
#[utoipa::path(
    get,
    path = "/v1/dictionaries/type/{dict_type}",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(
        ("dict_type" = String, Path, description = "字典类型"),
        ListByTypeQuery,
        PaginationParams
    ),
    responses(
        (status = 200, description = "字典条目列表", body = Vec<DictionaryItem>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_by_type(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(dict_type): Path<String>,
    Query(query): Query<ListByTypeQuery>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();

    let total = match state.cert_store.count_dictionaries_by_type(&dict_type, query.enabled_only) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, dict_type = %dict_type, "Failed to count dictionaries by type");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state.cert_store.list_dictionaries_by_type(
        &dict_type,
        query.enabled_only,
        limit,
        offset,
    ) {
        Ok(items) => success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset),
        Err(e) => {
            tracing::error!(error = %e, dict_type = %dict_type, "Failed to list dictionaries by type");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 获取单条字典条目详情。
#[utoipa::path(
    get,
    path = "/v1/dictionaries/{id}",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "字典条目 ID")),
    responses(
        (status = 200, description = "字典条目详情", body = DictionaryItem),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "条目不存在", body = crate::api::ApiError)
    )
)]
async fn get_dictionary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_dictionary_by_id(&id) {
        Ok(Some(item)) => success_response(StatusCode::OK, &trace_id, item),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Dictionary item not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to get dictionary item");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 创建字典条目。
#[utoipa::path(
    post,
    path = "/v1/dictionaries",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    request_body = CreateDictionaryRequest,
    responses(
        (status = 201, description = "字典条目已创建", body = DictionaryItem),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 409, description = "dict_type + dict_key 重复", body = crate::api::ApiError)
    )
)]
async fn create_dictionary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateDictionaryRequest>,
) -> impl IntoResponse {
    // Auto-ensure dictionary type exists
    if let Err(e) = state.cert_store.ensure_dictionary_type(&req.dict_type) {
        tracing::warn!(error = %e, dict_type = %req.dict_type, "Failed to auto-ensure dictionary type");
    }
    match state.cert_store.insert_dictionary(&req) {
        Ok(item) => success_response(StatusCode::CREATED, &trace_id, item),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                error_response(
                    StatusCode::CONFLICT,
                    &trace_id,
                    "conflict",
                    "Dictionary item with same type and key already exists",
                )
                .into_response()
            } else {
                tracing::error!(error = %e, "Failed to create dictionary item");
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "storage_error",
                    "Database error",
                )
                .into_response()
            }
        }
    }
}

/// 更新字典条目。
#[utoipa::path(
    put,
    path = "/v1/dictionaries/{id}",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "字典条目 ID")),
    request_body = UpdateDictionaryRequest,
    responses(
        (status = 200, description = "字典条目已更新", body = DictionaryItem),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "条目不存在", body = crate::api::ApiError)
    )
)]
async fn update_dictionary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateDictionaryRequest>,
) -> impl IntoResponse {
    match state.cert_store.update_dictionary(&id, &req) {
        Ok(Some(item)) => success_response(StatusCode::OK, &trace_id, item),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Dictionary item not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update dictionary item");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 删除字典条目（系统内置项不可删除）。
#[utoipa::path(
    delete,
    path = "/v1/dictionaries/{id}",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "字典条目 ID")),
    responses(
        (status = 200, description = "字典条目已删除"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 403, description = "系统内置项不可删除", body = crate::api::ApiError),
        (status = 404, description = "条目不存在", body = crate::api::ApiError)
    )
)]
async fn delete_dictionary(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Check if item exists first
    match state.cert_store.get_dictionary_by_id(&id) {
        Ok(Some(item)) => {
            if item.is_system {
                return error_response(
                    StatusCode::FORBIDDEN,
                    &trace_id,
                    "forbidden",
                    "System built-in dictionary items cannot be deleted",
                )
                .into_response();
            }
            match state.cert_store.delete_dictionary(&id) {
                Ok(true) => {
                    success_empty_response(StatusCode::OK, &trace_id, "Dictionary item deleted")
                }
                Ok(false) => error_response(
                    StatusCode::NOT_FOUND,
                    &trace_id,
                    "not_found",
                    "Dictionary item not found",
                )
                .into_response(),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to delete dictionary item");
                    error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &trace_id,
                        "storage_error",
                        "Database error",
                    )
                    .into_response()
                }
            }
        }
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Dictionary item not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to check dictionary item");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 创建字典类型。
#[utoipa::path(
    post,
    path = "/v1/dictionaries/types",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    request_body = CreateDictionaryTypeRequest,
    responses(
        (status = 201, description = "字典类型已创建", body = DictionaryType),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 409, description = "字典类型已存在", body = crate::api::ApiError)
    )
)]
async fn create_dict_type(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateDictionaryTypeRequest>,
) -> impl IntoResponse {
    match state.cert_store.insert_dictionary_type(&req) {
        Ok(item) => success_response(StatusCode::CREATED, &trace_id, item),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint") {
                error_response(
                    StatusCode::CONFLICT,
                    &trace_id,
                    "conflict",
                    "Dictionary type already exists",
                )
                .into_response()
            } else {
                tracing::error!(error = %e, "Failed to create dictionary type");
                error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "storage_error",
                    "Database error",
                )
                .into_response()
            }
        }
    }
}

/// 更新字典类型。
#[utoipa::path(
    put,
    path = "/v1/dictionaries/types/{dict_type}",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(("dict_type" = String, Path, description = "字典类型标识")),
    request_body = UpdateDictionaryTypeRequest,
    responses(
        (status = 200, description = "字典类型已更新", body = DictionaryType),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "字典类型不存在", body = crate::api::ApiError)
    )
)]
async fn update_dict_type(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(dict_type): Path<String>,
    Json(req): Json<UpdateDictionaryTypeRequest>,
) -> impl IntoResponse {
    match state.cert_store.update_dictionary_type(&dict_type, &req) {
        Ok(Some(item)) => success_response(StatusCode::OK, &trace_id, item),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Dictionary type not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to update dictionary type");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

/// 删除字典类型。
#[utoipa::path(
    delete,
    path = "/v1/dictionaries/types/{dict_type}",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(("dict_type" = String, Path, description = "字典类型标识")),
    responses(
        (status = 200, description = "字典类型已删除"),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "字典类型不存在", body = crate::api::ApiError)
    )
)]
async fn delete_dict_type(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(dict_type): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_dictionary_type(&dict_type) {
        Ok(true) => success_empty_response(StatusCode::OK, &trace_id, "Dictionary type deleted"),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Dictionary type not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete dictionary type");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response()
        }
    }
}

pub fn dictionary_routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_dict_types, create_dict_type))
        .routes(routes!(update_dict_type, delete_dict_type))
        .routes(routes!(list_by_type))
        .routes(routes!(get_dictionary))
        .routes(routes!(create_dictionary, delete_dictionary))
        .routes(routes!(update_dictionary))
}
