use crate::api::pagination::PaginationParams;
use crate::api::{
    error_response, success_id_response, success_paginated_response, success_response,
};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use oxmon_common::types::{
    CreateDictionaryRequest, CreateDictionaryTypeRequest, DictionaryItem, DictionaryTypeSummary,
    UpdateDictionaryRequest, UpdateDictionaryTypeRequest,
};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 字典类型列表查询参数
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListDictTypesParams {
    /// 字典类型标识模糊匹配
    #[param(required = false, rename = "dict_type__contains")]
    #[serde(rename = "dict_type__contains")]
    dict_type_contains: Option<String>,
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

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListByTypesAllQuery {
    /// 字典类型，逗号分隔多个（如 ?dict_type__in=channel_type,severity_level）
    #[param(required = false, rename = "dict_type__in")]
    #[serde(rename = "dict_type__in")]
    dict_type_in: Option<String>,
    /// 是否仅返回启用的条目（默认 false）
    #[serde(default)]
    enabled_only: bool,
    /// dict_key 模糊匹配
    #[param(required = false, rename = "key__contains")]
    #[serde(rename = "key__contains")]
    key_contains: Option<String>,
    /// dict_label 模糊匹配
    #[param(required = false, rename = "label__contains")]
    #[serde(rename = "label__contains")]
    label_contains: Option<String>,
}

/// 获取所有字典类型摘要。
#[utoipa::path(
    get,
    path = "/v1/dictionaries/types",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(ListDictTypesParams),
    responses(
        (status = 200, description = "字典类型列表", body = Vec<DictionaryTypeSummary>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_dict_types(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListDictTypesParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);
    let dict_type_contains = params.dict_type_contains.as_deref();

    let total = match state.cert_store.count_all_dict_types(dict_type_contains) {
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

    match state
        .cert_store
        .list_all_dict_types(dict_type_contains, limit, offset)
    {
        Ok(types) => {
            success_paginated_response(StatusCode::OK, &trace_id, types, total, limit, offset)
        }
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

/// 批量获取指定类型下的字典条目，支持同时查询多个类型。
#[utoipa::path(
    get,
    path = "/v1/dictionaries/types/all",
    tag = "Dictionaries",
    security(("bearer_auth" = [])),
    params(ListByTypesAllQuery, PaginationParams),
    responses(
        (status = 200, description = "字典条目列表", body = Vec<DictionaryItem>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_by_types_all(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(query): Query<ListByTypesAllQuery>,
    Query(pagination): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = pagination.limit();
    let offset = pagination.offset();

    let dict_types: Vec<&str> = query
        .dict_type_in
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let key_contains = query.key_contains.as_deref();
    let label_contains = query.label_contains.as_deref();

    let total = match state.cert_store.count_dictionaries_by_types(
        &dict_types,
        query.enabled_only,
        key_contains,
        label_contains,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count dictionaries by types");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    match state.cert_store.list_dictionaries_by_types(
        &dict_types,
        query.enabled_only,
        key_contains,
        label_contains,
        limit,
        offset,
    ) {
        Ok(items) => {
            success_paginated_response(StatusCode::OK, &trace_id, items, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list dictionaries by types");
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
        (status = 201, description = "字典条目已创建", body = crate::api::IdResponse),
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
        Ok(item) => success_id_response(StatusCode::CREATED, &trace_id, item.id),
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
        (status = 200, description = "字典条目已更新", body = crate::api::IdResponse),
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
        Ok(Some(item)) => success_id_response(StatusCode::OK, &trace_id, item.id),
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
        (status = 200, description = "字典条目已删除", body = crate::api::IdResponse),
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
                Ok(true) => success_id_response(StatusCode::OK, &trace_id, id),
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
        (status = 201, description = "字典类型已创建", body = crate::api::IdResponse),
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
        Ok(item) => success_id_response(StatusCode::CREATED, &trace_id, item.dict_type),
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
        (status = 200, description = "字典类型已更新", body = crate::api::IdResponse),
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
        Ok(Some(item)) => success_id_response(StatusCode::OK, &trace_id, item.dict_type),
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
        (status = 200, description = "字典类型已删除", body = crate::api::IdResponse),
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
        Ok(true) => success_id_response(StatusCode::OK, &trace_id, dict_type),
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
        .routes(routes!(list_by_types_all))
        .routes(routes!(get_dictionary))
        .routes(routes!(create_dictionary, delete_dictionary))
        .routes(routes!(update_dictionary))
}
