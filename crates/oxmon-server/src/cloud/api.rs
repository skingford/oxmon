use crate::api::pagination::PaginationParams;
use crate::api::{error_response, success_paginated_response, success_response};
use crate::logging::TraceId;
use crate::state::AppState;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use oxmon_cloud::{build_provider, CloudAccountConfig};
use oxmon_storage::{CloudAccountRow, CloudInstanceRow, MetricQuery};
use oxmon_storage::StorageEngine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

/// 云账户响应
#[derive(Serialize, ToSchema)]
struct CloudAccountResponse {
    id: String,
    config_key: String,
    provider: String,
    display_name: String,
    description: Option<String>,
    /// 云账号名称（如"主账号"）
    account_name: String,
    secret_id: String,
    secret_key: String,
    /// 地域列表（如 ["ap-shanghai", "ap-guangzhou"]）
    regions: Vec<String>,
    collection_interval_secs: i64,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

/// 创建云账户请求
#[derive(Deserialize, ToSchema)]
struct CreateCloudAccountRequest {
    /// 配置标识（唯一，如 cloud_tencent_prod）
    config_key: String,
    /// 云供应商（tencent 或 alibaba）
    provider: String,
    /// 显示名称
    display_name: String,
    /// 描述
    description: Option<String>,
    /// 云账号名称（如"主账号"、"子账号1"）
    account_name: String,
    /// API 密钥 ID（腾讯云 SecretId, 阿里云 AccessKeyId）
    secret_id: String,
    /// API 密钥 Secret（腾讯云 SecretKey, 阿里云 AccessKeySecret）
    secret_key: String,
    /// 地域列表（如 ["ap-shanghai", "ap-guangzhou"]）
    regions: Vec<String>,
    /// 采集间隔（秒，默认 3600）
    collection_interval_secs: Option<i64>,
}

/// 更新云账户请求
#[derive(Deserialize, ToSchema)]
struct UpdateCloudAccountRequest {
    display_name: Option<String>,
    description: Option<Option<String>>,
    /// 云账号名称
    account_name: Option<String>,
    secret_id: Option<String>,
    secret_key: Option<String>,
    /// 地域列表（传入则完整替换）
    regions: Option<Vec<String>>,
    collection_interval_secs: Option<i64>,
    enabled: Option<bool>,
}

/// 云实例响应
#[derive(Serialize, ToSchema)]
struct CloudInstanceResponse {
    /// 系统雪花ID(主键)
    #[schema(example = "1234567890123456789")]
    id: String,
    /// 云提供商的实例ID
    #[schema(example = "ins-ic9p379n")]
    instance_id: String,
    instance_name: Option<String>,
    provider: String,
    account_config_key: String,
    region: String,
    public_ip: Option<String>,
    private_ip: Option<String>,
    os: Option<String>,
    /// 原始云厂商状态归一化后的状态（running/pending/stopped/error/unknown）
    normalized_status: String,
    status: Option<String>,
    last_seen_at: String,
    created_at: String,
    updated_at: String,
    // Hardware specifications
    instance_type: Option<String>,
    cpu_cores: Option<i32>,
    memory_gb: Option<f64>,
    disk_gb: Option<f64>,
    // Phase 1: Lifecycle information
    /// 实例创建时间(Unix timestamp)
    created_time: Option<i64>,
    /// 实例过期时间(Unix timestamp,仅预付费实例)
    expired_time: Option<i64>,
    /// 计费类型(PREPAID/POSTPAID_BY_HOUR/PrePaid/PostPaid)
    charge_type: Option<String>,
    // Phase 1: Network configuration
    /// VPC ID
    vpc_id: Option<String>,
    /// 子网/交换机ID
    subnet_id: Option<String>,
    /// 安全组ID列表
    security_group_ids: Vec<String>,
    // Phase 1: Location
    /// 可用区
    zone: Option<String>,
    // Phase 2: Advanced network
    /// 公网带宽上限(Mbps)
    internet_max_bandwidth: Option<i32>,
    /// IPv6地址列表
    ipv6_addresses: Vec<String>,
    /// 弹性公网IP分配ID(阿里云)
    eip_allocation_id: Option<String>,
    /// 网络计费类型
    internet_charge_type: Option<String>,
    // Phase 2: System and image
    /// 镜像ID
    image_id: Option<String>,
    /// 主机名
    hostname: Option<String>,
    /// 实例描述
    description: Option<String>,
    // Phase 2: Compute extensions
    /// GPU核数
    gpu: Option<i32>,
    /// IO优化状态
    io_optimized: Option<String>,
    // Phase 2: Operation tracking
    /// 最近操作
    latest_operation: Option<String>,
    /// 最近操作状态
    latest_operation_state: Option<String>,
    // Phase 3: Additional metadata
    /// 标签
    tags: std::collections::HashMap<String, String>,
    /// 项目ID
    project_id: Option<String>,
    /// 资源组ID
    resource_group_id: Option<String>,
    /// 自动续费标识
    auto_renew_flag: Option<String>,
}

/// 单条指标最新值
#[derive(Serialize, ToSchema)]
struct MetricLatestValue {
    /// 指标名称
    metric_name: String,
    /// 最新值
    value: f64,
    /// 采集时间
    collected_at: String,
}

/// 云实例详情响应（包含实时指标）
#[derive(Serialize, ToSchema)]
struct CloudInstanceDetailResponse {
    // ---- Instance basic info ----
    /// 数据库主键
    id: String,
    /// 云实例 ID（如 ins-abc123）
    instance_id: String,
    /// 实例名称
    instance_name: Option<String>,
    /// 云供应商（tencent / alibaba）
    provider: String,
    /// 关联的云账户 config_key
    account_config_key: String,
    /// 地域
    region: String,
    /// 公网 IP
    public_ip: Option<String>,
    /// 内网 IP
    private_ip: Option<String>,
    /// 操作系统
    os: Option<String>,
    /// 归一化状态（running/pending/stopped/error/unknown）
    normalized_status: String,
    /// 实例状态（Running / Stopped 等）
    status: Option<String>,

    // ---- Hardware specifications ----
    /// 实例规格（如 S5.LARGE8）
    instance_type: Option<String>,
    /// CPU 核心数
    cpu_cores: Option<i32>,
    /// 内存（GB）
    memory_gb: Option<f64>,
    /// 磁盘总容量（GB）
    disk_gb: Option<f64>,

    // ---- Phase 1: Lifecycle information ----
    /// 实例创建时间(Unix timestamp)
    created_time: Option<i64>,
    /// 实例过期时间(Unix timestamp,仅预付费实例)
    expired_time: Option<i64>,
    /// 计费类型(PREPAID/POSTPAID_BY_HOUR/PrePaid/PostPaid)
    charge_type: Option<String>,

    // ---- Phase 1: Network configuration ----
    /// VPC ID
    vpc_id: Option<String>,
    /// 子网/交换机ID
    subnet_id: Option<String>,
    /// 安全组ID列表
    security_group_ids: Vec<String>,

    // ---- Phase 1: Location ----
    /// 可用区
    zone: Option<String>,

    // ---- Phase 2: Advanced network ----
    /// 公网带宽上限(Mbps)
    internet_max_bandwidth: Option<i32>,
    /// IPv6地址列表
    ipv6_addresses: Vec<String>,
    /// 弹性公网IP分配ID(阿里云)
    eip_allocation_id: Option<String>,
    /// 网络计费类型
    internet_charge_type: Option<String>,

    // ---- Phase 2: System and image ----
    /// 镜像ID
    image_id: Option<String>,
    /// 主机名
    hostname: Option<String>,
    /// 实例描述
    description: Option<String>,

    // ---- Phase 2: Compute extensions ----
    /// GPU核数
    gpu: Option<i32>,
    /// IO优化状态
    io_optimized: Option<String>,

    // ---- Phase 2: Operation tracking ----
    /// 最近操作
    latest_operation: Option<String>,
    /// 最近操作状态
    latest_operation_state: Option<String>,

    // ---- Phase 3: Additional metadata ----
    /// 标签
    tags: std::collections::HashMap<String, String>,
    /// 项目ID
    project_id: Option<String>,
    /// 资源组ID
    resource_group_id: Option<String>,
    /// 自动续费标识
    auto_renew_flag: Option<String>,

    // ---- Latest metrics ----
    /// CPU 使用率（%）
    cpu_usage: Option<MetricLatestValue>,
    /// 内存使用率（%）
    memory_usage: Option<MetricLatestValue>,
    /// 磁盘使用率（%）
    disk_usage: Option<MetricLatestValue>,
    /// 入站网络流量（bytes/s）
    network_in_bytes: Option<MetricLatestValue>,
    /// 出站网络流量（bytes/s）
    network_out_bytes: Option<MetricLatestValue>,
    /// 磁盘读 IOPS
    disk_iops_read: Option<MetricLatestValue>,
    /// 磁盘写 IOPS
    disk_iops_write: Option<MetricLatestValue>,
    /// TCP 连接数
    connections: Option<MetricLatestValue>,

    // ---- Timestamps ----
    /// 最近一次被调度器发现的时间
    last_seen_at: String,
    /// 最近一次指标采集时间（来自指标数据）
    last_collected_at: Option<String>,
    /// 实例首次入库时间
    created_at: String,
    /// 实例信息最后更新时间
    updated_at: String,
}

/// 测试连接响应
#[derive(Serialize, ToSchema)]
struct TestConnectionResponse {
    success: bool,
    message: String,
    instance_count: Option<usize>,
}

/// 触发采集响应
#[derive(Serialize, ToSchema)]
struct TriggerCollectionResponse {
    success: bool,
    message: String,
    collected_count: Option<usize>,
}

fn row_to_cloud_account_config(row: &CloudAccountRow) -> CloudAccountConfig {
    CloudAccountConfig {
        secret_id: row.secret_id.clone(),
        secret_key: row.secret_key.clone(),
        regions: row.regions.clone(),
        collection_interval_secs: row.collection_interval_secs as u64,
        concurrency: 5,
        instance_filter: Default::default(),
    }
}

fn row_to_cloud_account_response(_state: &AppState, row: CloudAccountRow) -> CloudAccountResponse {
    CloudAccountResponse {
        id: row.id,
        config_key: row.config_key,
        provider: row.provider,
        display_name: row.display_name,
        description: row.description,
        account_name: row.account_name,
        secret_id: row.secret_id,
        secret_key: row.secret_key,
        regions: row.regions,
        collection_interval_secs: row.collection_interval_secs,
        enabled: row.enabled,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }
}

fn cloud_instance_row_to_response(row: CloudInstanceRow) -> CloudInstanceResponse {
    // 反序列化安全组ID数组
    let security_group_ids = row
        .security_group_ids
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default();

    // 反序列化IPv6地址数组
    let ipv6_addresses = row
        .ipv6_addresses
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default();

    // 反序列化tags对象
    let tags = row
        .tags
        .and_then(|json| {
            serde_json::from_str::<std::collections::HashMap<String, String>>(&json).ok()
        })
        .unwrap_or_default();

    CloudInstanceResponse {
        id: row.id,
        instance_id: row.instance_id,
        instance_name: row.instance_name,
        provider: row.provider,
        account_config_key: row.account_config_key,
        region: row.region,
        public_ip: row.public_ip,
        private_ip: row.private_ip,
        os: row.os,
        normalized_status: normalize_cloud_instance_status(row.status.as_deref()).to_string(),
        status: row.status,
        last_seen_at: chrono::DateTime::from_timestamp(row.last_seen_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
        created_at: chrono::DateTime::from_timestamp(row.created_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
        updated_at: chrono::DateTime::from_timestamp(row.updated_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
        // Hardware specifications
        instance_type: row.instance_type,
        cpu_cores: row.cpu_cores,
        memory_gb: row.memory_gb,
        disk_gb: row.disk_gb,
        // Phase 1 fields
        created_time: row.created_time,
        expired_time: row.expired_time,
        charge_type: row.charge_type,
        vpc_id: row.vpc_id,
        subnet_id: row.subnet_id,
        security_group_ids,
        zone: row.zone,
        // Phase 2 & 3 fields
        internet_max_bandwidth: row.internet_max_bandwidth,
        ipv6_addresses,
        eip_allocation_id: row.eip_allocation_id,
        internet_charge_type: row.internet_charge_type,
        image_id: row.image_id,
        hostname: row.hostname,
        description: row.description,
        gpu: row.gpu,
        io_optimized: row.io_optimized,
        latest_operation: row.latest_operation,
        latest_operation_state: row.latest_operation_state,
        tags,
        project_id: row.project_id,
        resource_group_id: row.resource_group_id,
        auto_renew_flag: row.auto_renew_flag,
    }
}

fn normalize_cloud_instance_status(status: Option<&str>) -> &'static str {
    let normalized = status.unwrap_or_default().trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "unknown" | "unk" | "none" | "null" | "nil" | "-" => "unknown",
        "running" | "active" | "online" | "started" | "up" | "1" => "running",
        "stopped" | "stop" | "offline" | "terminated" | "shutdown" | "shutoff" | "down" | "0" => {
            "stopped"
        }
        "pending" | "starting" | "stopping" | "provisioning" | "initializing" | "booting"
        | "creating" | "rebooting" | "restarting" | "resetting" | "reinstalling" | "migrating"
        | "2" => "pending",
        "failed" | "error" | "err" | "unhealthy" | "launch_failed" | "create_failed"
        | "start_failed" | "stop_failed" | "reboot_failed" | "3" => "error",
        _ => "unknown",
    }
}

/// 云账户列表查询参数
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListCloudAccountParams {
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
    /// 按供应商过滤（tencent 或 alibaba）
    #[param(required = false)]
    provider: Option<String>,
    /// 按启用状态过滤
    #[param(required = false)]
    enabled: Option<bool>,
}

/// 列出所有云账户
#[utoipa::path(
    get,
    path = "/v1/cloud/accounts",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(ListCloudAccountParams),
    responses(
        (status = 200, description = "云账户列表", body = Vec<CloudAccountResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_cloud_accounts(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListCloudAccountParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    let total = match state
        .cert_store
        .count_cloud_accounts(params.provider.as_deref(), params.enabled)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count cloud accounts");
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
        .list_cloud_accounts(params.provider.as_deref(), params.enabled, limit, offset)
        .await
    {
        Ok(rows) => {
            let resp: Vec<CloudAccountResponse> = rows
                .into_iter()
                .map(|row| row_to_cloud_account_response(&state, row))
                .collect();
            success_paginated_response(StatusCode::OK, &trace_id, resp, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list cloud accounts");
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

/// 创建云账户
#[utoipa::path(
    post,
    path = "/v1/cloud/accounts",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    request_body = CreateCloudAccountRequest,
    responses(
        (status = 201, description = "云账户已创建", body = CloudAccountResponse),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 409, description = "配置键已存在", body = crate::api::ApiError)
    )
)]
async fn create_cloud_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<CreateCloudAccountRequest>,
) -> impl IntoResponse {
    // Validate provider
    if req.provider != "tencent" && req.provider != "alibaba" {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_provider",
            "Provider must be 'tencent' or 'alibaba'",
        )
        .into_response();
    }

    // Validate config_key format
    if !req.config_key.starts_with("cloud_") {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_config_key",
            "config_key must start with 'cloud_'",
        )
        .into_response();
    }

    let now = chrono::Utc::now();
    let collection_interval = req.collection_interval_secs.unwrap_or(
        state
            .config
            .cloud_check
            .default_account_collection_interval_secs as i64,
    );

    let row = CloudAccountRow {
        id: oxmon_common::id::next_id(),
        config_key: req.config_key,
        provider: req.provider,
        display_name: req.display_name,
        description: req.description,
        account_name: req.account_name,
        secret_id: req.secret_id,
        secret_key: req.secret_key,
        regions: req.regions,
        collection_interval_secs: collection_interval,
        enabled: true,
        created_at: now,
        updated_at: now,
    };

    match state.cert_store.insert_cloud_account(&row).await {
        Ok(row) => {
            let resp = row_to_cloud_account_response(&state, row);
            success_response(StatusCode::CREATED, &trace_id, resp)
        }
        Err(e) => {
            let err_msg = e.to_string();
            if err_msg.contains("UNIQUE constraint failed") {
                error_response(
                    StatusCode::CONFLICT,
                    &trace_id,
                    "duplicate_config_key",
                    "Cloud account with this config_key already exists",
                )
                .into_response()
            } else {
                tracing::error!(error = %e, "Failed to create cloud account");
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

/// 获取单个云账户
#[utoipa::path(
    get,
    path = "/v1/cloud/accounts/{id}",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    responses(
        (status = 200, description = "云账户详情", body = CloudAccountResponse),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn get_cloud_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.get_cloud_account_by_id(&id).await {
        Ok(row) => {
            let resp = row_to_cloud_account_response(&state, row);
            success_response(StatusCode::OK, &trace_id, resp)
        }
        Err(e) => {
            let err_msg = e.to_string();
            if err_msg.contains("no rows") || err_msg.contains("NOT FOUND") {
                error_response(
                    StatusCode::NOT_FOUND,
                    &trace_id,
                    "not_found",
                    "Cloud account not found",
                )
                .into_response()
            } else {
                tracing::error!(error = %e, "Failed to get cloud account");
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

/// 更新云账户
#[utoipa::path(
    put,
    path = "/v1/cloud/accounts/{id}",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    request_body = UpdateCloudAccountRequest,
    responses(
        (status = 200, description = "云账户已更新", body = CloudAccountResponse),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn update_cloud_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateCloudAccountRequest>,
) -> impl IntoResponse {
    // Get existing account
    let existing = match state.cert_store.get_cloud_account_by_id(&id).await {
        Ok(row) => row,
        Err(e) => {
            let err_msg = e.to_string();
            if err_msg.contains("no rows") || err_msg.contains("NOT FOUND") {
                return error_response(
                    StatusCode::NOT_FOUND,
                    &trace_id,
                    "not_found",
                    "Cloud account not found",
                )
                .into_response();
            } else {
                tracing::error!(error = %e, "Failed to get cloud account");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &trace_id,
                    "storage_error",
                    "Database error",
                )
                .into_response();
            }
        }
    };

    // Build updated row
    let description = match req.description {
        Some(Some(d)) => Some(d),
        Some(None) => None,
        None => existing.description,
    };

    let updated = CloudAccountRow {
        id: existing.id,
        config_key: existing.config_key,
        provider: existing.provider,
        display_name: req.display_name.unwrap_or(existing.display_name),
        description,
        account_name: req.account_name.unwrap_or(existing.account_name),
        secret_id: req.secret_id.unwrap_or(existing.secret_id),
        secret_key: req.secret_key.unwrap_or(existing.secret_key),
        regions: req.regions.unwrap_or(existing.regions),
        collection_interval_secs: req
            .collection_interval_secs
            .unwrap_or(existing.collection_interval_secs),
        enabled: req.enabled.unwrap_or(existing.enabled),
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    match state.cert_store.update_cloud_account(&id, &updated).await {
        Ok(row) => {
            let resp = row_to_cloud_account_response(&state, row);
            success_response(StatusCode::OK, &trace_id, resp)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to update cloud account");
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

/// 删除云账户
#[utoipa::path(
    delete,
    path = "/v1/cloud/accounts/{id}",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    responses(
        (status = 204, description = "云账户已删除"),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn delete_cloud_account(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.cert_store.delete_cloud_account(&id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error_response(
            StatusCode::NOT_FOUND,
            &trace_id,
            "not_found",
            "Cloud account not found",
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete cloud account");
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

/// 测试云账户连接
#[utoipa::path(
    post,
    path = "/v1/cloud/accounts/{id}/test",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    responses(
        (status = 200, description = "连接测试结果", body = TestConnectionResponse),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn test_cloud_account_connection(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let row = match state.cert_store.get_cloud_account_by_id(&id).await {
        Ok(row) => row,
        Err(e) => {
            let err_msg = e.to_string();
            if err_msg.contains("no rows") || err_msg.contains("NOT FOUND") || err_msg.contains("not found") {
                return error_response(
                    StatusCode::NOT_FOUND,
                    &trace_id,
                    "not_found",
                    "Cloud account not found",
                )
                .into_response();
            }
            tracing::error!(error = %e, "Failed to get cloud account");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    let account_config = row_to_cloud_account_config(&row);
    let provider_type = &row.provider;
    let account_name = &row.account_name;

    match build_provider(provider_type, account_name, account_config) {
        Ok(provider) => match provider.list_instances().await {
            Ok(instances) => {
                let resp = TestConnectionResponse {
                    success: true,
                    message: format!("Successfully connected to {} cloud", provider_type),
                    instance_count: Some(instances.len()),
                };
                success_response(StatusCode::OK, &trace_id, resp)
            }
            Err(e) => {
                let resp = TestConnectionResponse {
                    success: false,
                    message: format!("Failed to list instances: {}", e),
                    instance_count: None,
                };
                success_response(StatusCode::OK, &trace_id, resp)
            }
        },
        Err(e) => {
            let resp = TestConnectionResponse {
                success: false,
                message: format!("Failed to build provider: {}", e),
                instance_count: None,
            };
            success_response(StatusCode::OK, &trace_id, resp)
        }
    }
}

/// 手动触发云账户采集
#[utoipa::path(
    post,
    path = "/v1/cloud/accounts/{id}/collect",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云账户ID")
    ),
    responses(
        (status = 200, description = "采集任务已触发", body = TriggerCollectionResponse),
        (status = 404, description = "云账户不存在", body = crate::api::ApiError)
    )
)]
async fn trigger_cloud_account_collection(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let row = match state.cert_store.get_cloud_account_by_id(&id).await {
        Ok(row) => row,
        Err(e) => {
            let err_msg = e.to_string();
            if err_msg.contains("no rows") || err_msg.contains("NOT FOUND") || err_msg.contains("not found") {
                return error_response(
                    StatusCode::NOT_FOUND,
                    &trace_id,
                    "not_found",
                    "Cloud account not found",
                )
                .into_response();
            }
            tracing::error!(error = %e, "Failed to get cloud account");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    let account_config = row_to_cloud_account_config(&row);
    let provider_type = row.provider.clone();
    let account_name = row.account_name.clone();

    // Build provider and collect metrics
    match build_provider(&provider_type, &account_name, account_config) {
        Ok(provider) => {
            // First, list instances to get hardware specs
            let instances = match provider.list_instances().await {
                Ok(inst) => inst,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to list instances");
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &trace_id,
                        "provider_error",
                        "Failed to list instances",
                    )
                    .into_response();
                }
            };

            // Use CloudCollector to gather metrics
            let collector = oxmon_cloud::collector::CloudCollector::new(
                vec![std::sync::Arc::from(provider)],
                5,
            );

            match collector.collect_all().await {
                Ok(mut metrics) => {
                    // Enrich metrics with hardware specs from instances
                    for metric in &mut metrics {
                        if let Some(instance) = instances
                            .iter()
                            .find(|i| i.instance_id == metric.instance_id)
                        {
                            metric.instance_type = instance.instance_type.clone();
                            metric.cpu_cores = instance.cpu_cores;
                            metric.memory_gb = instance.memory_gb;
                            metric.disk_gb = instance.disk_gb;
                        }
                    }
                    // Convert to MetricDataPoint and write to storage
                    let now = chrono::Utc::now();
                    let mut data_points = Vec::new();

                    for m in &metrics {
                        let agent_id = format!("cloud:{}:{}", m.provider, m.instance_id);
                        let mut labels = std::collections::HashMap::new();
                        labels.insert("provider".to_string(), m.provider.clone());
                        labels.insert("region".to_string(), m.region.clone());
                        labels.insert("instance_name".to_string(), m.instance_name.clone());

                        // Add hardware specifications as labels
                        if !m.instance_type.is_empty() {
                            labels.insert("instance_type".to_string(), m.instance_type.clone());
                        }
                        if let Some(cpu_cores) = m.cpu_cores {
                            labels.insert("cpu_cores".to_string(), cpu_cores.to_string());
                        }
                        if let Some(memory_gb) = m.memory_gb {
                            labels.insert("memory_gb".to_string(), format!("{:.1}", memory_gb));
                        }
                        if let Some(disk_gb) = m.disk_gb {
                            labels.insert("disk_gb".to_string(), format!("{:.1}", disk_gb));
                        }

                        if let Some(cpu) = m.cpu_usage {
                            data_points.push(oxmon_common::types::MetricDataPoint {
                                id: oxmon_common::id::next_id(),
                                timestamp: m.collected_at,
                                agent_id: agent_id.clone(),
                                metric_name: "cloud.cpu.usage".to_string(),
                                value: cpu,
                                labels: labels.clone(),
                                created_at: now,
                                updated_at: now,
                            });
                        }

                        if let Some(memory) = m.memory_usage {
                            data_points.push(oxmon_common::types::MetricDataPoint {
                                id: oxmon_common::id::next_id(),
                                timestamp: m.collected_at,
                                agent_id: agent_id.clone(),
                                metric_name: "cloud.memory.usage".to_string(),
                                value: memory,
                                labels: labels.clone(),
                                created_at: now,
                                updated_at: now,
                            });
                        }

                        if let Some(disk) = m.disk_usage {
                            data_points.push(oxmon_common::types::MetricDataPoint {
                                id: oxmon_common::id::next_id(),
                                timestamp: m.collected_at,
                                agent_id: agent_id.clone(),
                                metric_name: "cloud.disk.usage".to_string(),
                                value: disk,
                                labels,
                                created_at: now,
                                updated_at: now,
                            });
                        }
                    }

                    if !data_points.is_empty() {
                        let batch = oxmon_common::types::MetricBatch {
                            agent_id: "manual-collection".to_string(),
                            timestamp: now,
                            data_points,
                        };

                        if let Err(e) = state.storage.write_batch(&batch) {
                            tracing::error!(error = %e, "Failed to write cloud metrics batch");
                            return error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &trace_id,
                                "storage_error",
                                "Failed to write metrics",
                            )
                            .into_response();
                        }
                    }

                    let resp = TriggerCollectionResponse {
                        success: true,
                        message: format!(
                            "Successfully collected metrics from {} instances",
                            metrics.len()
                        ),
                        collected_count: Some(metrics.len()),
                    };
                    success_response(StatusCode::OK, &trace_id, resp)
                }
                Err(e) => {
                    let resp = TriggerCollectionResponse {
                        success: false,
                        message: format!("Failed to collect metrics: {}", e),
                        collected_count: None,
                    };
                    success_response(StatusCode::OK, &trace_id, resp)
                }
            }
        }
        Err(e) => {
            let resp = TriggerCollectionResponse {
                success: false,
                message: format!("Failed to build provider: {}", e),
                collected_count: None,
            };
            success_response(StatusCode::OK, &trace_id, resp)
        }
    }
}

/// 云实例列表查询参数
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct ListCloudInstancesParams {
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
    /// 按供应商过滤
    #[param(required = false)]
    provider: Option<String>,
    /// 按区域过滤
    #[param(required = false)]
    region: Option<String>,
    /// 按归一化状态过滤（running/pending/stopped/error/unknown）
    #[param(required = false)]
    status: Option<String>,
    /// 关键字搜索（实例ID/名称/IP/区域等）
    #[param(required = false)]
    search: Option<String>,
}

/// 列出所有云实例
#[utoipa::path(
    get,
    path = "/v1/cloud/instances",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(ListCloudInstancesParams),
    responses(
        (status = 200, description = "云实例列表", body = Vec<CloudInstanceResponse>),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn list_cloud_instances(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<ListCloudInstancesParams>,
) -> impl IntoResponse {
    let limit = PaginationParams::resolve_limit(params.limit);
    let offset = PaginationParams::resolve_offset(params.offset);

    let total = match state
        .cert_store
        .count_cloud_instances(
            params.provider.as_deref(),
            params.region.as_deref(),
            params.status.as_deref(),
            params.search.as_deref(),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to count cloud instances");
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
        .list_cloud_instances(
            params.provider.as_deref(),
            params.region.as_deref(),
            params.status.as_deref(),
            params.search.as_deref(),
            limit,
            offset,
        )
        .await
    {
        Ok(rows) => {
            let resp: Vec<CloudInstanceResponse> = rows
                .into_iter()
                .map(cloud_instance_row_to_response)
                .collect();
            success_paginated_response(StatusCode::OK, &trace_id, resp, total, limit, offset)
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list cloud instances");
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

/// Cloud metric names to query for instance detail
const CLOUD_METRIC_NAMES: &[&str] = &[
    "cloud.cpu.usage",
    "cloud.memory.usage",
    "cloud.disk.usage",
    "cloud.network.in_bytes",
    "cloud.network.out_bytes",
    "cloud.disk.iops_read",
    "cloud.disk.iops_write",
    "cloud.connections",
];

/// 获取云实例详情（含最新指标数据）
#[utoipa::path(
    get,
    path = "/v1/cloud/instances/{id}",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云实例系统雪花ID（cloud_instances 表主键，例如 1234567890123456789）")
    ),
    responses(
        (status = 200, description = "云实例详情（含最新指标）", body = CloudInstanceDetailResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "实例不存在", body = crate::api::ApiError)
    )
)]
async fn get_cloud_instance_detail(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // 1. Load instance metadata from cloud_instances table
    let instance = match state.cert_store.get_cloud_instance_by_id(&id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Cloud instance not found",
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get cloud instance");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    // 2. Construct the virtual agent_id used in metrics storage
    //    Format: cloud:{provider}:{instance_id}
    let agent_id = format!("cloud:{}:{}", instance.provider, instance.instance_id);

    // 3. Query latest metric values (lookback 2 days to cover partition boundaries)
    let metrics = match state.storage.query_latest_metrics_for_agent(
        &agent_id,
        CLOUD_METRIC_NAMES,
        2,
    ) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, agent_id = %agent_id, "Failed to query latest cloud metrics, returning instance info without metrics");
            vec![]
        }
    };

    // 4. Build a lookup map: metric_name -> MetricDataPoint
    let metrics_map: std::collections::HashMap<String, _> = metrics
        .into_iter()
        .map(|dp| (dp.metric_name.clone(), dp))
        .collect();

    // Helper closure to extract a metric latest value
    let extract_metric = |name: &str| -> Option<MetricLatestValue> {
        metrics_map.get(name).map(|dp| MetricLatestValue {
            metric_name: name.to_string(),
            value: dp.value,
            collected_at: dp.timestamp.to_rfc3339(),
        })
    };

    // 5. Determine the last_collected_at from the most recent metric timestamp
    let last_collected_at = metrics_map
        .values()
        .map(|dp| dp.timestamp)
        .max()
        .map(|t| t.to_rfc3339());

    // 6. Assemble the response
    // 反序列化安全组ID数组
    let security_group_ids = instance
        .security_group_ids
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default();

    // 反序列化IPv6地址数组
    let ipv6_addresses = instance
        .ipv6_addresses
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default();

    // 反序列化tags对象
    let tags = instance
        .tags
        .and_then(|json| {
            serde_json::from_str::<std::collections::HashMap<String, String>>(&json).ok()
        })
        .unwrap_or_default();

    let resp = CloudInstanceDetailResponse {
        id: instance.id,
        instance_id: instance.instance_id,
        instance_name: instance.instance_name,
        provider: instance.provider,
        account_config_key: instance.account_config_key,
        region: instance.region,
        public_ip: instance.public_ip,
        private_ip: instance.private_ip,
        os: instance.os,
        normalized_status: normalize_cloud_instance_status(instance.status.as_deref()).to_string(),
        status: instance.status,
        instance_type: instance.instance_type,
        cpu_cores: instance.cpu_cores,
        memory_gb: instance.memory_gb,
        disk_gb: instance.disk_gb,
        // Phase 1 fields
        created_time: instance.created_time,
        expired_time: instance.expired_time,
        charge_type: instance.charge_type,
        vpc_id: instance.vpc_id,
        subnet_id: instance.subnet_id,
        security_group_ids,
        zone: instance.zone,
        // Phase 2 & 3 fields
        internet_max_bandwidth: instance.internet_max_bandwidth,
        ipv6_addresses,
        eip_allocation_id: instance.eip_allocation_id,
        internet_charge_type: instance.internet_charge_type,
        image_id: instance.image_id,
        hostname: instance.hostname,
        description: instance.description,
        gpu: instance.gpu,
        io_optimized: instance.io_optimized,
        latest_operation: instance.latest_operation,
        latest_operation_state: instance.latest_operation_state,
        tags,
        project_id: instance.project_id,
        resource_group_id: instance.resource_group_id,
        auto_renew_flag: instance.auto_renew_flag,
        // Metrics
        cpu_usage: extract_metric("cloud.cpu.usage"),
        memory_usage: extract_metric("cloud.memory.usage"),
        disk_usage: extract_metric("cloud.disk.usage"),
        network_in_bytes: extract_metric("cloud.network.in_bytes"),
        network_out_bytes: extract_metric("cloud.network.out_bytes"),
        disk_iops_read: extract_metric("cloud.disk.iops_read"),
        disk_iops_write: extract_metric("cloud.disk.iops_write"),
        connections: extract_metric("cloud.connections"),
        last_seen_at: chrono::DateTime::from_timestamp(instance.last_seen_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
        last_collected_at,
        created_at: chrono::DateTime::from_timestamp(instance.created_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
        updated_at: chrono::DateTime::from_timestamp(instance.updated_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
    };

    success_response(StatusCode::OK, &trace_id, resp)
}

/// 批量导入云账户响应
#[derive(Serialize, ToSchema)]
struct BatchCreateCloudAccountsResponse {
    /// 成功创建数量
    created: usize,
    /// 跳过（config_key 已存在）数量
    skipped: usize,
    /// 错误列表（格式: "行N: 原因"）
    errors: Vec<String>,
}

/// 批量导入云账户请求
///
/// 文本格式每行一条，字段用 `:` 分隔，区域用 `,` 分隔：
/// `账号名:SecretId:SecretKey:region1,region2`
///
/// 多条记录用 `|` 分隔，例如：
/// `主账号:AKID123:secret:ap-shanghai,ap-guangzhou|子账号:AKID456:secret2:ap-beijing`
#[derive(Deserialize, ToSchema)]
struct BatchCreateCloudAccountsRequest {
    /// 供应商（tencent 或 alibaba）
    provider: String,
    /// 批量文本，格式：账号名:SecretId:SecretKey:region1,region2|...
    text: String,
    /// 采集间隔（秒，默认 3600）
    collection_interval_secs: Option<i64>,
}

/// 批量导入云账户
#[utoipa::path(
    post,
    path = "/v1/cloud/accounts/batch",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    request_body = BatchCreateCloudAccountsRequest,
    responses(
        (status = 200, description = "批量导入结果", body = BatchCreateCloudAccountsResponse),
        (status = 400, description = "请求参数错误", body = crate::api::ApiError),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn batch_create_cloud_accounts(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Json(req): Json<BatchCreateCloudAccountsRequest>,
) -> impl IntoResponse {
    if req.provider != "tencent" && req.provider != "alibaba" {
        return error_response(
            StatusCode::BAD_REQUEST,
            &trace_id,
            "invalid_provider",
            "Provider must be 'tencent' or 'alibaba'",
        )
        .into_response();
    }

    let collection_interval = req.collection_interval_secs.unwrap_or(
        state
            .config
            .cloud_check
            .default_account_collection_interval_secs as i64,
    );

    let mut created = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for (line_idx, entry) in req.text.split('|').enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let parts: Vec<&str> = entry.splitn(4, ':').collect();
        if parts.len() != 4 {
            errors.push(format!(
                "条目{}: 格式错误，期望 账号名:SecretId:SecretKey:region1,region2",
                line_idx + 1
            ));
            continue;
        }
        let account_name = parts[0].trim();
        let secret_id = parts[1].trim();
        let secret_key = parts[2].trim();
        let regions: Vec<String> = parts[3]
            .split(',')
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();

        if account_name.is_empty() || secret_id.is_empty() || secret_key.is_empty() {
            errors.push(format!("条目{}: 账号名、SecretId 或 SecretKey 不能为空", line_idx + 1));
            continue;
        }
        if regions.is_empty() {
            errors.push(format!("条目{}: 至少需要一个地域", line_idx + 1));
            continue;
        }

        let config_key = format!("cloud_{}_{}", req.provider, account_name.replace(' ', "_"));
        let now = chrono::Utc::now();
        let row = oxmon_storage::CloudAccountRow {
            id: oxmon_common::id::next_id(),
            config_key,
            provider: req.provider.clone(),
            display_name: account_name.to_string(),
            description: None,
            account_name: account_name.to_string(),
            secret_id: secret_id.to_string(),
            secret_key: secret_key.to_string(),
            regions,
            collection_interval_secs: collection_interval,
            enabled: true,
            created_at: now,
            updated_at: now,
        };

        match state.cert_store.insert_cloud_account(&row).await {
            Ok(_) => created += 1,
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("UNIQUE constraint failed") {
                    skipped += 1;
                } else {
                    errors.push(format!("条目{} ({}): {}", line_idx + 1, account_name, err_msg));
                }
            }
        }
    }

    let resp = BatchCreateCloudAccountsResponse { created, skipped, errors };
    success_response(StatusCode::OK, &trace_id, resp)
}

// ─── 解析指标简名 → 完整指标名 ────────────────────────────────────────────────

fn parse_metric_names(metrics_param: Option<&str>) -> Vec<String> {
    match metrics_param {
        None | Some("") => vec![
            "cloud.cpu.usage".to_string(),
            "cloud.memory.usage".to_string(),
            "cloud.disk.usage".to_string(),
        ],
        Some(s) => s
            .split(',')
            .map(|m| match m.trim() {
                "cpu" => "cloud.cpu.usage",
                "memory" | "mem" => "cloud.memory.usage",
                "disk" => "cloud.disk.usage",
                "network_in" => "cloud.network.in_bytes",
                "network_out" => "cloud.network.out_bytes",
                "iops_read" | "disk_read" => "cloud.disk.iops_read",
                "iops_write" | "disk_write" => "cloud.disk.iops_write",
                "connections" | "conns" => "cloud.connections",
                other => other,
            })
            .map(|s| s.to_string())
            .collect(),
    }
}

// ─── 云实例历史指标（时间序列）─────────────────────────────────────────────────

/// 时间序列单个数据点
#[derive(Serialize, ToSchema)]
#[schema(example = json!({"t": 1740787200, "v": 45.2}))]
struct MetricPoint {
    /// Unix 时间戳（秒）
    #[schema(example = 1740787200_i64)]
    t: i64,
    /// 指标值（百分比 0‒100，或字节/IOPS 等原始数值，取决于指标类型）
    #[schema(example = 45.2)]
    v: f64,
}

/// 云实例历史指标响应
#[derive(Serialize, ToSchema)]
struct CloudInstanceMetricsResponse {
    /// 云厂商实例 ID（如 ins-abc123 / i-abc123456）
    #[schema(example = "ins-abc123")]
    instance_id: String,
    /// 实例显示名称
    #[schema(example = "web-server-01")]
    instance_name: Option<String>,
    /// 时间序列数据，key 为完整指标名，value 为按时间升序排列的数据点数组。
    ///
    /// 常用 key：
    /// - `cloud.cpu.usage` — CPU 使用率（%）
    /// - `cloud.memory.usage` — 内存使用率（%）
    /// - `cloud.disk.usage` — 磁盘使用率（%）
    /// - `cloud.network.in_bytes` — 入流量（字节/秒）
    /// - `cloud.network.out_bytes` — 出流量（字节/秒）
    /// - `cloud.disk.iops_read` — 磁盘读 IOPS
    /// - `cloud.disk.iops_write` — 磁盘写 IOPS
    /// - `cloud.connections` — TCP 连接数
    #[schema(
        value_type = Object,
        example = json!({
            "cloud.cpu.usage":    [{"t": 1740787200, "v": 32.5}, {"t": 1740790800, "v": 45.1}],
            "cloud.memory.usage": [{"t": 1740787200, "v": 67.8}, {"t": 1740790800, "v": 68.3}],
            "cloud.disk.usage":   [{"t": 1740787200, "v": 55.0}, {"t": 1740790800, "v": 55.2}]
        })
    )]
    series: std::collections::HashMap<String, Vec<MetricPoint>>,
}

/// 历史指标查询参数
#[derive(Deserialize, utoipa::IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
struct CloudInstanceMetricsParams {
    /// 查询开始时间（RFC3339/ISO8601）。
    /// 默认为今天 00:00:00 UTC；最早不超过当前时间往前 7 天（与数据保留期一致）。
    #[param(example = "2025-03-01T00:00:00Z")]
    from: Option<String>,
    /// 查询结束时间（RFC3339/ISO8601）。
    /// 默认为当前时间。
    #[param(example = "2025-03-01T23:59:59Z")]
    to: Option<String>,
    /// 要返回的指标，逗号分隔。
    /// 支持简名（`cpu` / `memory` / `disk` / `network_in` / `network_out` / `iops_read` / `iops_write` / `connections`）
    /// 或完整指标名（`cloud.cpu.usage` 等）。
    /// 默认值：`cpu,memory,disk`
    #[param(example = "cpu,memory,disk")]
    metrics: Option<String>,
}

/// 获取云实例历史指标时间序列（用于折线图等可视化）
#[utoipa::path(
    get,
    path = "/v1/cloud/instances/{id}/metrics",
    operation_id = "getCloudInstanceMetrics",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(
        ("id" = String, Path, description = "云实例系统雪花ID（cloud_instances 表主键，例如 1234567890123456789）"),
        CloudInstanceMetricsParams,
    ),
    responses(
        (status = 200, description = "历史指标时间序列，series 中每个 key 对应一条折线", body = CloudInstanceMetricsResponse),
        (status = 401, description = "未认证", body = crate::api::ApiError),
        (status = 404, description = "实例不存在", body = crate::api::ApiError)
    )
)]
async fn cloud_instance_metrics(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<CloudInstanceMetricsParams>,
) -> impl IntoResponse {
    // 1. 加载实例元数据
    let instance = match state.cert_store.get_cloud_instance_by_id(&id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                &trace_id,
                "not_found",
                "Cloud instance not found",
            )
            .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to get cloud instance");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    // 2. 解析时间范围（默认今天 00:00 UTC 到现在，最长 7 天）
    let now = chrono::Utc::now();
    let max_retention = chrono::Duration::days(7);

    let to_time = params
        .to
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or(now);

    let from_time = params
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| {
            // 默认今天 00:00 UTC
            now.date_naive()
                .and_hms_opt(0, 0, 0)
                .and_then(|ndt| ndt.and_local_timezone(chrono::Utc).single())
                .unwrap_or(now - chrono::Duration::hours(24))
        });

    // 强制不超过 7 天
    let from_time = from_time.max(to_time - max_retention);

    // 3. 确定要查询的指标列表
    let metric_names = parse_metric_names(params.metrics.as_deref());

    // 4. 逐指标查询时间序列
    let agent_id = format!("cloud:{}:{}", instance.provider, instance.instance_id);
    let mut series: std::collections::HashMap<String, Vec<MetricPoint>> =
        std::collections::HashMap::new();

    for metric_name in &metric_names {
        let pts = match state.storage.query(&MetricQuery {
            agent_id: agent_id.clone(),
            metric_name: metric_name.clone(),
            from: from_time,
            to: to_time,
        }) {
            Ok(dps) => dps
                .into_iter()
                .map(|dp| MetricPoint {
                    t: dp.timestamp.timestamp(),
                    v: dp.value,
                })
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, metric = %metric_name, agent_id = %agent_id, "Failed to query metric series");
                vec![]
            }
        };
        series.insert(metric_name.clone(), pts);
    }

    let resp = CloudInstanceMetricsResponse {
        instance_id: instance.instance_id,
        instance_name: instance.instance_name,
        series,
    };
    success_response(StatusCode::OK, &trace_id, resp)
}

// ─── 所有实例指标图表（并行数组格式）────────────────────────────────────────────

/// 图表中单个实例的元信息（与 labels / series 数组下标一一对应）
#[derive(Serialize, ToSchema)]
struct CloudInstanceChartMeta {
    /// 系统雪花ID（cloud_instances 表主键）
    #[schema(example = "1234567890123456789")]
    id: String,
    /// 云厂商实例 ID（如 ins-abc123 / i-abc123456）
    #[schema(example = "ins-abc123")]
    instance_id: String,
    /// 实例显示名称
    #[schema(example = "web-server-01")]
    instance_name: Option<String>,
    /// 云供应商（tencent / alibaba）
    #[schema(example = "tencent")]
    provider: String,
    /// 地域
    #[schema(example = "ap-shanghai")]
    region: String,
    /// 云厂商原始状态（如 RUNNING / Stopped）
    #[schema(example = "RUNNING")]
    status: Option<String>,
    /// 归一化状态（running / stopped / pending / error / unknown）
    #[schema(example = "running")]
    normalized_status: String,
}

/// 所有实例最新指标图表响应
///
/// 采用并行数组格式，`labels[i]`、`instances[i]`、`series[metric][i]` 三者下标对应同一台实例，
/// 可直接传入 ECharts / Chart.js 等图表库使用。
#[derive(Serialize, ToSchema)]
struct CloudInstancesChartResponse {
    /// X 轴标签列表，优先使用实例名，无名称时使用实例 ID
    #[schema(example = json!(["web-server-01", "db-primary", "cache-01"]))]
    labels: Vec<String>,
    /// 实例元信息列表，与 labels 下标一一对应
    instances: Vec<CloudInstanceChartMeta>,
    /// 各指标 Y 轴数据：完整指标名 → 各实例最新值数组。
    ///
    /// - 数组长度与 `labels` 相同
    /// - `null` 表示该实例在最近 2 天内没有该指标数据
    /// - 常用 key：`cloud.cpu.usage` / `cloud.memory.usage` / `cloud.disk.usage`
    #[schema(
        value_type = Object,
        example = json!({
            "cloud.cpu.usage":    [45.2, 67.8, 12.3],
            "cloud.memory.usage": [67.8, 82.1, 55.3],
            "cloud.disk.usage":   [32.1, 45.6, 28.7]
        })
    )]
    series: std::collections::HashMap<String, Vec<Option<f64>>>,
}

/// 图表查询过滤参数
#[derive(Deserialize, utoipa::IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
struct CloudInstancesChartParams {
    /// 按云供应商过滤（tencent / alibaba）
    #[param(example = "tencent")]
    provider: Option<String>,
    /// 按地域过滤（如 ap-shanghai）
    #[param(example = "ap-shanghai")]
    region: Option<String>,
    /// 按归一化状态过滤（running / stopped / pending / error / unknown）
    #[param(example = "running")]
    status: Option<String>,
    /// 要返回的指标，逗号分隔，支持简名（`cpu` / `memory` / `disk`）或完整名。
    /// 默认值：`cpu,memory,disk`
    #[param(example = "cpu,memory,disk")]
    metrics: Option<String>,
}

/// 获取所有云实例最新指标图表数据（X 轴 = 实例，Y 轴 = 指标值）
///
/// 返回并行数组格式，适合直接传入 ECharts / Chart.js 等图表库渲染柱状图或雷达图。
/// 每个实例取最近 2 天内的最新一条数据点。
#[utoipa::path(
    get,
    path = "/v1/cloud/instances/chart",
    operation_id = "getCloudInstancesChart",
    tag = "Cloud",
    security(("bearer_auth" = [])),
    params(CloudInstancesChartParams),
    responses(
        (
            status = 200,
            description = "所有实例最新指标并行数组（labels / instances / series 下标对应同一实例）",
            body = CloudInstancesChartResponse
        ),
        (status = 401, description = "未认证", body = crate::api::ApiError)
    )
)]
async fn cloud_instances_chart(
    Extension(trace_id): Extension<TraceId>,
    State(state): State<AppState>,
    Query(params): Query<CloudInstancesChartParams>,
) -> impl IntoResponse {
    // 1. 加载实例列表（最多 1000 条，按供应商/地域/状态过滤）
    let instances = match state
        .cert_store
        .list_cloud_instances(
            params.provider.as_deref(),
            params.region.as_deref(),
            params.status.as_deref(),
            None,
            1000,
            0,
        )
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list cloud instances for chart");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &trace_id,
                "storage_error",
                "Database error",
            )
            .into_response();
        }
    };

    // 2. 确定指标列表
    let metric_names = parse_metric_names(params.metrics.as_deref());
    // 查最近 2 天确保跨分区都能拿到
    let metric_names_refs: Vec<&str> = metric_names.iter().map(|s| s.as_str()).collect();

    // 3. 为每个实例查最新指标值，构建并行数组
    let mut labels: Vec<String> = Vec::with_capacity(instances.len());
    let mut chart_instances: Vec<CloudInstanceChartMeta> = Vec::with_capacity(instances.len());
    let mut series: std::collections::HashMap<String, Vec<Option<f64>>> = metric_names
        .iter()
        .map(|name| (name.clone(), Vec::with_capacity(instances.len())))
        .collect();

    for inst in &instances {
        // 标签：优先用实例名，否则用实例ID
        let label = inst
            .instance_name
            .as_deref()
            .filter(|n| !n.is_empty())
            .unwrap_or(&inst.instance_id)
            .to_string();
        labels.push(label);

        chart_instances.push(CloudInstanceChartMeta {
            id: inst.id.clone(),
            instance_id: inst.instance_id.clone(),
            instance_name: inst.instance_name.clone(),
            provider: inst.provider.clone(),
            region: inst.region.clone(),
            status: inst.status.clone(),
            normalized_status: normalize_cloud_instance_status(inst.status.as_deref())
                .to_string(),
        });

        // 查该实例最新指标
        let agent_id = format!("cloud:{}:{}", inst.provider, inst.instance_id);
        let latest = state
            .storage
            .query_latest_metrics_for_agent(&agent_id, &metric_names_refs, 2)
            .unwrap_or_default();

        let latest_map: std::collections::HashMap<&str, f64> = latest
            .iter()
            .map(|dp| (dp.metric_name.as_str(), dp.value))
            .collect();

        for name in &metric_names {
            let val = latest_map.get(name.as_str()).copied();
            if let Some(vec) = series.get_mut(name) {
                vec.push(val);
            }
        }
    }

    let resp = CloudInstancesChartResponse {
        labels,
        instances: chart_instances,
        series,
    };
    success_response(StatusCode::OK, &trace_id, resp)
}

/// 注册云API路由
pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_cloud_accounts))
        .routes(routes!(create_cloud_account))
        .routes(routes!(batch_create_cloud_accounts))
        .routes(routes!(get_cloud_account))
        .routes(routes!(update_cloud_account))
        .routes(routes!(delete_cloud_account))
        .routes(routes!(test_cloud_account_connection))
        .routes(routes!(trigger_cloud_account_collection))
        .routes(routes!(list_cloud_instances))
        .routes(routes!(cloud_instances_chart))
        .routes(routes!(get_cloud_instance_detail))
        .routes(routes!(cloud_instance_metrics))
}
