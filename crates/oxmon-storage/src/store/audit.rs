use anyhow::Result;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};

use crate::entities::audit_log::{self, Column as AuditCol, Entity as AuditEntity};
use crate::store::CertStore;

/// 审计日志数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRow {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub method: String,
    pub path: String,
    pub status_code: i32,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
    pub request_body: Option<String>,
    pub duration_ms: i64,
    pub created_at: String,
}

/// 审计日志过滤条件
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub user_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
}

fn model_to_row(m: audit_log::Model) -> AuditLogRow {
    AuditLogRow {
        id: m.id,
        user_id: m.user_id,
        username: m.username,
        action: m.action,
        resource_type: m.resource_type,
        resource_id: m.resource_id,
        method: m.method,
        path: m.path,
        status_code: m.status_code,
        ip_address: m.ip_address,
        user_agent: m.user_agent,
        trace_id: m.trace_id,
        request_body: m.request_body,
        duration_ms: m.duration_ms,
        created_at: m.created_at,
    }
}

impl CertStore {
    /// 写入一条审计日志
    pub async fn insert_audit_log(&self, row: AuditLogRow) -> Result<()> {
        let model = audit_log::ActiveModel {
            id: Set(row.id),
            user_id: Set(row.user_id),
            username: Set(row.username),
            action: Set(row.action),
            resource_type: Set(row.resource_type),
            resource_id: Set(row.resource_id),
            method: Set(row.method),
            path: Set(row.path),
            status_code: Set(row.status_code),
            ip_address: Set(row.ip_address),
            user_agent: Set(row.user_agent),
            trace_id: Set(row.trace_id),
            request_body: Set(row.request_body),
            duration_ms: Set(row.duration_ms),
            created_at: Set(row.created_at),
        };
        model.insert(&self.db).await?;
        Ok(())
    }

    /// 查询审计日志列表（分页）
    pub async fn list_audit_logs(
        &self,
        filter: &AuditLogFilter,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<AuditLogRow>> {
        let mut q = AuditEntity::find();

        if let Some(uid) = &filter.user_id {
            q = q.filter(AuditCol::UserId.eq(uid.as_str()));
        }
        if let Some(action) = &filter.action {
            q = q.filter(AuditCol::Action.eq(action.as_str()));
        }
        if let Some(rt) = &filter.resource_type {
            q = q.filter(AuditCol::ResourceType.eq(rt.as_str()));
        }
        if let Some(start) = &filter.start_time {
            q = q.filter(AuditCol::CreatedAt.gte(start.as_str()));
        }
        if let Some(end) = &filter.end_time {
            q = q.filter(AuditCol::CreatedAt.lte(end.as_str()));
        }

        let rows = q
            .order_by(AuditCol::CreatedAt, Order::Desc)
            .limit(limit)
            .offset(offset)
            .all(&self.db)
            .await?
            .into_iter()
            .map(model_to_row)
            .collect();

        Ok(rows)
    }

    /// 查询审计日志总数
    pub async fn count_audit_logs(&self, filter: &AuditLogFilter) -> Result<u64> {
        let mut q = AuditEntity::find();

        if let Some(uid) = &filter.user_id {
            q = q.filter(AuditCol::UserId.eq(uid.as_str()));
        }
        if let Some(action) = &filter.action {
            q = q.filter(AuditCol::Action.eq(action.as_str()));
        }
        if let Some(rt) = &filter.resource_type {
            q = q.filter(AuditCol::ResourceType.eq(rt.as_str()));
        }
        if let Some(start) = &filter.start_time {
            q = q.filter(AuditCol::CreatedAt.gte(start.as_str()));
        }
        if let Some(end) = &filter.end_time {
            q = q.filter(AuditCol::CreatedAt.lte(end.as_str()));
        }

        Ok(q.count(&self.db).await?)
    }

    /// 按 ID 查询单条审计日志
    pub async fn get_audit_log(&self, id: &str) -> Result<Option<AuditLogRow>> {
        let row = AuditEntity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(model_to_row);
        Ok(row)
    }
}
