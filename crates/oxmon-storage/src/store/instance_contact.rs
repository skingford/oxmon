use anyhow::Result;
use chrono::Utc;
use sea_orm::*;

use crate::entities::instance_contact::{
    self, Column as Col, Entity as ContactEntity,
};

/// 实例联系人行（对外暴露的 Row 类型）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InstanceContactRow {
    pub id: String,
    pub agent_patterns: String,
    pub contact_name: String,
    pub contact_email: Option<String>,
    pub contact_phone: Option<String>,
    pub contact_dingtalk: Option<String>,
    pub contact_webhook: Option<String>,
    pub enabled: bool,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// 实例联系人更新请求。
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct InstanceContactUpdate {
    pub agent_patterns: Option<String>,
    pub contact_name: Option<String>,
    pub contact_email: Option<Option<String>>,
    pub contact_phone: Option<Option<String>>,
    pub contact_dingtalk: Option<Option<String>>,
    pub contact_webhook: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub description: Option<Option<String>>,
}

/// 实例联系人列表过滤条件。
#[derive(Debug, Clone, Default)]
pub struct InstanceContactFilter {
    pub contact_name_contains: Option<String>,
    pub enabled_eq: Option<bool>,
}

fn model_to_row(m: instance_contact::Model) -> InstanceContactRow {
    InstanceContactRow {
        id: m.id,
        agent_patterns: m.agent_patterns,
        contact_name: m.contact_name,
        contact_email: m.contact_email,
        contact_phone: m.contact_phone,
        contact_dingtalk: m.contact_dingtalk,
        contact_webhook: m.contact_webhook,
        enabled: m.enabled,
        description: m.description,
        created_at: m.created_at.to_rfc3339(),
        updated_at: m.updated_at.to_rfc3339(),
    }
}

fn apply_filter(
    mut q: Select<ContactEntity>,
    filter: &InstanceContactFilter,
) -> Select<ContactEntity> {
    if let Some(ref s) = filter.contact_name_contains {
        q = q.filter(Col::ContactName.contains(s.as_str()));
    }
    if let Some(en) = filter.enabled_eq {
        q = q.filter(Col::Enabled.eq(en));
    }
    q
}

impl super::CertStore {
    // ---- CRUD ----

    pub async fn insert_instance_contact(
        &self,
        row: &InstanceContactRow,
    ) -> Result<InstanceContactRow> {
        let now = Utc::now().fixed_offset();
        let am = instance_contact::ActiveModel {
            id: Set(row.id.clone()),
            agent_patterns: Set(row.agent_patterns.clone()),
            contact_name: Set(row.contact_name.clone()),
            contact_email: Set(row.contact_email.clone()),
            contact_phone: Set(row.contact_phone.clone()),
            contact_dingtalk: Set(row.contact_dingtalk.clone()),
            contact_webhook: Set(row.contact_webhook.clone()),
            enabled: Set(row.enabled),
            description: Set(row.description.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let model = am.insert(self.db()).await?;
        Ok(model_to_row(model))
    }

    pub async fn get_instance_contact_by_id(
        &self,
        id: &str,
    ) -> Result<Option<InstanceContactRow>> {
        let model = ContactEntity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(model_to_row))
    }

    pub async fn list_instance_contacts(
        &self,
        filter: &InstanceContactFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<InstanceContactRow>> {
        let q = apply_filter(ContactEntity::find(), filter);
        let rows = q
            .order_by(Col::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_row).collect())
    }

    pub async fn count_instance_contacts(
        &self,
        filter: &InstanceContactFilter,
    ) -> Result<u64> {
        let q = apply_filter(ContactEntity::find(), filter);
        Ok(q.count(self.db()).await?)
    }

    pub async fn update_instance_contact(
        &self,
        id: &str,
        upd: &InstanceContactUpdate,
    ) -> Result<Option<InstanceContactRow>> {
        let model = ContactEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: instance_contact::ActiveModel = m.into();
            if let Some(ref v) = upd.agent_patterns {
                am.agent_patterns = Set(v.clone());
            }
            if let Some(ref v) = upd.contact_name {
                am.contact_name = Set(v.clone());
            }
            if let Some(ref v) = upd.contact_email {
                am.contact_email = Set(v.clone());
            }
            if let Some(ref v) = upd.contact_phone {
                am.contact_phone = Set(v.clone());
            }
            if let Some(ref v) = upd.contact_dingtalk {
                am.contact_dingtalk = Set(v.clone());
            }
            if let Some(ref v) = upd.contact_webhook {
                am.contact_webhook = Set(v.clone());
            }
            if let Some(en) = upd.enabled {
                am.enabled = Set(en);
            }
            if let Some(ref v) = upd.description {
                am.description = Set(v.clone());
            }
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            Ok(Some(model_to_row(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_instance_contact(&self, id: &str) -> Result<bool> {
        let res = ContactEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    // ---- 核心查询：根据 agent_id 查找匹配的联系人 ----

    /// 加载所有已启用的联系人，解析 agent_patterns JSON 数组，逐一 glob_match。
    /// 返回所有匹配的联系人（已去重）。
    pub async fn find_contacts_for_agent(
        &self,
        agent_id: &str,
    ) -> Result<Vec<InstanceContactRow>> {
        let all = ContactEntity::find()
            .filter(Col::Enabled.eq(true))
            .all(self.db())
            .await?;

        let mut matched = Vec::new();
        for m in all {
            let patterns: Vec<String> =
                serde_json::from_str(&m.agent_patterns).unwrap_or_default();
            for pattern in &patterns {
                if glob_match::glob_match(pattern, agent_id) {
                    matched.push(model_to_row(m));
                    break;
                }
            }
        }
        Ok(matched)
    }
}
