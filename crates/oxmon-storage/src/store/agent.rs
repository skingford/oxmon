use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AgentEntry, AgentInfo, AgentWhitelistEntry};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};

use crate::entities::agent::{self, Column as AgentCol, Entity as AgentEntity};
use crate::entities::agent_whitelist::{
    self, Column as WhitelistCol, Entity as WhitelistEntity,
};
use crate::store::CertStore;

/// 白名单列表过滤器
#[derive(Debug, Clone, Default)]
pub struct AgentWhitelistFilter {
    pub agent_id_contains: Option<String>,
    pub description_contains: Option<String>,
}

/// agents 表列表过滤器
#[derive(Debug, Clone, Default)]
pub struct AgentListFilter {
    pub agent_id_contains: Option<String>,
    pub status_eq: Option<String>,
    pub last_seen_gte: Option<DateTime<Utc>>,
    pub last_seen_lte: Option<DateTime<Utc>>,
}

fn whitelist_to_entry(m: agent_whitelist::Model, token: Option<String>) -> AgentWhitelistEntry {
    AgentWhitelistEntry {
        id: m.id,
        agent_id: m.agent_id,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
        description: m.description,
        collection_interval_secs: None,
        token,
    }
}

fn agent_to_info(m: &agent::Model) -> AgentInfo {
    let five_min = 300i64;
    let interval = m.collection_interval_secs.unwrap_or(five_min);
    let last_seen = m.last_seen.with_timezone(&Utc);
    let active = (Utc::now() - last_seen).num_seconds() < interval * 3;
    AgentInfo {
        id: m.id.clone(),
        agent_id: m.agent_id.clone(),
        last_seen,
        active,
        collection_interval_secs: m.collection_interval_secs.map(|v| v as u64),
        description: m.description.clone(),
    }
}

fn agent_to_entry(m: agent::Model) -> AgentEntry {
    AgentEntry {
        id: m.id,
        agent_id: m.agent_id,
        first_seen: m.first_seen.with_timezone(&Utc),
        last_seen: m.last_seen.with_timezone(&Utc),
        collection_interval_secs: m.collection_interval_secs.map(|v| v as u64),
        description: m.description,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

impl CertStore {
    // ---- agent_whitelist ----

    pub async fn add_agent_to_whitelist(
        &self,
        agent_id: &str,
        _token: &str,
        token_hash: &str,
        description: Option<&str>,
    ) -> Result<String> {
        let id = oxmon_common::id::next_id();
        let now = Utc::now().fixed_offset();
        let encrypted = self.token_encryptor.encrypt(_token)?;
        let am = agent_whitelist::ActiveModel {
            id: Set(id.clone()),
            agent_id: Set(agent_id.to_owned()),
            token_hash: Set(token_hash.to_owned()),
            encrypted_token: Set(Some(encrypted)),
            description: Set(description.map(|s| s.to_owned())),
            created_at: Set(now),
            updated_at: Set(now),
        };
        am.insert(self.db()).await?;
        Ok(id)
    }

    pub async fn get_agent_token_hash(&self, agent_id: &str) -> Result<Option<String>> {
        let model = WhitelistEntity::find()
            .filter(WhitelistCol::AgentId.eq(agent_id))
            .one(self.db())
            .await?;
        Ok(model.map(|m| m.token_hash))
    }

    /// 返回 (encrypted_token, token_hash)
    pub async fn get_agent_auth(
        &self,
        agent_id: &str,
    ) -> Result<Option<(Option<String>, String)>> {
        let model = WhitelistEntity::find()
            .filter(WhitelistCol::AgentId.eq(agent_id))
            .one(self.db())
            .await?;
        Ok(model.map(|m| (m.encrypted_token, m.token_hash)))
    }

    pub async fn list_agents(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AgentWhitelistEntry>> {
        let rows = WhitelistEntity::find()
            .order_by(WhitelistCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        let mut result = Vec::with_capacity(rows.len());
        for m in rows {
            let token = m
                .encrypted_token
                .as_deref()
                .and_then(|enc| self.token_encryptor.decrypt(enc).ok());
            result.push(whitelist_to_entry(m, token));
        }
        Ok(result)
    }

    pub async fn list_agents_with_filter(
        &self,
        filter: &AgentWhitelistFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AgentWhitelistEntry>> {
        let mut q = WhitelistEntity::find();
        if let Some(ref s) = filter.agent_id_contains {
            q = q.filter(WhitelistCol::AgentId.contains(s.as_str()));
        }
        if let Some(ref s) = filter.description_contains {
            q = q.filter(WhitelistCol::Description.contains(s.as_str()));
        }
        let rows = q
            .order_by(WhitelistCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        let mut result = Vec::with_capacity(rows.len());
        for m in rows {
            let token = m
                .encrypted_token
                .as_deref()
                .and_then(|enc| self.token_encryptor.decrypt(enc).ok());
            result.push(whitelist_to_entry(m, token));
        }
        Ok(result)
    }

    pub async fn count_agents(&self) -> Result<u64> {
        Ok(WhitelistEntity::find().count(self.db()).await?)
    }

    pub async fn count_agents_with_filter(&self, filter: &AgentWhitelistFilter) -> Result<u64> {
        let mut q = WhitelistEntity::find();
        if let Some(ref s) = filter.agent_id_contains {
            q = q.filter(WhitelistCol::AgentId.contains(s.as_str()));
        }
        if let Some(ref s) = filter.description_contains {
            q = q.filter(WhitelistCol::Description.contains(s.as_str()));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn delete_agent_from_whitelist(&self, id: &str) -> Result<bool> {
        let res = WhitelistEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn get_agent_id_by_agent_id(&self, agent_id: &str) -> Result<Option<String>> {
        let model = WhitelistEntity::find()
            .filter(WhitelistCol::AgentId.eq(agent_id))
            .one(self.db())
            .await?;
        Ok(model.map(|m| m.id))
    }

    pub async fn agent_exists(&self, agent_id: &str) -> Result<bool> {
        let count = WhitelistEntity::find()
            .filter(WhitelistCol::AgentId.eq(agent_id))
            .count(self.db())
            .await?;
        Ok(count > 0)
    }

    pub async fn update_agent_whitelist(
        &self,
        id: &str,
        description: Option<Option<&str>>,
    ) -> Result<bool> {
        let model = WhitelistEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: agent_whitelist::ActiveModel = m.into();
            if let Some(d) = description {
                am.description = Set(d.map(|s| s.to_owned()));
            }
            am.updated_at = Set(now);
            am.update(self.db()).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn update_agent_token_hash(
        &self,
        id: &str,
        token: &str,
        token_hash: &str,
    ) -> Result<bool> {
        let model = WhitelistEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let encrypted = self.token_encryptor.encrypt(token)?;
            let mut am: agent_whitelist::ActiveModel = m.into();
            am.token_hash = Set(token_hash.to_owned());
            am.encrypted_token = Set(Some(encrypted));
            am.updated_at = Set(now);
            am.update(self.db()).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn get_agent_by_id(&self, id: &str) -> Result<Option<AgentWhitelistEntry>> {
        let model = WhitelistEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let token = m
                .encrypted_token
                .as_deref()
                .and_then(|enc| self.token_encryptor.decrypt(enc).ok());
            Ok(Some(whitelist_to_entry(m, token)))
        } else {
            Ok(None)
        }
    }

    // ---- agents 表 ----

    pub async fn upsert_agent(&self, agent_id: &str) -> Result<()> {
        use sea_orm::sea_query::OnConflict;
        use sea_orm::Set as S;
        let now = Utc::now().fixed_offset();
        // 尝试插入；若 agent_id 已存在则更新 last_seen
        let id = oxmon_common::id::next_id();
        let am = agent::ActiveModel {
            id: S(id),
            agent_id: S(agent_id.to_owned()),
            first_seen: S(now),
            last_seen: S(now),
            collection_interval_secs: Set(None),
            description: Set(None),
            created_at: S(now),
            updated_at: S(now),
        };
        AgentEntity::insert(am)
            .on_conflict(
                OnConflict::column(AgentCol::AgentId)
                    .update_column(AgentCol::LastSeen)
                    .update_column(AgentCol::UpdatedAt)
                    .to_owned(),
            )
            .exec(self.db())
            .await?;
        Ok(())
    }

    pub async fn update_agent_config(
        &self,
        agent_id: &str,
        collection_interval_secs: Option<Option<u64>>,
        description: Option<Option<&str>>,
    ) -> Result<bool> {
        let model = AgentEntity::find()
            .filter(AgentCol::AgentId.eq(agent_id))
            .one(self.db())
            .await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: agent::ActiveModel = m.into();
            if let Some(interval) = collection_interval_secs {
                am.collection_interval_secs = Set(interval.map(|v| v as i64));
            }
            if let Some(desc) = description {
                am.description = Set(desc.map(|s| s.to_owned()));
            }
            am.updated_at = Set(now);
            am.update(self.db()).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn delete_agent_from_db(&self, id: &str) -> Result<bool> {
        let res = AgentEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn list_agents_from_db(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AgentInfo>> {
        let rows = AgentEntity::find()
            .order_by(AgentCol::LastSeen, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.iter().map(agent_to_info).collect())
    }

    pub async fn list_agents_from_db_with_filter(
        &self,
        filter: &AgentListFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AgentInfo>> {
        let mut q = AgentEntity::find();
        if let Some(ref s) = filter.agent_id_contains {
            q = q.filter(AgentCol::AgentId.contains(s.as_str()));
        }
        if let Some(ref ts) = filter.last_seen_gte {
            q = q.filter(AgentCol::LastSeen.gte(ts.fixed_offset()));
        }
        if let Some(ref ts) = filter.last_seen_lte {
            q = q.filter(AgentCol::LastSeen.lte(ts.fixed_offset()));
        }
        let rows = q
            .order_by(AgentCol::LastSeen, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.iter().map(agent_to_info).collect())
    }

    pub async fn count_agents_from_db(&self) -> Result<u64> {
        Ok(AgentEntity::find().count(self.db()).await?)
    }

    pub async fn count_agents_from_db_with_filter(
        &self,
        filter: &AgentListFilter,
    ) -> Result<u64> {
        let mut q = AgentEntity::find();
        if let Some(ref s) = filter.agent_id_contains {
            q = q.filter(AgentCol::AgentId.contains(s.as_str()));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn get_agent_collection_interval(&self, agent_id: &str) -> Result<Option<u64>> {
        let model = AgentEntity::find()
            .filter(AgentCol::AgentId.eq(agent_id))
            .one(self.db())
            .await?;
        Ok(model.and_then(|m| m.collection_interval_secs.map(|v| v as u64)))
    }

    pub async fn get_agent_by_agent_id(&self, agent_id: &str) -> Result<Option<AgentWhitelistEntry>> {
        // 在 agent_whitelist 中查（agent_id 字段相同）
        let model = WhitelistEntity::find()
            .filter(WhitelistCol::AgentId.eq(agent_id))
            .one(self.db())
            .await?;
        if let Some(m) = model {
            let token = m
                .encrypted_token
                .as_deref()
                .and_then(|enc| self.token_encryptor.decrypt(enc).ok());
            Ok(Some(whitelist_to_entry(m, token)))
        } else {
            Ok(None)
        }
    }

    pub async fn get_whitelist_created_at_map(
        &self,
    ) -> Result<std::collections::HashMap<String, DateTime<Utc>>> {
        let rows = WhitelistEntity::find().all(self.db()).await?;
        Ok(rows
            .into_iter()
            .map(|m| (m.agent_id, m.created_at.with_timezone(&Utc)))
            .collect())
    }

    pub async fn get_agent_from_db(
        &self,
        agent_id: &str,
    ) -> Result<Option<(DateTime<Utc>, DateTime<Utc>)>> {
        let model = AgentEntity::find()
            .filter(AgentCol::AgentId.eq(agent_id))
            .one(self.db())
            .await?;
        Ok(model.map(|m| {
            (
                m.first_seen.with_timezone(&Utc),
                m.last_seen.with_timezone(&Utc),
            )
        }))
    }

    pub async fn get_agent_by_id_or_agent_id(&self, id: &str) -> Result<Option<AgentEntry>> {
        use sea_orm::Condition;
        let model = AgentEntity::find()
            .filter(
                Condition::any()
                    .add(AgentCol::Id.eq(id))
                    .add(AgentCol::AgentId.eq(id)),
            )
            .one(self.db())
            .await?;
        Ok(model.map(agent_to_entry))
    }
}
