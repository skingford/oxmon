use anyhow::Result;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};

use crate::entities::system_config::{self, Column, Entity};
use crate::store::CertStore;

/// 系统配置数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfigRow {
    pub id: String,
    pub config_key: String,
    pub config_type: String,
    pub provider: Option<String>,
    pub display_name: String,
    pub description: Option<String>,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 系统配置更新请求
#[derive(Debug, Clone)]
pub struct SystemConfigUpdate {
    pub display_name: Option<String>,
    pub description: Option<Option<String>>,
    pub config_json: Option<String>,
    pub enabled: Option<bool>,
}

/// 系统配置过滤器
#[derive(Debug, Clone, Default)]
pub struct SystemConfigFilter {
    pub config_key_contains: Option<String>,
    pub config_type_eq: Option<String>,
    pub provider_eq: Option<String>,
    pub enabled_eq: Option<bool>,
}

fn to_row(m: system_config::Model) -> SystemConfigRow {
    SystemConfigRow {
        id: m.id,
        config_key: m.config_key,
        config_type: m.config_type,
        provider: m.provider,
        display_name: m.display_name,
        description: m.description,
        config_json: m.config_json,
        enabled: m.enabled,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

impl CertStore {
    pub async fn insert_system_config(&self, row: &SystemConfigRow) -> Result<SystemConfigRow> {
        let now = Utc::now().fixed_offset();
        let am = system_config::ActiveModel {
            id: Set(row.id.clone()),
            config_key: Set(row.config_key.clone()),
            config_type: Set(row.config_type.clone()),
            provider: Set(row.provider.clone()),
            display_name: Set(row.display_name.clone()),
            description: Set(row.description.clone()),
            config_json: Set(row.config_json.clone()),
            enabled: Set(row.enabled),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let model = am.insert(self.db()).await?;
        Ok(to_row(model))
    }

    pub async fn get_system_config_by_id(&self, id: &str) -> Result<Option<SystemConfigRow>> {
        Ok(Entity::find_by_id(id).one(self.db()).await?.map(to_row))
    }

    pub async fn get_system_config_by_key(&self, config_key: &str) -> Result<Option<SystemConfigRow>> {
        Ok(Entity::find()
            .filter(Column::ConfigKey.eq(config_key))
            .one(self.db())
            .await?
            .map(to_row))
    }

    pub async fn list_system_configs(
        &self,
        config_type: Option<&str>,
        enabled: Option<bool>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<SystemConfigRow>> {
        let mut q = Entity::find();
        if let Some(ct) = config_type {
            q = q.filter(Column::ConfigType.eq(ct));
        }
        if let Some(en) = enabled {
            q = q.filter(Column::Enabled.eq(en));
        }
        let rows = q
            .order_by(Column::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(to_row).collect())
    }

    pub async fn count_system_configs(
        &self,
        config_type: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<u64> {
        let mut q = Entity::find();
        if let Some(ct) = config_type {
            q = q.filter(Column::ConfigType.eq(ct));
        }
        if let Some(en) = enabled {
            q = q.filter(Column::Enabled.eq(en));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn update_system_config(
        &self,
        id: &str,
        description: Option<&str>,
        enabled: Option<bool>,
        config_json: Option<&str>,
    ) -> Result<Option<SystemConfigRow>> {
        let model = Entity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: system_config::ActiveModel = m.into();
            if let Some(d) = description {
                am.description = Set(Some(d.to_owned()));
            }
            if let Some(en) = enabled {
                am.enabled = Set(en);
            }
            if let Some(cj) = config_json {
                am.config_json = Set(cj.to_owned());
            }
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            Ok(Some(to_row(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_system_config(&self, id: &str) -> Result<bool> {
        let res = Entity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    // ---- Runtime 设置（system_configs 中 config_type="runtime" 的项）----

    async fn get_runtime_setting_raw(&self, config_key: &str) -> Option<String> {
        let model = Entity::find()
            .filter(Column::ConfigKey.eq(config_key))
            .filter(Column::ConfigType.eq("runtime"))
            .one(self.db())
            .await
            .ok()
            .flatten();
        model.map(|m| m.config_json)
    }

    fn parse_json_string(json: &str) -> Option<String> {
        serde_json::from_str::<String>(json).ok()
            .or_else(|| Some(json.trim_matches('"').to_owned()))
    }

    pub async fn get_runtime_setting_u64(&self, config_key: &str, default: u64) -> u64 {
        self.get_runtime_setting_raw(config_key)
            .await
            .and_then(|v| serde_json::from_str::<u64>(&v).ok())
            .unwrap_or(default)
    }

    pub async fn get_runtime_setting_u32(&self, config_key: &str, default: u32) -> u32 {
        self.get_runtime_setting_raw(config_key)
            .await
            .and_then(|v| serde_json::from_str::<u32>(&v).ok())
            .unwrap_or(default)
    }

    pub async fn get_runtime_setting_string(&self, config_key: &str, default: &str) -> String {
        self.get_runtime_setting_raw(config_key)
            .await
            .and_then(|v| Self::parse_json_string(&v))
            .unwrap_or_else(|| default.to_owned())
    }

    pub async fn get_runtime_setting_bool(&self, config_key: &str, default: bool) -> bool {
        self.get_runtime_setting_raw(config_key)
            .await
            .and_then(|v| serde_json::from_str::<bool>(&v).ok())
            .unwrap_or(default)
    }
}
