use anyhow::{anyhow, Result};
use chrono::Utc;
use oxmon_common::types::{
    CreateDictionaryRequest, CreateDictionaryTypeRequest, DictionaryItem, DictionaryType,
    DictionaryTypeSummary, UpdateDictionaryRequest, UpdateDictionaryTypeRequest,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};

use crate::entities::dictionary_type::{self, Column as DtCol, Entity as DtEntity};
use crate::entities::system_dictionary::{self, Column as DictCol, Entity as DictEntity};
use crate::store::CertStore;

/// 字典类型过滤条件
#[derive(Debug, Clone, Default)]
pub struct DictTypeFilter {
    pub dict_type_contains: Option<String>,
    pub description_contains: Option<String>,
}

fn model_to_dict_item(m: system_dictionary::Model) -> DictionaryItem {
    DictionaryItem {
        id: m.id,
        dict_type: m.dict_type,
        dict_key: m.dict_key,
        dict_label: m.dict_label,
        dict_value: m.dict_value,
        sort_order: m.sort_order,
        enabled: m.enabled,
        is_system: m.is_system,
        description: m.description,
        extra_json: m.extra_json,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

fn model_to_dict_type(m: dictionary_type::Model) -> DictionaryType {
    DictionaryType {
        dict_type: m.dict_type,
        dict_type_label: m.dict_type_label,
        sort_order: m.sort_order,
        description: m.description,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

impl CertStore {
    // ---- system_dictionaries CRUD ----

    pub async fn insert_dictionary(
        &self,
        req: &CreateDictionaryRequest,
    ) -> Result<DictionaryItem> {
        let id = oxmon_common::id::next_id();
        let now = Utc::now().fixed_offset();
        let sort_order = req.sort_order.unwrap_or(0);
        let enabled = req.enabled.unwrap_or(true);
        let am = system_dictionary::ActiveModel {
            id: Set(id.clone()),
            dict_type: Set(req.dict_type.clone()),
            dict_key: Set(req.dict_key.clone()),
            dict_label: Set(req.dict_label.clone()),
            dict_value: Set(req.dict_value.clone()),
            sort_order: Set(sort_order),
            enabled: Set(enabled),
            is_system: Set(false),
            description: Set(req.description.clone()),
            extra_json: Set(req.extra_json.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        am.insert(self.db()).await?;
        self.get_dictionary_by_id(&id)
            .await?
            .ok_or_else(|| anyhow!("Failed to read inserted dictionary"))
    }

    pub async fn batch_insert_dictionaries(&self, items: &[DictionaryItem]) -> Result<usize> {
        let mut count = 0usize;
        for item in items {
            let now = item.created_at.fixed_offset();
            let am = system_dictionary::ActiveModel {
                id: Set(item.id.clone()),
                dict_type: Set(item.dict_type.clone()),
                dict_key: Set(item.dict_key.clone()),
                dict_label: Set(item.dict_label.clone()),
                dict_value: Set(item.dict_value.clone()),
                sort_order: Set(item.sort_order),
                enabled: Set(item.enabled),
                is_system: Set(item.is_system),
                description: Set(item.description.clone()),
                extra_json: Set(item.extra_json.clone()),
                created_at: Set(now),
                updated_at: Set(item.updated_at.fixed_offset()),
            };
            // Use INSERT OR IGNORE behavior: if insert fails (conflict), skip
            if am.insert(self.db()).await.is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    pub async fn get_dictionary_by_id(&self, id: &str) -> Result<Option<DictionaryItem>> {
        let model = DictEntity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(model_to_dict_item))
    }

    pub async fn list_dictionaries_by_types(
        &self,
        dict_types: &[&str],
        enabled_only: bool,
        key_contains: Option<&str>,
        label_contains: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<DictionaryItem>> {
        if dict_types.is_empty() {
            return Ok(vec![]);
        }
        let mut q = DictEntity::find()
            .filter(DictCol::DictType.is_in(dict_types.to_vec()));
        if enabled_only {
            q = q.filter(DictCol::Enabled.eq(true));
        }
        if let Some(k) = key_contains {
            q = q.filter(DictCol::DictKey.contains(k));
        }
        if let Some(l) = label_contains {
            q = q.filter(DictCol::DictLabel.contains(l));
        }
        let rows = q
            .order_by(DictCol::DictType, Order::Asc)
            .order_by(DictCol::SortOrder, Order::Asc)
            .order_by(DictCol::CreatedAt, Order::Asc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_dict_item).collect())
    }

    pub async fn list_dictionaries_by_type(
        &self,
        dict_type: &str,
        enabled_only: bool,
        key_contains: Option<&str>,
        label_contains: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<DictionaryItem>> {
        self.list_dictionaries_by_types(
            &[dict_type],
            enabled_only,
            key_contains,
            label_contains,
            limit,
            offset,
        )
        .await
    }

    pub async fn list_all_dict_types(
        &self,
        dict_type_contains: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<DictionaryTypeSummary>> {
        use sea_orm::{ConnectionTrait, Statement};
        let mut sql = String::from(
            "SELECT sd.dict_type, COUNT(*) AS cnt, dt.dict_type_label
             FROM system_dictionaries sd
             LEFT JOIN dictionary_types dt ON sd.dict_type = dt.dict_type
             WHERE 1=1",
        );
        if let Some(v) = dict_type_contains {
            let escaped = v.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
            sql.push_str(&format!(" AND sd.dict_type LIKE '%{escaped}%' ESCAPE '\\'"));
        }
        sql.push_str(&format!(
            " GROUP BY sd.dict_type ORDER BY COALESCE(dt.sort_order, 0) ASC, sd.dict_type ASC LIMIT {limit} OFFSET {offset}"
        ));
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        let mut results = Vec::with_capacity(rows.len());
        for row in rows {

            let dict_type: String = row.try_get("", "dict_type")?;
            let count: i64 = row.try_get("", "cnt")?;
            let label: Option<String> = row.try_get("", "dict_type_label")?;
            results.push(DictionaryTypeSummary {
                dict_type_label: label.unwrap_or_else(|| dict_type.clone()),
                dict_type,
                count: count as u64,
            });
        }
        Ok(results)
    }

    pub async fn update_dictionary(
        &self,
        id: &str,
        update: &UpdateDictionaryRequest,
    ) -> Result<Option<DictionaryItem>> {
        let model = DictEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: system_dictionary::ActiveModel = m.into();
            if let Some(ref label) = update.dict_label {
                am.dict_label = Set(label.clone());
            }
            if let Some(ref val) = update.dict_value {
                am.dict_value = Set(val.clone());
            }
            if let Some(order) = update.sort_order {
                am.sort_order = Set(order);
            }
            if let Some(en) = update.enabled {
                am.enabled = Set(en);
            }
            if let Some(ref desc) = update.description {
                am.description = Set(desc.clone());
            }
            if let Some(ref extra) = update.extra_json {
                am.extra_json = Set(extra.clone());
            }
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            Ok(Some(model_to_dict_item(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_dictionary(&self, id: &str) -> Result<bool> {
        use sea_orm::{ConnectionTrait, Statement};
        let sql = format!(
            "DELETE FROM system_dictionaries WHERE id = '{}' AND is_system = 0",
            id.replace('\'', "''")
        );
        let result = self
            .db()
            .execute_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count_dictionaries(&self) -> Result<u64> {
        Ok(DictEntity::find().count(self.db()).await?)
    }

    pub async fn count_dictionaries_by_types(
        &self,
        dict_types: &[&str],
        enabled_only: bool,
        key_contains: Option<&str>,
        label_contains: Option<&str>,
    ) -> Result<u64> {
        if dict_types.is_empty() {
            return Ok(0);
        }
        let mut q = DictEntity::find()
            .filter(DictCol::DictType.is_in(dict_types.to_vec()));
        if enabled_only {
            q = q.filter(DictCol::Enabled.eq(true));
        }
        if let Some(k) = key_contains {
            q = q.filter(DictCol::DictKey.contains(k));
        }
        if let Some(l) = label_contains {
            q = q.filter(DictCol::DictLabel.contains(l));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn count_dictionaries_by_type(
        &self,
        dict_type: &str,
        enabled_only: bool,
        key_contains: Option<&str>,
        label_contains: Option<&str>,
    ) -> Result<u64> {
        self.count_dictionaries_by_types(
            &[dict_type],
            enabled_only,
            key_contains,
            label_contains,
        )
        .await
    }

    pub async fn count_all_dict_types(
        &self,
        dict_type_contains: Option<&str>,
    ) -> Result<u64> {
        use sea_orm::{ConnectionTrait, Statement};
        let mut sql = String::from(
            "SELECT COUNT(DISTINCT dict_type) AS cnt FROM system_dictionaries WHERE 1=1",
        );
        if let Some(v) = dict_type_contains {
            let escaped = v.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
            sql.push_str(&format!(" AND dict_type LIKE '%{escaped}%' ESCAPE '\\'"));
        }
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        if let Some(row) = rows.into_iter().next() {

            let cnt: i64 = row.try_get("", "cnt")?;
            Ok(cnt as u64)
        } else {
            Ok(0)
        }
    }

    // ---- dictionary_types CRUD ----

    pub async fn insert_dictionary_type(
        &self,
        req: &CreateDictionaryTypeRequest,
    ) -> Result<DictionaryType> {
        let now = Utc::now().fixed_offset();
        let sort_order = req.sort_order.unwrap_or(0);
        let am = dictionary_type::ActiveModel {
            dict_type: Set(req.dict_type.clone()),
            dict_type_label: Set(req.dict_type_label.clone()),
            sort_order: Set(sort_order),
            description: Set(req.description.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        am.insert(self.db()).await?;
        self.get_dictionary_type(&req.dict_type)
            .await?
            .ok_or_else(|| anyhow!("Failed to read inserted dictionary type"))
    }

    pub async fn get_dictionary_type(&self, dict_type: &str) -> Result<Option<DictionaryType>> {
        let model = DtEntity::find_by_id(dict_type).one(self.db()).await?;
        Ok(model.map(model_to_dict_type))
    }

    pub async fn list_dictionary_types(&self) -> Result<Vec<DictionaryType>> {
        let rows = DtEntity::find()
            .order_by(DtCol::SortOrder, Order::Asc)
            .order_by(DtCol::DictType, Order::Asc)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_dict_type).collect())
    }

    pub async fn update_dictionary_type(
        &self,
        dict_type: &str,
        update: &UpdateDictionaryTypeRequest,
    ) -> Result<Option<DictionaryType>> {
        let model = DtEntity::find_by_id(dict_type).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: dictionary_type::ActiveModel = m.into();
            if let Some(ref label) = update.dict_type_label {
                am.dict_type_label = Set(label.clone());
            }
            if let Some(order) = update.sort_order {
                am.sort_order = Set(order);
            }
            if let Some(ref desc) = update.description {
                am.description = Set(desc.clone());
            }
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            Ok(Some(model_to_dict_type(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_dictionary_type(&self, dict_type: &str) -> Result<bool> {
        let res = DtEntity::delete_by_id(dict_type).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn batch_insert_dictionary_types(&self, items: &[DictionaryType]) -> Result<usize> {
        let mut count = 0usize;
        for item in items {
            let am = dictionary_type::ActiveModel {
                dict_type: Set(item.dict_type.clone()),
                dict_type_label: Set(item.dict_type_label.clone()),
                sort_order: Set(item.sort_order),
                description: Set(item.description.clone()),
                created_at: Set(item.created_at.fixed_offset()),
                updated_at: Set(item.updated_at.fixed_offset()),
            };
            if am.insert(self.db()).await.is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    pub async fn upsert_system_dictionary_types(
        &self,
        items: &[DictionaryType],
    ) -> Result<(usize, usize)> {
        let mut inserted = 0usize;
        let mut updated = 0usize;
        for item in items {
            let existing = DtEntity::find_by_id(&item.dict_type).one(self.db()).await?;
            if let Some(m) = existing {
                let now = Utc::now().fixed_offset();
                let needs_update = m.dict_type_label != item.dict_type_label
                    || m.sort_order != item.sort_order
                    || m.description != item.description;
                if needs_update {
                    let mut am: dictionary_type::ActiveModel = m.into();
                    am.dict_type_label = Set(item.dict_type_label.clone());
                    am.sort_order = Set(item.sort_order);
                    am.description = Set(item.description.clone());
                    am.updated_at = Set(now);
                    am.update(self.db()).await?;
                    updated += 1;
                }
            } else {
                let am = dictionary_type::ActiveModel {
                    dict_type: Set(item.dict_type.clone()),
                    dict_type_label: Set(item.dict_type_label.clone()),
                    sort_order: Set(item.sort_order),
                    description: Set(item.description.clone()),
                    created_at: Set(item.created_at.fixed_offset()),
                    updated_at: Set(item.updated_at.fixed_offset()),
                };
                am.insert(self.db()).await?;
                inserted += 1;
            }
        }
        Ok((inserted, updated))
    }

    pub async fn upsert_system_dictionaries(
        &self,
        items: &[DictionaryItem],
    ) -> Result<(usize, usize)> {
        let mut inserted = 0usize;
        let mut updated = 0usize;
        for item in items {
            // Find by dict_type + dict_key
            let existing = DictEntity::find()
                .filter(DictCol::DictType.eq(item.dict_type.as_str()))
                .filter(DictCol::DictKey.eq(item.dict_key.as_str()))
                .filter(DictCol::IsSystem.eq(true))
                .one(self.db())
                .await?;

            if let Some(m) = existing {
                let now = Utc::now().fixed_offset();
                let needs_update = m.dict_label != item.dict_label
                    || m.dict_value != item.dict_value
                    || m.sort_order != item.sort_order
                    || m.description != item.description;
                if needs_update {
                    let mut am: system_dictionary::ActiveModel = m.into();
                    am.dict_label = Set(item.dict_label.clone());
                    am.dict_value = Set(item.dict_value.clone());
                    am.sort_order = Set(item.sort_order);
                    am.description = Set(item.description.clone());
                    am.updated_at = Set(now);
                    am.update(self.db()).await?;
                    updated += 1;
                }
            } else {
                let now = item.created_at.fixed_offset();
                let am = system_dictionary::ActiveModel {
                    id: Set(item.id.clone()),
                    dict_type: Set(item.dict_type.clone()),
                    dict_key: Set(item.dict_key.clone()),
                    dict_label: Set(item.dict_label.clone()),
                    dict_value: Set(item.dict_value.clone()),
                    sort_order: Set(item.sort_order),
                    enabled: Set(item.enabled),
                    is_system: Set(item.is_system),
                    description: Set(item.description.clone()),
                    extra_json: Set(item.extra_json.clone()),
                    created_at: Set(now),
                    updated_at: Set(item.updated_at.fixed_offset()),
                };
                if am.insert(self.db()).await.is_ok() {
                    inserted += 1;
                }
            }
        }
        Ok((inserted, updated))
    }

    pub async fn disable_stale_system_dictionaries(
        &self,
        active_keys: &[(String, String)],
    ) -> Result<usize> {
        if active_keys.is_empty() {
            return Ok(0);
        }
        use sea_orm::{ConnectionTrait, Statement};
        // Build NOT EXISTS condition using OR
        let conditions: Vec<String> = active_keys
            .iter()
            .map(|(dt, dk)| {
                format!(
                    "(dict_type = '{}' AND dict_key = '{}')",
                    dt.replace('\'', "''"),
                    dk.replace('\'', "''")
                )
            })
            .collect();
        let not_in = conditions.join(" OR ");
        let now = Utc::now().fixed_offset().to_rfc3339();
        let sql = format!(
            "UPDATE system_dictionaries SET enabled = 0, updated_at = '{now}'
             WHERE is_system = 1 AND enabled = 1
               AND NOT ({not_in})"
        );
        let result = self
            .db()
            .execute_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        Ok(result.rows_affected() as usize)
    }

    pub async fn delete_stale_dictionary_types(&self, active_types: &[String]) -> Result<usize> {
        if active_types.is_empty() {
            return Ok(0);
        }
        use sea_orm::{ConnectionTrait, Statement};
        let quoted: Vec<String> = active_types
            .iter()
            .map(|s| format!("'{}'", s.replace('\'', "''")))
            .collect();
        let sql = format!(
            "DELETE FROM dictionary_types WHERE dict_type NOT IN ({})",
            quoted.join(", ")
        );
        let result = self
            .db()
            .execute_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        Ok(result.rows_affected() as usize)
    }

    pub async fn ensure_dictionary_type(&self, dict_type: &str) -> Result<()> {
        let exists = DtEntity::find_by_id(dict_type).one(self.db()).await?.is_some();
        if !exists {
            let now = Utc::now().fixed_offset();
            let am = dictionary_type::ActiveModel {
                dict_type: Set(dict_type.to_owned()),
                dict_type_label: Set(dict_type.to_owned()),
                sort_order: Set(0),
                description: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            let _ = am.insert(self.db()).await; // ignore conflict
        }
        Ok(())
    }
}
