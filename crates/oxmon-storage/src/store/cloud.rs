use anyhow::Result;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};

use crate::entities::cloud_account::{self, Column as AcctCol, Entity as AcctEntity};
use crate::entities::cloud_collection_state::{self, Entity as StateEntity};
use crate::entities::cloud_instance::{self, Column as InstCol, Entity as InstEntity};
use crate::store::CertStore;

/// 云账号数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAccountRow {
    pub id: String,
    pub config_key: String,
    pub provider: String,
    pub display_name: String,
    pub description: Option<String>,
    pub account_name: String,
    pub secret_id: String,
    pub secret_key: String,
    pub regions: Vec<String>,
    pub collection_interval_secs: i64,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 云实例数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudInstanceRow {
    pub id: String,
    pub instance_id: String,
    pub instance_name: Option<String>,
    pub provider: String,
    pub account_config_key: String,
    pub region: String,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub os: Option<String>,
    pub status: Option<String>,
    pub last_seen_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub instance_type: Option<String>,
    pub cpu_cores: Option<i32>,
    pub memory_gb: Option<f64>,
    pub disk_gb: Option<f64>,
    pub created_time: Option<i64>,
    pub expired_time: Option<i64>,
    pub charge_type: Option<String>,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub security_group_ids: Option<String>,
    pub zone: Option<String>,
    pub internet_max_bandwidth: Option<i32>,
    pub ipv6_addresses: Option<String>,
    pub eip_allocation_id: Option<String>,
    pub internet_charge_type: Option<String>,
    pub image_id: Option<String>,
    pub hostname: Option<String>,
    pub description: Option<String>,
    pub gpu: Option<i32>,
    pub io_optimized: Option<String>,
    pub latest_operation: Option<String>,
    pub latest_operation_state: Option<String>,
    pub tags: Option<String>,
    pub project_id: Option<String>,
    pub resource_group_id: Option<String>,
    pub auto_renew_flag: Option<String>,
}

/// 云采集状态数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudCollectionStateRow {
    pub config_key: String,
    pub last_collected_at: i64,
    pub last_instance_count: i32,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

/// 云实例状态摘要
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudInstanceStatusSummary {
    pub total_instances: u64,
    pub running_instances: u64,
    pub stopped_instances: u64,
    pub pending_instances: u64,
    pub error_instances: u64,
    pub unknown_instances: u64,
}

/// 云账号摘要
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudAccountSummary {
    pub total_accounts: u64,
    pub enabled_accounts: u64,
}

fn model_to_account(m: cloud_account::Model) -> CloudAccountRow {
    let regions: Vec<String> = serde_json::from_str(&m.regions).unwrap_or_default();
    CloudAccountRow {
        id: m.id,
        config_key: m.config_key,
        provider: m.provider,
        display_name: m.display_name,
        description: m.description,
        account_name: m.account_name,
        secret_id: m.secret_id,
        secret_key: m.secret_key,
        regions,
        collection_interval_secs: m.collection_interval_secs,
        enabled: m.enabled,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

fn model_to_instance(m: cloud_instance::Model) -> CloudInstanceRow {
    let created_time: Option<i64> = m
        .created_time
        .as_deref()
        .and_then(|s| s.parse::<i64>().ok());
    let expired_time: Option<i64> = m
        .expired_time
        .as_deref()
        .and_then(|s| s.parse::<i64>().ok());
    let auto_renew_flag = m
        .auto_renew_flag
        .map(|b| if b { "1".to_string() } else { "0".to_string() });
    CloudInstanceRow {
        id: m.id,
        instance_id: m.instance_id,
        instance_name: m.instance_name,
        provider: m.provider,
        account_config_key: m.account_config_key,
        region: m.region,
        public_ip: m.public_ip,
        private_ip: m.private_ip,
        os: m.os,
        status: m.status,
        last_seen_at: m.last_seen_at.with_timezone(&Utc).timestamp(),
        created_at: m.created_at.with_timezone(&Utc).timestamp(),
        updated_at: m.updated_at.with_timezone(&Utc).timestamp(),
        instance_type: m.instance_type,
        cpu_cores: m.cpu_cores,
        memory_gb: m.memory_gb.map(|v| v as f64),
        disk_gb: m.disk_gb.map(|v| v as f64),
        created_time,
        expired_time,
        charge_type: m.charge_type,
        vpc_id: m.vpc_id,
        subnet_id: m.subnet_id,
        security_group_ids: m.security_group_ids,
        zone: m.zone,
        internet_max_bandwidth: m.internet_max_bandwidth,
        ipv6_addresses: m.ipv6_addresses,
        eip_allocation_id: m.eip_allocation_id,
        internet_charge_type: m.internet_charge_type,
        image_id: m.image_id,
        hostname: m.hostname,
        description: m.description,
        gpu: m.gpu,
        io_optimized: m.io_optimized,
        latest_operation: m.latest_operation,
        latest_operation_state: m.latest_operation_state,
        tags: m.tags,
        project_id: m.project_id,
        resource_group_id: m.resource_group_id,
        auto_renew_flag,
    }
}

fn ts_to_dt(ts: i64) -> chrono::DateTime<chrono::FixedOffset> {
    DateTime::<Utc>::from_timestamp(ts, 0)
        .unwrap_or_default()
        .fixed_offset()
}

impl CertStore {
    // ---- cloud_accounts ----

    pub async fn insert_cloud_account(&self, row: &CloudAccountRow) -> Result<CloudAccountRow> {
        let now = Utc::now().fixed_offset();
        let regions_json = serde_json::to_string(&row.regions)?;
        let am = cloud_account::ActiveModel {
            id: Set(row.id.clone()),
            config_key: Set(row.config_key.clone()),
            provider: Set(row.provider.clone()),
            display_name: Set(row.display_name.clone()),
            description: Set(row.description.clone()),
            account_name: Set(row.account_name.clone()),
            secret_id: Set(row.secret_id.clone()),
            secret_key: Set(row.secret_key.clone()),
            regions: Set(regions_json),
            collection_interval_secs: Set(row.collection_interval_secs),
            enabled: Set(row.enabled),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let model = am.insert(self.db()).await?;
        Ok(model_to_account(model))
    }

    pub async fn get_cloud_account_by_id(&self, id: &str) -> Result<CloudAccountRow> {
        let model = AcctEntity::find_by_id(id).one(self.db()).await?;
        model
            .map(model_to_account)
            .ok_or_else(|| anyhow::anyhow!("Cloud account not found: {}", id))
    }

    pub async fn get_cloud_account_by_config_key(
        &self,
        config_key: &str,
    ) -> Result<CloudAccountRow> {
        let model = AcctEntity::find()
            .filter(AcctCol::ConfigKey.eq(config_key))
            .one(self.db())
            .await?;
        model
            .map(model_to_account)
            .ok_or_else(|| anyhow::anyhow!("Cloud account not found: {}", config_key))
    }

    pub async fn list_cloud_accounts(
        &self,
        provider: Option<&str>,
        enabled: Option<bool>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CloudAccountRow>> {
        let mut q = AcctEntity::find();
        if let Some(p) = provider {
            q = q.filter(AcctCol::Provider.eq(p));
        }
        if let Some(en) = enabled {
            q = q.filter(AcctCol::Enabled.eq(en));
        }
        let rows = q
            .order_by(AcctCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_account).collect())
    }

    pub async fn count_cloud_accounts(
        &self,
        provider: Option<&str>,
        enabled: Option<bool>,
    ) -> Result<u64> {
        let mut q = AcctEntity::find();
        if let Some(p) = provider {
            q = q.filter(AcctCol::Provider.eq(p));
        }
        if let Some(en) = enabled {
            q = q.filter(AcctCol::Enabled.eq(en));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn update_cloud_account(
        &self,
        id: &str,
        row: &CloudAccountRow,
    ) -> Result<CloudAccountRow> {
        let model = AcctEntity::find_by_id(id).one(self.db()).await?;
        let m = model.ok_or_else(|| anyhow::anyhow!("Cloud account not found: {}", id))?;
        let now = Utc::now().fixed_offset();
        let regions_json = serde_json::to_string(&row.regions)?;
        let mut am: cloud_account::ActiveModel = m.into();
        am.config_key = Set(row.config_key.clone());
        am.provider = Set(row.provider.clone());
        am.display_name = Set(row.display_name.clone());
        am.description = Set(row.description.clone());
        am.account_name = Set(row.account_name.clone());
        am.secret_id = Set(row.secret_id.clone());
        am.secret_key = Set(row.secret_key.clone());
        am.regions = Set(regions_json);
        am.collection_interval_secs = Set(row.collection_interval_secs);
        am.enabled = Set(row.enabled);
        am.updated_at = Set(now);
        let updated = am.update(self.db()).await?;
        Ok(model_to_account(updated))
    }

    pub async fn delete_cloud_account(&self, id: &str) -> Result<bool> {
        let res = AcctEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn cloud_account_summary(&self) -> Result<CloudAccountSummary> {
        let total = AcctEntity::find().count(self.db()).await?;
        let enabled = AcctEntity::find()
            .filter(AcctCol::Enabled.eq(true))
            .count(self.db())
            .await?;
        Ok(CloudAccountSummary {
            total_accounts: total,
            enabled_accounts: enabled,
        })
    }

    // ---- cloud_collection_state ----

    pub async fn get_cloud_collection_state(
        &self,
        config_key: &str,
    ) -> Result<Option<CloudCollectionStateRow>> {
        let model = StateEntity::find_by_id(config_key).one(self.db()).await?;
        Ok(model.map(|m| CloudCollectionStateRow {
            config_key: m.config_key,
            last_collected_at: m.last_collected_at.with_timezone(&Utc).timestamp(),
            last_instance_count: m.last_instance_count,
            last_error: m.last_error,
            updated_at: m.updated_at.with_timezone(&Utc).timestamp(),
        }))
    }

    pub async fn upsert_cloud_collection_state(
        &self,
        config_key: &str,
        last_collected_at: i64,
        last_instance_count: i32,
        last_error: Option<&str>,
    ) -> Result<()> {
        use sea_orm::sea_query::OnConflict;
        let now = Utc::now().fixed_offset();
        let collected_dt = ts_to_dt(last_collected_at);
        let am = cloud_collection_state::ActiveModel {
            config_key: Set(config_key.to_owned()),
            last_collected_at: Set(collected_dt),
            last_instance_count: Set(last_instance_count),
            last_error: Set(last_error.map(|s| s.to_owned())),
            updated_at: Set(now),
        };
        StateEntity::insert(am)
            .on_conflict(
                OnConflict::column(crate::entities::cloud_collection_state::Column::ConfigKey)
                    .update_columns([
                        crate::entities::cloud_collection_state::Column::LastCollectedAt,
                        crate::entities::cloud_collection_state::Column::LastInstanceCount,
                        crate::entities::cloud_collection_state::Column::LastError,
                        crate::entities::cloud_collection_state::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(self.db())
            .await?;
        Ok(())
    }

    // ---- cloud_instances ----

    pub async fn upsert_cloud_instance(&self, instance: &CloudInstanceRow) -> Result<()> {
        use sea_orm::{ConnectionTrait, Statement};
        let now = Utc::now().fixed_offset();
        let id = oxmon_common::id::next_id();
        let last_seen_dt = ts_to_dt(instance.last_seen_at).to_rfc3339();
        let created_dt = now.to_rfc3339();

        fn opt_str(s: &Option<String>) -> String {
            match s {
                Some(v) => format!("'{}'", v.replace('\'', "''")),
                None => "NULL".to_string(),
            }
        }
        fn opt_i32(v: Option<i32>) -> String {
            match v {
                Some(n) => n.to_string(),
                None => "NULL".to_string(),
            }
        }
        fn opt_f64(v: Option<f64>) -> String {
            match v {
                Some(n) => n.to_string(),
                None => "NULL".to_string(),
            }
        }
        fn opt_i64_as_str(v: Option<i64>) -> String {
            match v {
                Some(n) => format!("'{n}'"),
                None => "NULL".to_string(),
            }
        }
        fn opt_bool_str(s: &Option<String>) -> String {
            match s.as_deref() {
                Some("1") | Some("true") | Some("True") => "1".to_string(),
                Some(_) => "0".to_string(),
                None => "NULL".to_string(),
            }
        }

        let sql = format!(
            "INSERT INTO cloud_instances
             (id, instance_id, instance_name, provider, account_config_key, region,
              public_ip, private_ip, os, status, last_seen_at, created_at, updated_at,
              instance_type, cpu_cores, memory_gb, disk_gb,
              created_time, expired_time, charge_type, vpc_id, subnet_id, security_group_ids, zone,
              internet_max_bandwidth, ipv6_addresses, eip_allocation_id, internet_charge_type,
              image_id, hostname, description,
              gpu, io_optimized, latest_operation, latest_operation_state,
              tags, project_id, resource_group_id, auto_renew_flag)
             VALUES
             ('{id}', '{iid}', {iname}, '{provider}', '{config_key}', '{region}',
              {pip}, {piv}, {os}, {status}, '{last_seen}', '{created}', '{updated}',
              {itype}, {cpu}, {mem}, {disk},
              {ct}, {et}, {charge}, {vpc}, {subnet}, {sg}, {zone},
              {bw}, {ipv6}, {eip}, {ict},
              {img}, {host}, {desc},
              {gpu}, {io}, {lop}, {lops},
              {tags}, {pid}, {rgid}, {arf})
             ON CONFLICT(provider, instance_id) DO UPDATE SET
             instance_name = excluded.instance_name,
             account_config_key = excluded.account_config_key,
             region = excluded.region,
             public_ip = excluded.public_ip,
             private_ip = excluded.private_ip,
             os = excluded.os,
             status = excluded.status,
             last_seen_at = excluded.last_seen_at,
             updated_at = excluded.updated_at,
             instance_type = COALESCE(excluded.instance_type, cloud_instances.instance_type),
             cpu_cores = COALESCE(excluded.cpu_cores, cloud_instances.cpu_cores),
             memory_gb = COALESCE(excluded.memory_gb, cloud_instances.memory_gb),
             disk_gb = COALESCE(excluded.disk_gb, cloud_instances.disk_gb),
             created_time = COALESCE(excluded.created_time, cloud_instances.created_time),
             expired_time = COALESCE(excluded.expired_time, cloud_instances.expired_time),
             charge_type = COALESCE(excluded.charge_type, cloud_instances.charge_type),
             vpc_id = COALESCE(excluded.vpc_id, cloud_instances.vpc_id),
             subnet_id = COALESCE(excluded.subnet_id, cloud_instances.subnet_id),
             security_group_ids = COALESCE(excluded.security_group_ids, cloud_instances.security_group_ids),
             zone = COALESCE(excluded.zone, cloud_instances.zone),
             internet_max_bandwidth = COALESCE(excluded.internet_max_bandwidth, cloud_instances.internet_max_bandwidth),
             ipv6_addresses = COALESCE(excluded.ipv6_addresses, cloud_instances.ipv6_addresses),
             eip_allocation_id = COALESCE(excluded.eip_allocation_id, cloud_instances.eip_allocation_id),
             internet_charge_type = COALESCE(excluded.internet_charge_type, cloud_instances.internet_charge_type),
             image_id = COALESCE(excluded.image_id, cloud_instances.image_id),
             hostname = COALESCE(excluded.hostname, cloud_instances.hostname),
             description = COALESCE(excluded.description, cloud_instances.description),
             gpu = COALESCE(excluded.gpu, cloud_instances.gpu),
             io_optimized = COALESCE(excluded.io_optimized, cloud_instances.io_optimized),
             latest_operation = COALESCE(excluded.latest_operation, cloud_instances.latest_operation),
             latest_operation_state = COALESCE(excluded.latest_operation_state, cloud_instances.latest_operation_state),
             tags = COALESCE(excluded.tags, cloud_instances.tags),
             project_id = COALESCE(excluded.project_id, cloud_instances.project_id),
             resource_group_id = COALESCE(excluded.resource_group_id, cloud_instances.resource_group_id),
             auto_renew_flag = COALESCE(excluded.auto_renew_flag, cloud_instances.auto_renew_flag)",
            id = id,
            iid = instance.instance_id.replace('\'', "''"),
            iname = opt_str(&instance.instance_name),
            provider = instance.provider.replace('\'', "''"),
            config_key = instance.account_config_key.replace('\'', "''"),
            region = instance.region.replace('\'', "''"),
            pip = opt_str(&instance.public_ip),
            piv = opt_str(&instance.private_ip),
            os = opt_str(&instance.os),
            status = opt_str(&instance.status),
            last_seen = last_seen_dt,
            created = created_dt,
            updated = created_dt,
            itype = opt_str(&instance.instance_type),
            cpu = opt_i32(instance.cpu_cores),
            mem = opt_f64(instance.memory_gb),
            disk = opt_f64(instance.disk_gb),
            ct = opt_i64_as_str(instance.created_time),
            et = opt_i64_as_str(instance.expired_time),
            charge = opt_str(&instance.charge_type),
            vpc = opt_str(&instance.vpc_id),
            subnet = opt_str(&instance.subnet_id),
            sg = opt_str(&instance.security_group_ids),
            zone = opt_str(&instance.zone),
            bw = opt_i32(instance.internet_max_bandwidth),
            ipv6 = opt_str(&instance.ipv6_addresses),
            eip = opt_str(&instance.eip_allocation_id),
            ict = opt_str(&instance.internet_charge_type),
            img = opt_str(&instance.image_id),
            host = opt_str(&instance.hostname),
            desc = opt_str(&instance.description),
            gpu = opt_i32(instance.gpu),
            io = opt_str(&instance.io_optimized),
            lop = opt_str(&instance.latest_operation),
            lops = opt_str(&instance.latest_operation_state),
            tags = opt_str(&instance.tags),
            pid = opt_str(&instance.project_id),
            rgid = opt_str(&instance.resource_group_id),
            arf = opt_bool_str(&instance.auto_renew_flag),
        );
        self.db()
            .execute_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        Ok(())
    }

    pub async fn list_cloud_instances(
        &self,
        provider: Option<&str>,
        region: Option<&str>,
        status: Option<&str>,
        search: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CloudInstanceRow>> {
        let mut q = InstEntity::find();
        if let Some(p) = provider {
            q = q.filter(InstCol::Provider.eq(p));
        }
        if let Some(r) = region {
            q = q.filter(InstCol::Region.eq(r));
        }
        if let Some(s) = status {
            let normalized = s.trim().to_lowercase();
            if !normalized.is_empty() && normalized != "all" {
                q = q.filter(InstCol::Status.eq(s));
            }
        }
        if let Some(s) = search {
            use sea_orm::Condition;
            q = q.filter(
                Condition::any()
                    .add(InstCol::InstanceId.contains(s))
                    .add(InstCol::InstanceName.contains(s))
                    .add(InstCol::PublicIp.contains(s))
                    .add(InstCol::PrivateIp.contains(s)),
            );
        }
        let rows = q
            .order_by(InstCol::LastSeenAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_instance).collect())
    }

    pub async fn count_cloud_instances(
        &self,
        provider: Option<&str>,
        region: Option<&str>,
        status: Option<&str>,
        search: Option<&str>,
    ) -> Result<u64> {
        let mut q = InstEntity::find();
        if let Some(p) = provider {
            q = q.filter(InstCol::Provider.eq(p));
        }
        if let Some(r) = region {
            q = q.filter(InstCol::Region.eq(r));
        }
        if let Some(s) = status {
            let normalized = s.trim().to_lowercase();
            if !normalized.is_empty() && normalized != "all" {
                q = q.filter(InstCol::Status.eq(s));
            }
        }
        if let Some(s) = search {
            use sea_orm::Condition;
            q = q.filter(
                Condition::any()
                    .add(InstCol::InstanceId.contains(s))
                    .add(InstCol::InstanceName.contains(s))
                    .add(InstCol::PublicIp.contains(s))
                    .add(InstCol::PrivateIp.contains(s)),
            );
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn cloud_instance_status_summary(&self) -> Result<CloudInstanceStatusSummary> {
        use sea_orm::{ConnectionTrait, Statement};
        let sql = "SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN LOWER(COALESCE(status,'')) IN ('running','started','active') THEN 1 ELSE 0 END) AS running,
                SUM(CASE WHEN LOWER(COALESCE(status,'')) IN ('stopped','shutdown') THEN 1 ELSE 0 END) AS stopped,
                SUM(CASE WHEN LOWER(COALESCE(status,'')) IN ('pending','starting','stopping','rebooting') THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN LOWER(COALESCE(status,'')) IN ('error','failed') THEN 1 ELSE 0 END) AS error
             FROM cloud_instances";
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql.to_string(),
            ))
            .await?;
        if let Some(row) = rows.into_iter().next() {
            let total: i64 = row.try_get("", "total")?;
            let running: i64 = row.try_get("", "running")?;
            let stopped: i64 = row.try_get("", "stopped")?;
            let pending: i64 = row.try_get("", "pending")?;
            let error: i64 = row.try_get("", "error")?;
            let unknown = total - running - stopped - pending - error;
            Ok(CloudInstanceStatusSummary {
                total_instances: total as u64,
                running_instances: running as u64,
                stopped_instances: stopped as u64,
                pending_instances: pending as u64,
                error_instances: error as u64,
                unknown_instances: unknown.max(0) as u64,
            })
        } else {
            Ok(CloudInstanceStatusSummary::default())
        }
    }

    pub async fn get_cloud_instance_by_id(&self, id: &str) -> Result<Option<CloudInstanceRow>> {
        let model = InstEntity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(model_to_instance))
    }
}
