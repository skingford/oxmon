use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "cloud_instances")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
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
    pub instance_type: Option<String>,
    pub cpu_cores: Option<i32>,
    pub memory_gb: Option<f32>,
    pub disk_gb: Option<f32>,
    pub created_time: Option<String>,
    pub expired_time: Option<String>,
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
    pub auto_renew_flag: Option<bool>,
    pub last_seen_at: DateTimeWithTimeZone,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
