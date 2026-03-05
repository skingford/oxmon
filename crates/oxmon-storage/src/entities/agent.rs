use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "agents")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub agent_id: String,
    pub first_seen: DateTimeWithTimeZone,
    pub last_seen: DateTimeWithTimeZone,
    pub collection_interval_secs: Option<i64>,
    pub description: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub arch: Option<String>,
    pub kernel_version: Option<String>,
    pub cpu_cores: Option<i32>,
    pub memory_gb: Option<f64>,
    pub disk_gb: Option<f64>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
