use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "agent_report_logs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub agent_id: String,
    pub metric_count: i32,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub arch: Option<String>,
    pub kernel_version: Option<String>,
    pub cpu_cores: Option<i32>,
    pub memory_gb: Option<f64>,
    pub disk_gb: Option<f64>,
    pub reported_at: DateTimeWithTimeZone,
    pub created_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
