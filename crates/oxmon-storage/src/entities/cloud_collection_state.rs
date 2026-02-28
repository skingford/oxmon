use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cloud_collection_state")]
pub struct Model {
    /// config_key 作为主键
    #[sea_orm(primary_key, auto_increment = false)]
    pub config_key: String,
    pub last_collected_at: DateTimeWithTimeZone,
    pub last_instance_count: i32,
    pub last_error: Option<String>,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
