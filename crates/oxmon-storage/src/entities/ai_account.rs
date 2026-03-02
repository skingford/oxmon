use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "ai_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub config_key: String,
    pub provider: String,
    pub display_name: String,
    pub description: Option<String>,
    pub api_key: String,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_mode: Option<String>,
    pub timeout_secs: Option<i32>,
    pub max_tokens: Option<i32>,
    pub temperature: Option<f32>,
    pub collection_interval_secs: Option<i32>,
    pub enabled: bool,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
