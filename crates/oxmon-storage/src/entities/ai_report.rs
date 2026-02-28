use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "ai_reports")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub report_date: String,
    pub ai_account_id: String,
    pub ai_provider: String,
    pub ai_model: String,
    pub total_agents: i32,
    pub risk_level: String,
    pub ai_analysis: String,
    pub html_content: String,
    pub raw_metrics_json: String,
    pub notified: bool,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
