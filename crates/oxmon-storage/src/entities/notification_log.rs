use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "notification_logs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub alert_event_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub agent_id: String,
    pub channel_id: String,
    pub channel_name: String,
    pub channel_type: String,
    pub status: String,
    pub error_message: Option<String>,
    pub duration_ms: i64,
    pub recipient_count: i32,
    pub severity: String,
    pub http_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub request_body: Option<String>,
    pub retry_count: i32,
    pub recipient_details: Option<String>,
    pub api_message_id: Option<String>,
    pub api_error_code: Option<String>,
    pub created_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
