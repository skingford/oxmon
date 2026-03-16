use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "instance_contacts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    /// JSON 数组，多个 glob pattern，如 ["prod-web-*","cloud:tencent:ins-*"]
    pub agent_patterns: String,
    pub contact_name: String,
    pub contact_email: Option<String>,
    pub contact_phone: Option<String>,
    /// 钉钉 Webhook URL
    pub contact_dingtalk: Option<String>,
    /// 通用 Webhook URL（webhook/weixin 等）
    pub contact_webhook: Option<String>,
    pub enabled: bool,
    pub description: Option<String>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
