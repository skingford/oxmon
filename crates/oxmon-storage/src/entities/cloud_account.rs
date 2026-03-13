use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "cloud_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    #[sea_orm(unique)]
    pub config_key: String,
    pub provider: String,
    pub display_name: String,
    pub description: Option<String>,
    pub account_name: String,
    pub secret_id: String,
    pub secret_key: String,
    pub regions: String,
    pub endpoint: Option<String>,
    /// AWS4 签名使用的 region（深信服 SCP 专用，默认 regionOne）
    pub region_for_sign: Option<String>,
    /// 深信服 SCP 6.3.0 及更早版本需要的 Cookie 认证 Token（SCP 6.3.70+ 无需）
    pub scp_auth_token: Option<String>,
    pub collection_interval_secs: i64,
    pub enabled: bool,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
