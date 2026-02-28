use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "cert_check_results")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub domain_id: String,
    pub domain: String,
    pub is_valid: bool,
    pub chain_valid: bool,
    pub not_before: Option<DateTimeWithTimeZone>,
    pub not_after: Option<DateTimeWithTimeZone>,
    pub days_until_expiry: Option<i32>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub san_list: Option<String>,
    pub resolved_ips: Option<String>,
    pub error: Option<String>,
    pub checked_at: DateTimeWithTimeZone,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
