use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "system_dictionaries")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub dict_type: String,
    pub dict_key: String,
    pub dict_label: String,
    pub dict_value: Option<String>,
    pub sort_order: i32,
    pub enabled: bool,
    pub is_system: bool,
    pub description: Option<String>,
    pub extra_json: Option<String>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
