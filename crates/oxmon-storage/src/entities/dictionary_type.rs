use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "dictionary_types")]
pub struct Model {
    /// dict_type 同时是主键
    #[sea_orm(primary_key, auto_increment = false)]
    pub dict_type: String,
    pub dict_type_label: String,
    pub sort_order: i32,
    pub description: Option<String>,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
