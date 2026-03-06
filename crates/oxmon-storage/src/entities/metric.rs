use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "metrics")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    /// Unix 时间戳（毫秒）
    pub timestamp: i64,
    pub agent_id: String,
    pub metric_name: String,
    pub value: f64,
    /// JSON 序列化的标签 map
    pub labels: String,
    /// Unix 时间戳（毫秒）
    pub created_at: i64,
    /// Unix 时间戳（毫秒）
    pub updated_at: i64,
}

impl ActiveModelBehavior for ActiveModel {}
