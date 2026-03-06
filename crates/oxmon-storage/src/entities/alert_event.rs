use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "alert_events")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub agent_id: String,
    pub metric_name: String,
    pub severity: String,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
    /// Unix 时间戳（毫秒）
    pub timestamp: i64,
    /// Unix 时间戳（毫秒），可选
    pub predicted_breach: Option<i64>,
    /// JSON 序列化的标签 map
    pub labels: String,
    /// Unix 时间戳（毫秒），可选
    pub first_triggered_at: Option<i64>,
    /// 状态：NULL / "acknowledged" / "resolved"
    pub status: Option<String>,
    /// Unix 时间戳（毫秒）
    pub created_at: i64,
    /// Unix 时间戳（毫秒）
    pub updated_at: i64,
}

impl ActiveModelBehavior for ActiveModel {}
