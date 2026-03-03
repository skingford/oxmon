use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "ai_check_jobs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    /// 任务类型："cloud_all" | "cloud_instance:{db_id}"
    pub job_type: String,
    /// 任务状态："running" | "succeeded" | "failed"
    pub status: String,
    pub ai_account_id: String,
    /// 成功后填入的报告 ID
    pub report_id: Option<String>,
    /// 失败时的错误信息
    pub error_message: Option<String>,
    pub started_at: DateTimeWithTimeZone,
    pub finished_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
}

impl ActiveModelBehavior for ActiveModel {}
