use anyhow::Result;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};

use crate::entities::notification_channel::{self, Column as ChanCol, Entity as ChanEntity};
use crate::entities::notification_log::{self, Column as LogCol, Entity as LogEntity};
use crate::entities::notification_recipient::{self, Column as RecipCol, Entity as RecipEntity};
use crate::entities::notification_silence_window::{
    self, Column as SilenceCol, Entity as SilenceEntity,
};
use crate::store::CertStore;

/// 通知渠道数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannelRow {
    pub id: String,
    pub name: String,
    pub channel_type: String,
    pub description: Option<String>,
    pub min_severity: String,
    pub enabled: bool,
    pub config_json: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 通知渠道更新请求
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationChannelUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub min_severity: Option<String>,
    pub enabled: Option<bool>,
    pub config_json: Option<String>,
    /// 可选：同时更新收件人列表（会替换现有收件人）
    pub recipients: Option<Vec<String>>,
}

/// 通知渠道过滤条件
#[derive(Debug, Clone, Default)]
pub struct NotificationChannelFilter {
    pub name_contains: Option<String>,
    pub channel_type_eq: Option<String>,
    pub enabled_eq: Option<bool>,
    pub min_severity_eq: Option<String>,
}

/// 收件人数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecipientRow {
    pub id: String,
    pub channel_id: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
}

/// 静默窗口数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilenceWindowRow {
    pub id: String,
    pub start_time: String,
    pub end_time: String,
    pub recurrence: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 静默窗口过滤条件
#[derive(Debug, Clone, Default)]
pub struct SilenceWindowFilter {
    pub recurrence_eq: Option<String>,
}

/// 通知日志数据行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationLogRow {
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
    pub created_at: DateTime<Utc>,
    pub http_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub request_body: Option<String>,
    pub retry_count: i32,
    pub recipient_details: Option<String>,
    pub api_message_id: Option<String>,
    pub api_error_code: Option<String>,
}

/// 通知日志过滤条件
#[derive(Debug, Clone, Default)]
pub struct NotificationLogFilter {
    pub channel_id: Option<String>,
    pub channel_type: Option<String>,
    pub status: Option<String>,
    pub alert_event_id: Option<String>,
    pub rule_id: Option<String>,
    pub agent_id: Option<String>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
}

/// 活跃告警过滤条件
#[derive(Debug, Clone, Default)]
pub struct ActiveAlertFilter {
    pub agent_id_eq: Option<String>,
    pub severity_eq: Option<String>,
    pub rule_id_eq: Option<String>,
    pub metric_name_eq: Option<String>,
    pub timestamp_gte: Option<i64>,
}

fn model_to_channel(m: notification_channel::Model) -> NotificationChannelRow {
    NotificationChannelRow {
        id: m.id,
        name: m.name,
        channel_type: m.channel_type,
        description: m.description,
        min_severity: m.min_severity,
        enabled: m.enabled,
        config_json: m.config_json,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

fn model_to_recipient(m: notification_recipient::Model) -> NotificationRecipientRow {
    NotificationRecipientRow {
        id: m.id,
        channel_id: m.channel_id,
        value: m.value,
        created_at: m.created_at.with_timezone(&Utc),
    }
}

fn model_to_silence(m: notification_silence_window::Model) -> SilenceWindowRow {
    SilenceWindowRow {
        id: m.id,
        start_time: m.start_time,
        end_time: m.end_time,
        recurrence: m.recurrence,
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

fn model_to_log(m: notification_log::Model) -> NotificationLogRow {
    NotificationLogRow {
        id: m.id,
        alert_event_id: m.alert_event_id,
        rule_id: m.rule_id,
        rule_name: m.rule_name,
        agent_id: m.agent_id,
        channel_id: m.channel_id,
        channel_name: m.channel_name,
        channel_type: m.channel_type,
        status: m.status,
        error_message: m.error_message,
        duration_ms: m.duration_ms,
        recipient_count: m.recipient_count,
        severity: m.severity,
        created_at: m.created_at.with_timezone(&Utc),
        http_status_code: m.http_status_code,
        response_body: m.response_body,
        request_body: m.request_body,
        retry_count: m.retry_count,
        recipient_details: m.recipient_details,
        api_message_id: m.api_message_id,
        api_error_code: m.api_error_code,
    }
}

impl CertStore {
    // ---- notification_channels ----

    pub async fn insert_notification_channel(
        &self,
        ch: &NotificationChannelRow,
    ) -> Result<NotificationChannelRow> {
        let now = Utc::now().fixed_offset();
        let am = notification_channel::ActiveModel {
            id: Set(ch.id.clone()),
            name: Set(ch.name.clone()),
            channel_type: Set(ch.channel_type.clone()),
            description: Set(ch.description.clone()),
            min_severity: Set(ch.min_severity.clone()),
            enabled: Set(ch.enabled),
            config_json: Set(ch.config_json.clone()),
            system_config_id: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let model = am.insert(self.db()).await?;
        Ok(model_to_channel(model))
    }

    pub async fn get_notification_channel_by_id(
        &self,
        id: &str,
    ) -> Result<Option<NotificationChannelRow>> {
        let model = ChanEntity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(model_to_channel))
    }

    pub async fn list_notification_channels(
        &self,
        filter: &NotificationChannelFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<NotificationChannelRow>> {
        let mut q = ChanEntity::find();
        if let Some(ref s) = filter.name_contains {
            q = q.filter(ChanCol::Name.contains(s.as_str()));
        }
        if let Some(ref ct) = filter.channel_type_eq {
            q = q.filter(ChanCol::ChannelType.eq(ct.as_str()));
        }
        if let Some(en) = filter.enabled_eq {
            q = q.filter(ChanCol::Enabled.eq(en));
        }
        if let Some(ref sev) = filter.min_severity_eq {
            q = q.filter(ChanCol::MinSeverity.eq(sev.as_str()));
        }
        let rows = q
            .order_by(ChanCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_channel).collect())
    }

    pub async fn count_notification_channels(
        &self,
        filter: &NotificationChannelFilter,
    ) -> Result<u64> {
        let mut q = ChanEntity::find();
        if let Some(ref s) = filter.name_contains {
            q = q.filter(ChanCol::Name.contains(s.as_str()));
        }
        if let Some(ref ct) = filter.channel_type_eq {
            q = q.filter(ChanCol::ChannelType.eq(ct.as_str()));
        }
        if let Some(en) = filter.enabled_eq {
            q = q.filter(ChanCol::Enabled.eq(en));
        }
        if let Some(ref sev) = filter.min_severity_eq {
            q = q.filter(ChanCol::MinSeverity.eq(sev.as_str()));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn update_notification_channel(
        &self,
        id: &str,
        upd: &NotificationChannelUpdate,
    ) -> Result<Option<NotificationChannelRow>> {
        let model = ChanEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: notification_channel::ActiveModel = m.into();
            if let Some(ref name) = upd.name {
                am.name = Set(name.clone());
            }
            if let Some(ref desc) = upd.description {
                am.description = Set(Some(desc.clone()));
            }
            if let Some(ref sev) = upd.min_severity {
                am.min_severity = Set(sev.clone());
            }
            if let Some(en) = upd.enabled {
                am.enabled = Set(en);
            }
            if let Some(ref cj) = upd.config_json {
                am.config_json = Set(cj.clone());
            }
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            if let Some(ref recipients) = upd.recipients {
                self.set_channel_recipients(id, recipients).await?;
            }
            Ok(Some(model_to_channel(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_notification_channel(&self, id: &str) -> Result<bool> {
        let res = ChanEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn list_enabled_channels_with_recipients(
        &self,
    ) -> Result<Vec<(NotificationChannelRow, Vec<String>)>> {
        let channels = ChanEntity::find()
            .filter(ChanCol::Enabled.eq(true))
            .order_by(ChanCol::CreatedAt, Order::Asc)
            .all(self.db())
            .await?;

        let mut result = Vec::with_capacity(channels.len());
        for ch in channels {
            let ch_row = model_to_channel(ch);
            let recipients = self
                .list_recipients_by_channel(&ch_row.id)
                .await?
                .into_iter()
                .map(|r| r.value)
                .collect();
            result.push((ch_row, recipients));
        }
        Ok(result)
    }

    // ---- notification_recipients ----

    pub async fn insert_recipient(
        &self,
        channel_id: &str,
        value: &str,
    ) -> Result<NotificationRecipientRow> {
        let id = oxmon_common::id::next_id();
        let now = Utc::now().fixed_offset();
        let am = notification_recipient::ActiveModel {
            id: Set(id.clone()),
            channel_id: Set(channel_id.to_owned()),
            value: Set(value.to_owned()),
            created_at: Set(now),
        };
        let model = am.insert(self.db()).await?;
        Ok(model_to_recipient(model))
    }

    pub async fn list_recipients_by_channel(
        &self,
        channel_id: &str,
    ) -> Result<Vec<NotificationRecipientRow>> {
        let rows = RecipEntity::find()
            .filter(RecipCol::ChannelId.eq(channel_id))
            .order_by(RecipCol::CreatedAt, Order::Asc)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_recipient).collect())
    }

    pub async fn list_recipients_by_channel_paged(
        &self,
        channel_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<NotificationRecipientRow>> {
        let rows = RecipEntity::find()
            .filter(RecipCol::ChannelId.eq(channel_id))
            .order_by(RecipCol::CreatedAt, Order::Asc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_recipient).collect())
    }

    pub async fn count_recipients_by_channel(&self, channel_id: &str) -> Result<u64> {
        Ok(RecipEntity::find()
            .filter(RecipCol::ChannelId.eq(channel_id))
            .count(self.db())
            .await?)
    }

    pub async fn delete_recipient(&self, id: &str) -> Result<bool> {
        let res = RecipEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn set_channel_recipients(
        &self,
        channel_id: &str,
        values: &[String],
    ) -> Result<Vec<NotificationRecipientRow>> {
        // Delete existing recipients
        RecipEntity::delete_many()
            .filter(RecipCol::ChannelId.eq(channel_id))
            .exec(self.db())
            .await?;

        let now = Utc::now().fixed_offset();
        let mut results = Vec::with_capacity(values.len());
        for value in values {
            let id = oxmon_common::id::next_id();
            let am = notification_recipient::ActiveModel {
                id: Set(id.clone()),
                channel_id: Set(channel_id.to_owned()),
                value: Set(value.clone()),
                created_at: Set(now),
            };
            am.insert(self.db()).await?;
            results.push(NotificationRecipientRow {
                id,
                channel_id: channel_id.to_string(),
                value: value.clone(),
                created_at: now.with_timezone(&Utc),
            });
        }
        Ok(results)
    }

    // ---- notification_silence_windows ----

    pub async fn insert_silence_window(&self, sw: &SilenceWindowRow) -> Result<SilenceWindowRow> {
        let now = Utc::now().fixed_offset();
        let am = notification_silence_window::ActiveModel {
            id: Set(sw.id.clone()),
            start_time: Set(sw.start_time.clone()),
            end_time: Set(sw.end_time.clone()),
            recurrence: Set(sw.recurrence.clone()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        let model = am.insert(self.db()).await?;
        Ok(model_to_silence(model))
    }

    pub async fn get_silence_window_by_id(&self, id: &str) -> Result<Option<SilenceWindowRow>> {
        let model = SilenceEntity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(model_to_silence))
    }

    pub async fn list_silence_windows(
        &self,
        filter: &SilenceWindowFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<SilenceWindowRow>> {
        let mut q = SilenceEntity::find();
        if let Some(ref rec) = filter.recurrence_eq {
            q = q.filter(SilenceCol::Recurrence.eq(rec.as_str()));
        }
        let rows = q
            .order_by(SilenceCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_silence).collect())
    }

    pub async fn count_silence_windows(&self, recurrence: Option<&str>) -> Result<u64> {
        let mut q = SilenceEntity::find();
        if let Some(rec) = recurrence {
            q = q.filter(SilenceCol::Recurrence.eq(rec));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn update_silence_window(
        &self,
        id: &str,
        start_time: Option<&str>,
        end_time: Option<&str>,
        recurrence: Option<Option<&str>>,
    ) -> Result<Option<SilenceWindowRow>> {
        let model = SilenceEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: notification_silence_window::ActiveModel = m.into();
            if let Some(s) = start_time {
                am.start_time = Set(s.to_owned());
            }
            if let Some(e) = end_time {
                am.end_time = Set(e.to_owned());
            }
            if let Some(r) = recurrence {
                am.recurrence = Set(r.map(|s| s.to_owned()));
            }
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            Ok(Some(model_to_silence(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_silence_window(&self, id: &str) -> Result<bool> {
        let res = SilenceEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn list_all_silence_windows(&self) -> Result<Vec<SilenceWindowRow>> {
        let rows = SilenceEntity::find()
            .order_by(SilenceCol::CreatedAt, Order::Asc)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_silence).collect())
    }

    // ---- notification_logs ----

    pub async fn insert_notification_log(&self, log: &NotificationLogRow) -> Result<()> {
        let now = Utc::now().fixed_offset();
        let am = notification_log::ActiveModel {
            id: Set(log.id.clone()),
            alert_event_id: Set(log.alert_event_id.clone()),
            rule_id: Set(log.rule_id.clone()),
            rule_name: Set(log.rule_name.clone()),
            agent_id: Set(log.agent_id.clone()),
            channel_id: Set(log.channel_id.clone()),
            channel_name: Set(log.channel_name.clone()),
            channel_type: Set(log.channel_type.clone()),
            status: Set(log.status.clone()),
            error_message: Set(log.error_message.clone()),
            duration_ms: Set(log.duration_ms),
            recipient_count: Set(log.recipient_count),
            severity: Set(log.severity.clone()),
            http_status_code: Set(log.http_status_code),
            response_body: Set(log.response_body.clone()),
            request_body: Set(log.request_body.clone()),
            retry_count: Set(log.retry_count),
            recipient_details: Set(log.recipient_details.clone()),
            api_message_id: Set(log.api_message_id.clone()),
            api_error_code: Set(log.api_error_code.clone()),
            created_at: Set(now),
        };
        am.insert(self.db()).await?;
        Ok(())
    }

    pub async fn list_notification_logs(
        &self,
        filter: &NotificationLogFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<NotificationLogRow>> {
        let mut q = LogEntity::find();
        q = apply_log_filter(q, filter);
        let rows = q
            .order_by(LogCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_log).collect())
    }

    pub async fn count_notification_logs(&self, filter: &NotificationLogFilter) -> Result<u64> {
        let mut q = LogEntity::find();
        q = apply_log_filter(q, filter);
        Ok(q.count(self.db()).await?)
    }

    pub async fn get_notification_log_by_id(&self, id: &str) -> Result<Option<NotificationLogRow>> {
        let model = LogEntity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(model_to_log))
    }

    pub async fn cleanup_notification_logs(&self, retention_days: u32) -> Result<u64> {
        use sea_orm::{ConnectionTrait, Statement};
        let cutoff = chrono::Duration::days(retention_days as i64);
        let cutoff_dt = (Utc::now() - cutoff).fixed_offset();
        let sql = format!(
            "DELETE FROM notification_logs WHERE created_at < '{}'",
            cutoff_dt.to_rfc3339()
        );
        let result = self
            .db()
            .execute_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        Ok(result.rows_affected())
    }
}

type LogSelect = sea_orm::Select<crate::entities::notification_log::Entity>;

fn apply_log_filter(mut q: LogSelect, filter: &NotificationLogFilter) -> LogSelect {
    if let Some(ref v) = filter.channel_id {
        q = q.filter(LogCol::ChannelId.eq(v.as_str()));
    }
    if let Some(ref v) = filter.channel_type {
        q = q.filter(LogCol::ChannelType.eq(v.as_str()));
    }
    if let Some(ref v) = filter.status {
        q = q.filter(LogCol::Status.eq(v.as_str()));
    }
    if let Some(ref v) = filter.alert_event_id {
        q = q.filter(LogCol::AlertEventId.eq(v.as_str()));
    }
    if let Some(ref v) = filter.rule_id {
        q = q.filter(LogCol::RuleId.eq(v.as_str()));
    }
    if let Some(ref v) = filter.agent_id {
        q = q.filter(LogCol::AgentId.eq(v.as_str()));
    }
    if let Some(start) = filter.start_time {
        if let Some(dt) = chrono::DateTime::<Utc>::from_timestamp(start, 0) {
            q = q.filter(LogCol::CreatedAt.gte(dt.fixed_offset()));
        }
    }
    if let Some(end) = filter.end_time {
        if let Some(dt) = chrono::DateTime::<Utc>::from_timestamp(end, 0) {
            q = q.filter(LogCol::CreatedAt.lte(dt.fixed_offset()));
        }
    }
    q
}
