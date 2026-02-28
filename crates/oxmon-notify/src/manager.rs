use crate::cert_report_template::{CertAlertDetail, CertReportParams, CertReportRenderer};
use crate::plugin::ChannelRegistry;
use crate::utils::{redact_json_string, truncate_string, MAX_BODY_LENGTH};
use crate::NotificationChannel;
use chrono::{DateTime, Duration, NaiveTime, Utc};
use oxmon_common::types::AlertEvent;
use oxmon_storage::{CertStore, NotificationChannelRow, NotificationLogRow, SilenceWindowFilter};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing;

/// 将接收者结果列表序列化为 JSON 字符串
fn serialize_recipient_results(response: &SendResponse) -> Option<String> {
    if response.recipient_results.is_empty() {
        return None;
    }
    serde_json::to_string(&response.recipient_results).ok()
}

pub struct SilenceWindow {
    pub start: NaiveTime,
    pub end: NaiveTime,
    pub recurrence: Option<String>,
}

impl SilenceWindow {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        let current_time = now.time();
        if self.start <= self.end {
            current_time >= self.start && current_time <= self.end
        } else {
            // Overnight window (e.g., 23:00 - 03:00)
            current_time >= self.start || current_time <= self.end
        }
    }
}

/// A loaded channel instance with its associated recipients.
struct ChannelInstance {
    channel: Box<dyn NotificationChannel>,
    recipients: Vec<String>,
    min_severity: oxmon_common::types::Severity,
    name: String,
    channel_type: String,
}

struct AggregationEntry {
    events: Vec<AlertEvent>,
    first_seen: DateTime<Utc>,
}

/// 单个接收者的发送结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecipientResult {
    pub recipient: String,
    pub status: String, // "success" | "failed"
    pub error: Option<String>,
}

/// 通知发送的详细响应信息
#[derive(Debug, Clone, Default)]
pub struct SendResponse {
    pub http_status: Option<u16>,
    pub response_body: Option<String>,
    pub request_body: Option<String>,
    pub retry_count: u32,
    pub recipient_results: Vec<RecipientResult>,
    pub api_message_id: Option<String>,
    pub api_error_code: Option<String>,
}

/// 通知发送结果上下文，用于记录日志。
pub struct SendLogContext<'a> {
    pub channel_id: &'a str,
    pub channel_name: &'a str,
    pub channel_type: &'a str,
    pub duration_ms: i64,
    pub recipient_count: i32,
    pub response: Option<SendResponse>,
}

pub struct NotificationManager {
    /// channel_id -> ChannelInstance
    instances: RwLock<HashMap<String, ChannelInstance>>,
    registry: ChannelRegistry,
    cert_store: Arc<CertStore>,
    aggregation_window_secs: u64,
    pending: Mutex<HashMap<String, AggregationEntry>>,
}

/// Check whether a JSON value represents a meaningful (non-empty) configuration.
/// An empty object `{}` or null is not considered meaningful.
pub fn is_meaningful_config(config: &serde_json::Value) -> bool {
    match config {
        serde_json::Value::Object(map) => !map.is_empty(),
        _ => false,
    }
}

/// Parse a config_json string into a serde_json::Value.
/// Returns None if parsing fails or the input is empty.
pub fn parse_config_json(raw: &str) -> Option<serde_json::Value> {
    if raw.trim().is_empty() {
        return None;
    }
    serde_json::from_str(raw).ok()
}

/// Resolve the effective configuration for a notification channel.
///
/// Returns the channel's `config_json` if non-empty, otherwise None (channel should be skipped).
pub fn resolve_config(
    _cert_store: &CertStore,
    row: &NotificationChannelRow,
) -> Option<serde_json::Value> {
    if let Some(cfg) = parse_config_json(&row.config_json) {
        if is_meaningful_config(&cfg) {
            tracing::debug!(
                channel_id = %row.id,
                name = %row.name,
                "Using channel-level config"
            );
            return Some(cfg);
        }
    }

    // No config available
    tracing::warn!(
        channel_id = %row.id,
        channel_type = %row.channel_type,
        name = %row.name,
        "Channel has no valid config_json, skipping"
    );
    None
}

impl NotificationManager {
    pub fn new(
        registry: ChannelRegistry,
        cert_store: Arc<CertStore>,
        aggregation_window_secs: u64,
    ) -> Self {
        Self {
            instances: RwLock::new(HashMap::new()),
            registry,
            cert_store,
            aggregation_window_secs,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// 从数据库重新加载所有已启用的通知渠道。
    /// 使用 build-then-swap 模式：先构建新实例表，再整体替换。
    pub async fn reload(&self) -> anyhow::Result<()> {
        let channels_with_recipients = self.cert_store.list_enabled_channels_with_recipients().await?;

        let mut new_instances = HashMap::new();
        for (row, recipients) in channels_with_recipients {
            // 配置优先级: 渠道自身 config_json > 全局 system_config > 跳过
            let config = match resolve_config(&self.cert_store, &row) {
                Some(cfg) => cfg,
                None => continue,
            };

            match self
                .registry
                .create_channel(&row.channel_type, &row.id, &config)
            {
                Ok(channel) => {
                    let severity = row
                        .min_severity
                        .parse()
                        .unwrap_or(oxmon_common::types::Severity::Info);
                    new_instances.insert(
                        row.id.clone(),
                        ChannelInstance {
                            channel,
                            recipients,
                            min_severity: severity,
                            name: row.name.clone(),
                            channel_type: row.channel_type.clone(),
                        },
                    );
                    tracing::info!(
                        channel_id = %row.id,
                        channel_type = %row.channel_type,
                        name = %row.name,
                        "Loaded notification channel"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        channel_id = %row.id,
                        channel_type = %row.channel_type,
                        error = %e,
                        "Failed to create notification channel, skipping"
                    );
                }
            }
        }

        let count = new_instances.len();
        {
            let mut guard = self.instances.write().await;
            *guard = new_instances;
        }

        tracing::info!(count = count, "Notification channels reloaded");
        Ok(())
    }

    /// Aggregation key: group by rule_id
    fn aggregation_key(event: &AlertEvent) -> String {
        event.rule_id.clone()
    }

    pub async fn notify(&self, event: &AlertEvent) {
        let now = Utc::now();

        // Check silence windows from DB
        if let Ok(windows) = self.cert_store.list_silence_windows(&SilenceWindowFilter { recurrence_eq: None }, 100, 0).await {
            for sw in &windows {
                if let (Ok(start), Ok(end)) = (
                    NaiveTime::parse_from_str(&sw.start_time, "%H:%M"),
                    NaiveTime::parse_from_str(&sw.end_time, "%H:%M"),
                ) {
                    let window = SilenceWindow {
                        start,
                        end,
                        recurrence: sw.recurrence.clone(),
                    };
                    if window.is_active(now) {
                        tracing::info!(
                            rule_id = %event.rule_id,
                            "Notification suppressed (silence window active)"
                        );
                        return;
                    }
                }
            }
        }

        if self.aggregation_window_secs == 0 {
            self.send_to_channels(event).await;
            return;
        }

        // Aggregation: buffer similar alerts
        let key = Self::aggregation_key(event);
        let mut pending = self.pending.lock().await;

        let entry = pending.entry(key).or_insert_with(|| AggregationEntry {
            events: Vec::new(),
            first_seen: now,
        });
        entry.events.push(event.clone());

        let window = Duration::seconds(self.aggregation_window_secs as i64);
        if now - entry.first_seen >= window {
            let events = std::mem::take(&mut entry.events);
            let first_seen = entry.first_seen;
            drop(pending);
            {
                let mut pending = self.pending.lock().await;
                pending.remove(&Self::aggregation_key(event));
            }

            if events.len() == 1 {
                self.send_to_channels(&events[0]).await;
            } else {
                let summary = AlertEvent {
                    id: format!("agg-{}-{}", events[0].rule_id, now.timestamp_millis()),
                    rule_id: events[0].rule_id.clone(),
                    rule_name: events[0].rule_name.clone(),
                    agent_id: if events.iter().all(|e| e.agent_id == events[0].agent_id) {
                        events[0].agent_id.clone()
                    } else {
                        format!(
                            "{} agents",
                            events
                                .iter()
                                .map(|e| &e.agent_id)
                                .collect::<std::collections::HashSet<_>>()
                                .len()
                        )
                    },
                    metric_name: events[0].metric_name.clone(),
                    severity: events
                        .iter()
                        .map(|e| e.severity)
                        .max()
                        .unwrap_or(events[0].severity),
                    message: format!(
                        "{} similar alerts aggregated since {}: {}",
                        events.len(),
                        first_seen.format("%H:%M:%S"),
                        events[0].message,
                    ),
                    value: events.last().map(|e| e.value).unwrap_or(0.0),
                    threshold: events[0].threshold,
                    timestamp: now,
                    predicted_breach: None,
                    status: 1,
                    labels: events[0].labels.clone(),
                    first_triggered_at: None,
                    created_at: now,
                    updated_at: now,
                };
                self.send_to_channels(&summary).await;
            }
        }
    }

    async fn send_to_channels(&self, event: &AlertEvent) {
        let locale = self
            .cert_store
            .get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE)
            .await;
        let instances = self.instances.read().await;
        for (channel_id, instance) in instances.iter() {
            if event.severity < instance.min_severity {
                continue;
            }

            let start = Instant::now();
            let result = instance
                .channel
                .send(event, &instance.recipients, &locale)
                .await;
            let duration_ms = start.elapsed().as_millis() as i64;

            let (send_result, response) = match result {
                Ok(resp) => (Ok(()), Some(resp)),
                Err(e) => {
                    tracing::error!(
                        channel_id = %channel_id,
                        channel_type = %instance.channel_type,
                        error = %e,
                        "Failed to send notification"
                    );
                    (Err(anyhow::anyhow!("{e}")), None)
                }
            };

            let ctx = SendLogContext {
                channel_id,
                channel_name: &instance.name,
                channel_type: &instance.channel_type,
                duration_ms,
                recipient_count: instance.recipients.len() as i32,
                response,
            };
            Self::record_send_log(&self.cert_store, event, &ctx, &send_result).await;
        }
    }

    /// 记录一条通知发送日志。
    /// 供内部 `send_to_channels` 及外部 API（如测试通知）统一调用。
    /// 写入失败仅 warn，不影响调用方逻辑。
    pub async fn record_send_log(
        cert_store: &CertStore,
        event: &AlertEvent,
        ctx: &SendLogContext<'_>,
        send_result: &Result<(), anyhow::Error>,
    ) {
        let (status, error_message) = match send_result {
            Ok(()) => ("success", None),
            Err(e) => ("failed", Some(e.to_string())),
        };

        // 从 SendResponse 提取详细信息
        let (
            http_status,
            response_body,
            request_body,
            retry_count,
            recipient_details,
            api_message_id,
            api_error_code,
        ) = if let Some(ref resp) = ctx.response {
            // 脱敏并截断 request_body
            let redacted_request = resp.request_body.as_ref().map(|s| {
                let redacted = redact_json_string(s);
                truncate_string(&redacted, MAX_BODY_LENGTH)
            });

            (
                resp.http_status.map(|s| s as i32),
                resp.response_body
                    .as_ref()
                    .map(|s| truncate_string(s, MAX_BODY_LENGTH)),
                redacted_request,
                resp.retry_count as i32,
                serialize_recipient_results(resp),
                resp.api_message_id.clone(),
                resp.api_error_code.clone(),
            )
        } else {
            (None, None, None, 0, None, None, None)
        };

        let log = NotificationLogRow {
            id: oxmon_common::id::next_id(),
            alert_event_id: event.id.clone(),
            rule_id: event.rule_id.clone(),
            rule_name: event.rule_name.clone(),
            agent_id: event.agent_id.clone(),
            channel_id: ctx.channel_id.to_string(),
            channel_name: ctx.channel_name.to_string(),
            channel_type: ctx.channel_type.to_string(),
            status: status.to_string(),
            error_message,
            duration_ms: ctx.duration_ms,
            recipient_count: ctx.recipient_count,
            severity: event.severity.to_string(),
            created_at: Utc::now(),
            http_status_code: http_status,
            response_body,
            request_body,
            retry_count,
            recipient_details,
            api_message_id,
            api_error_code,
        };

        if let Err(e) = cert_store.insert_notification_log(&log).await {
            tracing::warn!(
                channel_id = %ctx.channel_id,
                error = %e,
                "Failed to write notification log"
            );
        }
    }

    /// 发送证书告警批量报告。
    ///
    /// 将本次检查周期内所有触发告警的域名汇总为一条通知发送，
    /// 而非每个域名单独发一条。
    ///
    /// - Email 渠道：发送 HTML 格式报告
    /// - 钉钉/企业微信渠道：发送 Markdown 格式报告
    /// - 其他渠道：发送纯文本格式（通过 `send` 接口）
    pub async fn send_cert_report(
        &self,
        alert_items: &[CertAlertDetail],
        total_checked: i32,
        report_date: &str,
        locale: &str,
    ) {
        if alert_items.is_empty() {
            return;
        }

        let now = Utc::now();

        // 检查静默窗口
        if let Ok(windows) = self.cert_store.list_silence_windows(&SilenceWindowFilter { recurrence_eq: None }, 100, 0).await {
            for sw in &windows {
                if let (Ok(start), Ok(end)) = (
                    NaiveTime::parse_from_str(&sw.start_time, "%H:%M"),
                    NaiveTime::parse_from_str(&sw.end_time, "%H:%M"),
                ) {
                    let window = SilenceWindow { start, end, recurrence: sw.recurrence.clone() };
                    if window.is_active(now) {
                        tracing::info!("Cert report suppressed (silence window active)");
                        return;
                    }
                }
            }
        }

        let params = CertReportParams {
            report_date,
            total_checked,
            alert_items,
            locale,
        };

        // 渲染三种格式
        let html_content = match CertReportRenderer::render_html(&params) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, "Failed to render cert report HTML");
                String::new()
            }
        };
        let markdown_content = CertReportRenderer::render_markdown(&params);
        let plain_content = CertReportRenderer::render_plain(&params);

        let alert_count = alert_items.len();
        let subject = if locale == "zh-CN" {
            format!(
                "[oxmon][证书告警] {} | {} 个域名告警",
                report_date, alert_count
            )
        } else {
            format!(
                "[oxmon][Cert Alert] {} | {} domain(s) alerting",
                report_date, alert_count
            )
        };

        // 构建兜底用的合成 AlertEvent（供不支持 send_cert_report 的渠道使用）
        let max_severity = alert_items
            .iter()
            .map(|d| match d.severity.as_str() {
                "critical" => oxmon_common::types::Severity::Critical,
                "warning" => oxmon_common::types::Severity::Warning,
                _ => oxmon_common::types::Severity::Info,
            })
            .max()
            .unwrap_or(oxmon_common::types::Severity::Warning);

        let mut labels = std::collections::HashMap::new();
        labels.insert("report_date".to_string(), report_date.to_string());
        labels.insert("alert_count".to_string(), alert_count.to_string());

        let fallback_event = oxmon_common::types::AlertEvent {
            id: format!("cert-report-{}", now.timestamp_millis()),
            rule_id: "cert-alert-report".to_string(),
            rule_name: subject.clone(),
            agent_id: "cert-checker".to_string(),
            metric_name: "certificate.report".to_string(),
            severity: max_severity,
            message: plain_content.clone(),
            value: alert_count as f64,
            threshold: 0.0,
            timestamp: now,
            predicted_breach: None,
            status: 1,
            labels,
            first_triggered_at: None,
            created_at: now,
            updated_at: now,
        };

        let instances = self.instances.read().await;
        for (channel_id, instance) in instances.iter() {
            if max_severity < instance.min_severity {
                continue;
            }

            let start = Instant::now();

            // 尝试使用渠道原生的报告发送能力
            let result = instance
                .channel
                .send_cert_report(
                    &subject,
                    &html_content,
                    &markdown_content,
                    &plain_content,
                    &instance.recipients,
                )
                .await;

            let (send_result, response) = match result {
                Some(Ok(resp)) => (Ok(()), Some(resp)),
                Some(Err(e)) => {
                    tracing::error!(
                        channel_id = %channel_id,
                        channel_type = %instance.channel_type,
                        error = %e,
                        "Failed to send cert report via native channel"
                    );
                    (Err(anyhow::anyhow!("{e}")), None)
                }
                // 渠道不支持 send_cert_report，回退到普通 send 接口（纯文本）
                None => {
                    let r = instance
                        .channel
                        .send(&fallback_event, &instance.recipients, locale)
                        .await;
                    let duration_ms = start.elapsed().as_millis() as i64;
                    match r {
                        Ok(resp) => {
                            let ctx = SendLogContext {
                                channel_id,
                                channel_name: &instance.name,
                                channel_type: &instance.channel_type,
                                duration_ms,
                                recipient_count: instance.recipients.len() as i32,
                                response: Some(resp),
                            };
                            Self::record_send_log(
                                &self.cert_store,
                                &fallback_event,
                                &ctx,
                                &Ok(()),
                            ).await;
                        }
                        Err(e) => {
                            tracing::error!(
                                channel_id = %channel_id,
                                channel_type = %instance.channel_type,
                                error = %e,
                                "Failed to send cert report via fallback channel"
                            );
                            let ctx = SendLogContext {
                                channel_id,
                                channel_name: &instance.name,
                                channel_type: &instance.channel_type,
                                duration_ms,
                                recipient_count: instance.recipients.len() as i32,
                                response: None,
                            };
                            Self::record_send_log(
                                &self.cert_store,
                                &fallback_event,
                                &ctx,
                                &Err(anyhow::anyhow!("{e}")),
                            ).await;
                        }
                    }
                    continue;
                }
            };

            let duration_ms = start.elapsed().as_millis() as i64;
            let ctx = SendLogContext {
                channel_id,
                channel_name: &instance.name,
                channel_type: &instance.channel_type,
                duration_ms,
                recipient_count: instance.recipients.len() as i32,
                response,
            };
            Self::record_send_log(&self.cert_store, &fallback_event, &ctx, &send_result).await;
        }

        tracing::info!(
            alert_count = alert_count,
            total_checked = total_checked,
            report_date = report_date,
            "Cert alert report sent to all channels"
        );
    }

    /// 获取已加载的渠道数量。
    pub async fn channel_count(&self) -> usize {
        self.instances.read().await.len()
    }

    /// 获取 channel registry 引用。
    pub fn registry(&self) -> &ChannelRegistry {
        &self.registry
    }

    /// 获取 cert_store 引用（供 API 层记录通知日志使用）。
    pub fn cert_store(&self) -> &Arc<CertStore> {
        &self.cert_store
    }

    /// 直接发送事件到所有通知渠道，绕过静默窗口和聚合。
    /// 主要用于定时报告等场景。
    /// 返回成功发送的渠道数量。
    pub async fn send_event_direct(&self, event: &AlertEvent) -> usize {
        let locale = self
            .cert_store
            .get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE)
            .await;
        let instances = self.instances.read().await;
        let mut success_count = 0;

        for (channel_id, instance) in instances.iter() {
            if event.severity < instance.min_severity {
                continue;
            }

            let start = Instant::now();
            let result = instance
                .channel
                .send(event, &instance.recipients, &locale)
                .await;
            let duration_ms = start.elapsed().as_millis() as i64;

            let (send_result, response) = match result {
                Ok(resp) => {
                    success_count += 1;
                    (Ok(()), Some(resp))
                }
                Err(e) => {
                    tracing::error!(
                        channel_id = %channel_id,
                        channel_type = %instance.channel_type,
                        error = %e,
                        "Failed to send notification"
                    );
                    (Err(anyhow::anyhow!("{e}")), None)
                }
            };

            let ctx = SendLogContext {
                channel_id,
                channel_name: &instance.name,
                channel_type: &instance.channel_type,
                duration_ms,
                recipient_count: instance.recipients.len() as i32,
                response,
            };
            Self::record_send_log(&self.cert_store, event, &ctx, &send_result).await;
        }

        success_count
    }
}
