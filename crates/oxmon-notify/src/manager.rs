use crate::plugin::ChannelRegistry;
use crate::NotificationChannel;
use chrono::{DateTime, Duration, NaiveTime, Utc};
use oxmon_common::types::AlertEvent;
use oxmon_storage::cert_store::CertStore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing;

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
}

struct AggregationEntry {
    events: Vec<AlertEvent>,
    first_seen: DateTime<Utc>,
}

pub struct NotificationManager {
    /// channel_id -> ChannelInstance
    instances: RwLock<HashMap<String, ChannelInstance>>,
    registry: ChannelRegistry,
    cert_store: Arc<CertStore>,
    aggregation_window_secs: u64,
    pending: Mutex<HashMap<String, AggregationEntry>>,
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
        let channels_with_recipients = self
            .cert_store
            .list_enabled_channels_with_recipients()?;

        let mut new_instances = HashMap::new();
        for (row, recipients) in channels_with_recipients {
            let config: serde_json::Value = serde_json::from_str(&row.config_json)
                .unwrap_or_else(|_| serde_json::json!({}));

            match self.registry.create_channel(&row.channel_type, &row.id, &config) {
                Ok(channel) => {
                    let severity = row.min_severity.parse().unwrap_or(oxmon_common::types::Severity::Info);
                    new_instances.insert(row.id.clone(), ChannelInstance {
                        channel,
                        recipients,
                        min_severity: severity,
                    });
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
        if let Ok(windows) = self.cert_store.list_silence_windows(100, 0) {
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
                    created_at: now,
                    updated_at: now,
                };
                self.send_to_channels(&summary).await;
            }
        }
    }

    async fn send_to_channels(&self, event: &AlertEvent) {
        let instances = self.instances.read().await;
        for (channel_id, instance) in instances.iter() {
            if event.severity < instance.min_severity {
                continue;
            }

            if let Err(e) = instance.channel.send(event, &instance.recipients).await {
                tracing::error!(
                    channel_id = %channel_id,
                    channel_type = instance.channel.channel_type(),
                    error = %e,
                    "Failed to send notification"
                );
            }
        }
    }

    /// 获取已加载的渠道数量。
    pub async fn channel_count(&self) -> usize {
        self.instances.read().await.len()
    }

    /// 获取 channel registry 引用。
    pub fn registry(&self) -> &ChannelRegistry {
        &self.registry
    }
}
