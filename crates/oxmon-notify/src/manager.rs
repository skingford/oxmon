use crate::routing::ChannelRoute;
use crate::NotificationChannel;
use chrono::{DateTime, Duration, NaiveTime, Utc};
use oxmon_common::types::AlertEvent;
use std::collections::HashMap;
use tokio::sync::Mutex;
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

struct AggregationEntry {
    events: Vec<AlertEvent>,
    first_seen: DateTime<Utc>,
}

pub struct NotificationManager {
    channels: Vec<Box<dyn NotificationChannel>>,
    routes: Vec<ChannelRoute>,
    silence_windows: Vec<SilenceWindow>,
    aggregation_window_secs: u64,
    pending: Mutex<HashMap<String, AggregationEntry>>,
}

impl NotificationManager {
    pub fn new(
        channels: Vec<Box<dyn NotificationChannel>>,
        routes: Vec<ChannelRoute>,
        silence_windows: Vec<SilenceWindow>,
        aggregation_window_secs: u64,
    ) -> Self {
        Self {
            channels,
            routes,
            silence_windows,
            aggregation_window_secs,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Aggregation key: group by rule_id
    fn aggregation_key(event: &AlertEvent) -> String {
        event.rule_id.clone()
    }

    pub async fn notify(&self, event: &AlertEvent) {
        let now = Utc::now();

        // Check silence windows
        for window in &self.silence_windows {
            if window.is_active(now) {
                tracing::info!(
                    rule_id = %event.rule_id,
                    "Notification suppressed (silence window active)"
                );
                return;
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
            // Remove entry so next batch starts fresh
            drop(pending);
            {
                let mut pending = self.pending.lock().await;
                pending.remove(&Self::aggregation_key(event));
            }

            if events.len() == 1 {
                self.send_to_channels(&events[0]).await;
            } else {
                // Send aggregated notification
                let summary = AlertEvent {
                    id: format!("agg-{}-{}", events[0].rule_id, now.timestamp_millis()),
                    rule_id: events[0].rule_id.clone(),
                    agent_id: if events.iter().all(|e| e.agent_id == events[0].agent_id) {
                        events[0].agent_id.clone()
                    } else {
                        format!("{} agents", events.iter().map(|e| &e.agent_id).collect::<std::collections::HashSet<_>>().len())
                    },
                    metric_name: events[0].metric_name.clone(),
                    severity: events.iter().map(|e| e.severity).max().unwrap_or(events[0].severity),
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
                    created_at: now,
                    updated_at: now,
                };
                self.send_to_channels(&summary).await;
            }
        }
    }

    async fn send_to_channels(&self, event: &AlertEvent) {
        for route in &self.routes {
            if !route.should_send(event.severity) {
                continue;
            }

            if let Some(channel) = self.channels.get(route.channel_index) {
                if let Err(e) = channel.send(event).await {
                    tracing::error!(
                        channel = channel.channel_name(),
                        error = %e,
                        "Failed to send notification"
                    );
                }
            }
        }
    }

    pub fn channels(&self) -> &[Box<dyn NotificationChannel>] {
        &self.channels
    }
}
