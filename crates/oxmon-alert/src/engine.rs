use crate::window::SlidingWindow;
use crate::AlertRule;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricDataPoint};
use std::collections::HashMap;
use tracing;

/// Key: (rule_id, agent_id)
type WindowKey = (String, String);

pub struct AlertEngine {
    rules: Vec<Box<dyn AlertRule>>,
    windows: HashMap<WindowKey, SlidingWindow>,
    last_fired: HashMap<WindowKey, DateTime<Utc>>,
}

impl AlertEngine {
    pub fn new(rules: Vec<Box<dyn AlertRule>>) -> Self {
        Self {
            rules,
            windows: HashMap::new(),
            last_fired: HashMap::new(),
        }
    }

    pub fn rules(&self) -> &[Box<dyn AlertRule>] {
        &self.rules
    }

    pub fn ingest(&mut self, data_point: &MetricDataPoint) -> Vec<AlertEvent> {
        let now = Utc::now();
        let mut events = Vec::new();

        for rule in &self.rules {
            if rule.metric() != data_point.metric_name {
                continue;
            }

            if !agent_matches(rule.agent_pattern(), &data_point.agent_id) {
                continue;
            }

            let key = (rule.id().to_string(), data_point.agent_id.clone());

            let window = self
                .windows
                .entry(key.clone())
                .or_insert_with(|| SlidingWindow::new(rule.silence_secs().max(600)));

            window.push(data_point.clone());
            window.evict(now);

            let window_data: Vec<MetricDataPoint> =
                window.data().iter().cloned().collect();

            if let Some(event) = rule.evaluate(&window_data, now) {
                // Check deduplication
                if let Some(last) = self.last_fired.get(&key) {
                    let silence = chrono::Duration::seconds(rule.silence_secs() as i64);
                    if now - *last < silence {
                        tracing::debug!(
                            rule_id = rule.id(),
                            agent_id = %data_point.agent_id,
                            "Alert suppressed (silence period)"
                        );
                        continue;
                    }
                }

                self.last_fired.insert(key, now);
                events.push(event);
            }
        }

        events
    }
}

fn agent_matches(pattern: &str, agent_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    glob_match::glob_match(pattern, agent_id)
}
