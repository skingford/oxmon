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

    /// Get a rule by its ID.
    pub fn get_rule(&self, id: &str) -> Option<&dyn AlertRule> {
        self.rules.iter().find(|r| r.id() == id).map(|r| r.as_ref())
    }

    /// Add a new rule at runtime.
    pub fn add_rule(&mut self, rule: Box<dyn AlertRule>) {
        self.rules.push(rule);
    }

    /// Remove a rule by ID. Returns true if found and removed.
    pub fn remove_rule(&mut self, id: &str) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.id() != id);
        self.rules.len() < len_before
    }

    /// Replace all rules with a new set.
    pub fn replace_rules(&mut self, rules: Vec<Box<dyn AlertRule>>) {
        self.rules = rules;
        self.windows.clear();
        self.last_fired.clear();
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

            let silence_secs = rule.silence_secs();
            let rule_id = rule.id();

            // entry() consumes the key; avoid cloning by rebuilding only on alert (rare path)
            let key = (rule_id.to_string(), data_point.agent_id.clone());

            let window = self
                .windows
                .entry(key)
                .or_insert_with(|| SlidingWindow::new(silence_secs.max(600)));

            window.push(data_point.clone());
            window.evict(now);

            // Use make_contiguous() to get a &[MetricDataPoint] without allocating a Vec
            let event = rule.evaluate(window.as_contiguous_slice(), now);

            // NLL: window borrow ends here; self.last_fired is now accessible
            if let Some(event) = event {
                let key = (rule_id.to_string(), data_point.agent_id.clone());

                let suppressed = self.last_fired.get(&key).is_some_and(|last| {
                    now - *last < chrono::Duration::seconds(silence_secs as i64)
                });

                if suppressed {
                    tracing::debug!(
                        rule_id,
                        agent_id = %data_point.agent_id,
                        "Alert suppressed (silence period)"
                    );
                } else {
                    self.last_fired.insert(key, now);
                    events.push(event);
                }
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
