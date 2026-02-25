use crate::window::SlidingWindow;
use crate::AlertRule;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricDataPoint};
use std::collections::HashMap;
use tracing;

/// Key: (rule_id, agent_id)
type WindowKey = (String, String);

/// Default number of consecutive non-firing evaluations before recovery.
const DEFAULT_RECOVERY_COUNT: u32 = 3;

/// Tracks the state of an active alert for recovery detection.
struct ActiveAlertState {
    /// The original alert event that started this alert.
    first_triggered_at: DateTime<Utc>,
    /// Number of consecutive evaluations that did NOT fire.
    consecutive_ok: u32,
}

/// Output from alert engine ingestion.
#[derive(Debug)]
pub enum AlertOutput {
    /// A new alert has fired.
    Fired(AlertEvent),
    /// A previously active alert has recovered.
    Recovered(AlertEvent),
}

impl AlertOutput {
    pub fn event(&self) -> &AlertEvent {
        match self {
            AlertOutput::Fired(e) | AlertOutput::Recovered(e) => e,
        }
    }

    pub fn into_event(self) -> AlertEvent {
        match self {
            AlertOutput::Fired(e) | AlertOutput::Recovered(e) => e,
        }
    }
}

pub struct AlertEngine {
    rules: Vec<Box<dyn AlertRule>>,
    windows: HashMap<WindowKey, SlidingWindow>,
    last_fired: HashMap<WindowKey, DateTime<Utc>>,
    /// Tracks active (unrecovered) alerts for recovery detection.
    active_alerts: HashMap<WindowKey, ActiveAlertState>,
    /// Number of consecutive non-firing evaluations required before recovery.
    recovery_count: u32,
}

impl AlertEngine {
    pub fn new(rules: Vec<Box<dyn AlertRule>>) -> Self {
        Self {
            rules,
            windows: HashMap::new(),
            last_fired: HashMap::new(),
            active_alerts: HashMap::new(),
            recovery_count: DEFAULT_RECOVERY_COUNT,
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
        self.active_alerts.clear();
    }

    pub fn ingest(&mut self, data_point: &MetricDataPoint) -> Vec<AlertOutput> {
        self.ingest_with_locale(data_point, oxmon_common::i18n::DEFAULT_LOCALE)
    }

    pub fn ingest_with_locale(
        &mut self,
        data_point: &MetricDataPoint,
        locale: &str,
    ) -> Vec<AlertOutput> {
        let now = Utc::now();
        let mut outputs = Vec::new();

        for rule in &self.rules {
            if rule.metric() != data_point.metric_name {
                continue;
            }

            if !agent_matches(rule.agent_pattern(), &data_point.agent_id) {
                continue;
            }

            let silence_secs = rule.silence_secs();
            let rule_id = rule.id();
            let rule_name = rule.name();

            // entry() consumes the key; avoid cloning by rebuilding only on alert (rare path)
            let key = (rule_id.to_string(), data_point.agent_id.clone());

            let window = self
                .windows
                .entry(key.clone())
                .or_insert_with(|| SlidingWindow::new(silence_secs.max(600)));

            window.push(data_point.clone());
            window.evict(now);

            // Use make_contiguous() to get a &[MetricDataPoint] without allocating a Vec
            let event = rule.evaluate(window.as_contiguous_slice(), now, locale);

            // NLL: window borrow ends here; self.last_fired is now accessible
            if let Some(mut event) = event {
                // Rule fired — reset recovery counter
                if let Some(state) = self.active_alerts.get_mut(&key) {
                    state.consecutive_ok = 0;
                    // Preserve first_triggered_at from previous alert
                    event.first_triggered_at = Some(state.first_triggered_at);
                }

                let suppressed = self.last_fired.get(&key).is_some_and(|last| {
                    now - *last < chrono::Duration::seconds(silence_secs as i64)
                });

                if suppressed {
                    tracing::debug!(
                        rule_id,
                        agent_id = %data_point.agent_id,
                        "Alert suppressed (silence period)"
                    );
                    // Even if suppressed, mark as active
                    self.active_alerts.entry(key).or_insert(ActiveAlertState {
                        first_triggered_at: now,
                        consecutive_ok: 0,
                    });
                } else {
                    self.last_fired.insert(key.clone(), now);
                    // Record first trigger time
                    let first_triggered = self
                        .active_alerts
                        .get(&key)
                        .map(|s| s.first_triggered_at)
                        .unwrap_or(now);
                    event.first_triggered_at = Some(first_triggered);
                    self.active_alerts.entry(key).or_insert(ActiveAlertState {
                        first_triggered_at: now,
                        consecutive_ok: 0,
                    });
                    outputs.push(AlertOutput::Fired(event));
                }
            } else {
                // Rule did NOT fire — check for recovery
                let should_recover = if let Some(state) = self.active_alerts.get_mut(&key) {
                    state.consecutive_ok += 1;
                    state.consecutive_ok >= self.recovery_count
                } else {
                    false
                };

                if should_recover {
                    let state = self.active_alerts.remove(&key).unwrap();
                    self.last_fired.remove(&key);

                    let recovery_message = {
                        use oxmon_common::i18n::TRANSLATIONS;
                        let tmpl = TRANSLATIONS.get(
                            locale,
                            "alert.recovered",
                            "[RECOVERED] {metric} has returned to normal on {agent}",
                        );
                        tmpl.replace("{metric}", &data_point.metric_name)
                            .replace("{agent}", &data_point.agent_id)
                    };
                    let recovered_event = AlertEvent {
                        id: oxmon_common::id::next_id(),
                        rule_id: rule_id.to_string(),
                        rule_name: rule_name.to_string(),
                        agent_id: data_point.agent_id.clone(),
                        metric_name: data_point.metric_name.clone(),
                        severity: rule.severity(),
                        message: recovery_message,
                        value: data_point.value,
                        threshold: 0.0,
                        timestamp: now,
                        predicted_breach: None,
                        status: 3, // resolved
                        labels: data_point.labels.clone(),
                        first_triggered_at: Some(state.first_triggered_at),
                        created_at: now,
                        updated_at: now,
                    };

                    tracing::info!(
                        rule_id,
                        agent_id = %data_point.agent_id,
                        "Alert recovered after {} consecutive OK evaluations",
                        self.recovery_count,
                    );

                    outputs.push(AlertOutput::Recovered(recovered_event));
                }
            }
        }

        outputs
    }
}

fn agent_matches(pattern: &str, agent_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    glob_match::glob_match(pattern, agent_id)
}
