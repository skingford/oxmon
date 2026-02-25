use crate::AlertRule;
use chrono::{DateTime, Utc};
use oxmon_common::types::{format_labels, AlertEvent, MetricDataPoint, Severity};

pub struct RateOfChangeRule {
    pub id: String,
    pub name: String,
    pub metric: String,
    pub agent_pattern: String,
    pub severity: Severity,
    pub rate_threshold: f64,
    pub window_secs: u64,
    pub silence_secs: u64,
}

impl AlertRule for RateOfChangeRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn metric(&self) -> &str {
        &self.metric
    }

    fn agent_pattern(&self) -> &str {
        &self.agent_pattern
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn silence_secs(&self) -> u64 {
        self.silence_secs
    }

    fn evaluate(
        &self,
        window: &[MetricDataPoint],
        now: DateTime<Utc>,
        locale: &str,
    ) -> Option<AlertEvent> {
        if window.len() < 2 {
            return None;
        }

        let first = window.first()?;
        let last = window.last()?;

        if first.value.abs() < f64::EPSILON {
            return None;
        }

        let rate = ((last.value - first.value) / first.value) * 100.0;

        if rate.abs() > self.rate_threshold {
            let labels_str = format_labels(&last.labels);
            let labels_display = if labels_str.is_empty() {
                String::new()
            } else {
                format!(" [{}]", labels_str)
            };
            let message = {
                use oxmon_common::i18n::TRANSLATIONS;
                let tmpl = TRANSLATIONS.get(locale, "alert.rate_of_change",
                    "{metric}{labels} changed by {rate:.1}% (threshold: {rate_threshold:.1}%) on {agent}");
                tmpl.replace("{metric}", &self.metric)
                    .replace("{labels}", &labels_display)
                    .replace("{rate:.1}", &format!("{:.1}", rate))
                    .replace(
                        "{rate_threshold:.1}",
                        &format!("{:.1}", self.rate_threshold),
                    )
                    .replace("{agent}", &last.agent_id)
            };
            Some(AlertEvent {
                id: oxmon_common::id::next_id(),
                rule_id: self.id.clone(),
                rule_name: self.name.clone(),
                agent_id: last.agent_id.clone(),
                metric_name: self.metric.clone(),
                severity: self.severity,
                message,
                value: last.value,
                threshold: self.rate_threshold,
                timestamp: now,
                predicted_breach: None,
                status: 1,
                labels: last.labels.clone(),
                first_triggered_at: None,
                created_at: now,
                updated_at: now,
            })
        } else {
            None
        }
    }
}
