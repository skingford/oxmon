use crate::AlertRule;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricDataPoint, Severity};

pub struct RateOfChangeRule {
    pub id: String,
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

    fn evaluate(&self, window: &[MetricDataPoint], now: DateTime<Utc>) -> Option<AlertEvent> {
        if window.len() < 2 {
            return None;
        }

        let first = window.first().unwrap();
        let last = window.last().unwrap();

        if first.value.abs() < f64::EPSILON {
            return None;
        }

        let rate = ((last.value - first.value) / first.value) * 100.0;

        if rate.abs() > self.rate_threshold {
            Some(AlertEvent {
                id: format!("{}-{}-{}", self.id, last.agent_id, now.timestamp_millis()),
                rule_id: self.id.clone(),
                agent_id: last.agent_id.clone(),
                metric_name: self.metric.clone(),
                severity: self.severity,
                message: format!(
                    "{} changed by {:.1}% (threshold: {:.1}%) on {}",
                    self.metric, rate, self.rate_threshold, last.agent_id,
                ),
                value: last.value,
                threshold: self.rate_threshold,
                timestamp: now,
                predicted_breach: None,
            })
        } else {
            None
        }
    }
}
