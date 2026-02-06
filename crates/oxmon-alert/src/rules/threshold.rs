use crate::AlertRule;
use chrono::{DateTime, Duration, Utc};
use oxmon_common::types::{AlertEvent, MetricDataPoint, Severity};

#[derive(Debug, Clone)]
pub enum CompareOp {
    GreaterThan,
    LessThan,
    GreaterEqual,
    LessEqual,
}

impl CompareOp {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "greater_than" | "gt" => Some(Self::GreaterThan),
            "less_than" | "lt" => Some(Self::LessThan),
            "greater_equal" | "gte" => Some(Self::GreaterEqual),
            "less_equal" | "lte" => Some(Self::LessEqual),
            _ => None,
        }
    }

    fn eval(&self, value: f64, threshold: f64) -> bool {
        match self {
            Self::GreaterThan => value > threshold,
            Self::LessThan => value < threshold,
            Self::GreaterEqual => value >= threshold,
            Self::LessEqual => value <= threshold,
        }
    }
}

pub struct ThresholdRule {
    pub id: String,
    pub metric: String,
    pub agent_pattern: String,
    pub severity: Severity,
    pub operator: CompareOp,
    pub value: f64,
    pub duration_secs: u64,
    pub silence_secs: u64,
}

impl AlertRule for ThresholdRule {
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
        if window.is_empty() {
            return None;
        }

        let duration = Duration::seconds(self.duration_secs as i64);
        let cutoff = now - duration;

        // Check if ALL data points within the duration window exceed the threshold
        let recent: Vec<&MetricDataPoint> = window
            .iter()
            .filter(|dp| dp.timestamp >= cutoff)
            .collect();

        if recent.is_empty() {
            return None;
        }

        let all_exceeded = recent
            .iter()
            .all(|dp| self.operator.eval(dp.value, self.value));

        if !all_exceeded {
            return None;
        }

        let latest = recent.last().unwrap();
        Some(AlertEvent {
            id: format!("{}-{}-{}", self.id, latest.agent_id, now.timestamp_millis()),
            rule_id: self.id.clone(),
            agent_id: latest.agent_id.clone(),
            metric_name: self.metric.clone(),
            severity: self.severity,
            message: format!(
                "{} has been {} {:.1} for the configured duration on {}",
                self.metric, op_str(&self.operator), self.value, latest.agent_id,
            ),
            value: latest.value,
            threshold: self.value,
            timestamp: now,
            predicted_breach: None,
        })
    }
}

fn op_str(op: &CompareOp) -> &'static str {
    match op {
        CompareOp::GreaterThan => "above",
        CompareOp::LessThan => "below",
        CompareOp::GreaterEqual => "at or above",
        CompareOp::LessEqual => "at or below",
    }
}
