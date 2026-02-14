use crate::AlertRule;
use chrono::{DateTime, Duration, Utc};
use oxmon_common::types::{format_labels, AlertEvent, MetricDataPoint, Severity};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum CompareOp {
    GreaterThan,
    LessThan,
    GreaterEqual,
    LessEqual,
}

impl FromStr for CompareOp {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "greater_than" | "gt" => Ok(Self::GreaterThan),
            "less_than" | "lt" => Ok(Self::LessThan),
            "greater_equal" | "gte" => Ok(Self::GreaterEqual),
            "less_equal" | "lte" => Ok(Self::LessEqual),
            _ => Err(format!("unknown compare operator: {s}")),
        }
    }
}

impl std::fmt::Display for CompareOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GreaterThan => write!(f, "greater_than"),
            Self::LessThan => write!(f, "less_than"),
            Self::GreaterEqual => write!(f, "greater_equal"),
            Self::LessEqual => write!(f, "less_equal"),
        }
    }
}

impl CompareOp {
    fn check(&self, value: f64, threshold: f64) -> bool {
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
    pub name: String,
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

    fn evaluate(&self, window: &[MetricDataPoint], now: DateTime<Utc>) -> Option<AlertEvent> {
        if window.is_empty() {
            return None;
        }

        let duration = Duration::seconds(self.duration_secs as i64);
        let cutoff = now - duration;

        // Check if ALL data points within the duration window exceed the threshold
        let mut recent = window.iter().filter(|dp| dp.timestamp >= cutoff).peekable();

        recent.peek()?;

        let mut latest = None;
        let all_exceeded = recent.all(|dp| {
            latest = Some(dp);
            self.operator.check(dp.value, self.value)
        });

        if !all_exceeded {
            return None;
        }

        let latest = latest?;
        let labels_str = format_labels(&latest.labels);
        let labels_display = if labels_str.is_empty() {
            String::new()
        } else {
            format!(" [{}]", labels_str)
        };
        Some(AlertEvent {
            id: oxmon_common::id::next_id(),
            rule_id: self.id.clone(),
            rule_name: self.name.clone(),
            agent_id: latest.agent_id.clone(),
            metric_name: self.metric.clone(),
            severity: self.severity,
            message: format!(
                "{}{} has been {} {:.1} for the configured duration on {}",
                self.metric,
                labels_display,
                op_str(&self.operator),
                self.value,
                latest.agent_id,
            ),
            value: latest.value,
            threshold: self.value,
            timestamp: now,
            predicted_breach: None,
            status: 1,
            labels: latest.labels.clone(),
            first_triggered_at: None,
            created_at: now,
            updated_at: now,
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
