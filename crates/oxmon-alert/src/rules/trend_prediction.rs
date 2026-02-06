use crate::AlertRule;
use chrono::{DateTime, Duration, Utc};
use oxmon_common::types::{AlertEvent, MetricDataPoint, Severity};

pub struct TrendPredictionRule {
    pub id: String,
    pub metric: String,
    pub agent_pattern: String,
    pub severity: Severity,
    pub predict_threshold: f64,
    pub horizon_secs: u64,
    pub min_data_points: usize,
    pub silence_secs: u64,
}

impl AlertRule for TrendPredictionRule {
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
        if window.len() < self.min_data_points {
            return None;
        }

        // Simple linear regression: y = mx + b
        // x = timestamp (seconds from first point), y = value
        let base_ts = window[0].timestamp.timestamp() as f64;
        let n = window.len() as f64;

        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_x2 = 0.0;

        for dp in window {
            let x = dp.timestamp.timestamp() as f64 - base_ts;
            let y = dp.value;
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }

        let denom = n * sum_x2 - sum_x * sum_x;
        if denom.abs() < f64::EPSILON {
            return None;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / denom;
        let intercept = (sum_y - slope * sum_x) / n;

        // If slope is not positive (metric not increasing), no breach predicted
        if slope <= 0.0 {
            return None;
        }

        // Predict when value reaches threshold
        let current_x = now.timestamp() as f64 - base_ts;
        let current_predicted = slope * current_x + intercept;

        if current_predicted >= self.predict_threshold {
            // Already at threshold
            return None;
        }

        let time_to_threshold = (self.predict_threshold - intercept) / slope - current_x;
        if time_to_threshold < 0.0 || time_to_threshold > self.horizon_secs as f64 {
            return None;
        }

        let breach_time = now + Duration::seconds(time_to_threshold as i64);
        let hours_remaining = time_to_threshold / 3600.0;
        let last = window.last().unwrap();

        Some(AlertEvent {
            id: format!("{}-{}-{}", self.id, last.agent_id, now.timestamp_millis()),
            rule_id: self.id.clone(),
            agent_id: last.agent_id.clone(),
            metric_name: self.metric.clone(),
            severity: self.severity,
            message: format!(
                "{} predicted to reach {:.1} in {:.1} hours on {}",
                self.metric, self.predict_threshold, hours_remaining, last.agent_id,
            ),
            value: last.value,
            threshold: self.predict_threshold,
            timestamp: now,
            predicted_breach: Some(breach_time),
        })
    }
}
