use crate::AlertRule;
use chrono::{DateTime, Duration, Utc};
use oxmon_common::i18n::TRANSLATIONS;
use oxmon_common::types::{AlertEvent, MetricDataPoint, Severity};

/// Cloud instance scaling recommendation rule
/// Monitors CPU and memory usage to suggest scale-out or scale-in
pub struct CloudScaleRecommendationRule {
    pub id: String,
    pub name: String,
    pub metric: String, // e.g., "cloud.cpu.usage" or "cloud.memory.usage"
    pub agent_pattern: String, // e.g., "cloud:*"
    pub severity: Severity,
    pub high_threshold: f64, // e.g., 80.0 (%)
    pub low_threshold: f64,  // e.g., 20.0 (%)
    pub duration_secs: u64,  // How long the condition must persist
    pub silence_secs: u64,
}

#[derive(Debug, Clone, Copy)]
enum Trend {
    Rising,
    Falling,
    Stable,
}

impl CloudScaleRecommendationRule {
    /// Calculate trend from data points
    fn calculate_trend(&self, window: &[MetricDataPoint]) -> Trend {
        if window.len() < 3 {
            return Trend::Stable;
        }

        // Simple trend: compare first half avg vs second half avg
        let mid = window.len() / 2;
        let first_half: f64 = window[..mid].iter().map(|dp| dp.value).sum::<f64>() / mid as f64;
        let second_half: f64 = window[mid..].iter().map(|dp| dp.value).sum::<f64>() / (window.len() - mid) as f64;

        let diff = second_half - first_half;
        if diff > 5.0 {
            Trend::Rising
        } else if diff < -5.0 {
            Trend::Falling
        } else {
            Trend::Stable
        }
    }

    /// Check if values consistently exceed high threshold (scale-out signal)
    fn check_scale_out(&self, window: &[MetricDataPoint], cutoff: DateTime<Utc>) -> Option<(f64, Trend)> {
        let recent: Vec<_> = window.iter().filter(|dp| dp.timestamp >= cutoff).collect();

        if recent.is_empty() {
            return None;
        }

        // All recent points must be above high threshold
        if recent.iter().all(|dp| dp.value > self.high_threshold) {
            let avg = recent.iter().map(|dp| dp.value).sum::<f64>() / recent.len() as f64;
            let trend = self.calculate_trend(&recent.iter().map(|dp| (*dp).clone()).collect::<Vec<_>>());
            Some((avg, trend))
        } else {
            None
        }
    }

    /// Check if values consistently below low threshold (scale-in signal)
    fn check_scale_in(&self, window: &[MetricDataPoint], cutoff: DateTime<Utc>) -> Option<(f64, Trend)> {
        let recent: Vec<_> = window.iter().filter(|dp| dp.timestamp >= cutoff).collect();

        if recent.is_empty() {
            return None;
        }

        // All recent points must be below low threshold
        if recent.iter().all(|dp| dp.value < self.low_threshold) {
            let avg = recent.iter().map(|dp| dp.value).sum::<f64>() / recent.len() as f64;
            let trend = self.calculate_trend(&recent.iter().map(|dp| (*dp).clone()).collect::<Vec<_>>());
            Some((avg, trend))
        } else {
            None
        }
    }
}

impl AlertRule for CloudScaleRecommendationRule {
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

    fn evaluate(&self, window: &[MetricDataPoint], now: DateTime<Utc>, locale: &str) -> Option<AlertEvent> {
        if window.is_empty() {
            return None;
        }

        let duration = Duration::seconds(self.duration_secs as i64);
        let cutoff = now - duration;

        let latest = window.last()?;

        // Check for scale-out recommendation
        if let Some((avg_value, trend)) = self.check_scale_out(window, cutoff) {
            let trend_str = match trend {
                Trend::Rising => TRANSLATIONS.get(locale, "alert.trend.rising", "Rising"),
                Trend::Falling => TRANSLATIONS.get(locale, "alert.trend.falling", "Falling"),
                Trend::Stable => TRANSLATIONS.get(locale, "alert.trend.stable", "Stable"),
            };

            let metric_type = if self.metric.contains("cpu") {
                TRANSLATIONS.get(locale, "metric.cpu", "CPU")
            } else if self.metric.contains("memory") {
                TRANSLATIONS.get(locale, "metric.memory", "Memory")
            } else {
                self.metric.as_str()
            };

            let message = format!(
                "{}: {} {} {}% ({}: {:.1}%, {}: {}). {}",
                TRANSLATIONS.get(locale, "alert.scale.out.recommendation", "Scale-Out Recommendation"),
                latest.agent_id,
                metric_type,
                TRANSLATIONS.get(locale, "alert.scale.continuously_high", "usage continuously exceeds"),
                TRANSLATIONS.get(locale, "alert.scale.avg_value", "Average"),
                avg_value,
                TRANSLATIONS.get(locale, "alert.scale.trend", "Trend"),
                trend_str,
                TRANSLATIONS.get(locale, "alert.scale.out.action", "Consider adding more instances or upgrading instance specifications.")
            );

            return Some(AlertEvent {
                id: oxmon_common::id::next_id(),
                rule_id: self.id.clone(),
                rule_name: self.name.clone(),
                agent_id: latest.agent_id.clone(),
                metric_name: latest.metric_name.clone(),
                severity: self.severity,
                message,
                value: latest.value,
                threshold: self.high_threshold,
                timestamp: now,
                predicted_breach: None,
                status: 1, // 未处理
                labels: latest.labels.clone(),
                first_triggered_at: None,
                created_at: now,
                updated_at: now,
            });
        }

        // Check for scale-in recommendation
        if let Some((avg_value, trend)) = self.check_scale_in(window, cutoff) {
            let trend_str = match trend {
                Trend::Rising => TRANSLATIONS.get(locale, "alert.trend.rising", "Rising"),
                Trend::Falling => TRANSLATIONS.get(locale, "alert.trend.falling", "Falling"),
                Trend::Stable => TRANSLATIONS.get(locale, "alert.trend.stable", "Stable"),
            };

            let metric_type = if self.metric.contains("cpu") {
                TRANSLATIONS.get(locale, "metric.cpu", "CPU")
            } else if self.metric.contains("memory") {
                TRANSLATIONS.get(locale, "metric.memory", "Memory")
            } else {
                self.metric.as_str()
            };

            let message = format!(
                "{}: {} {} {} ({}: {:.1}%, {}: {}). {}",
                TRANSLATIONS.get(locale, "alert.scale.in.recommendation", "Scale-In Recommendation"),
                latest.agent_id,
                metric_type,
                TRANSLATIONS.get(locale, "alert.scale.continuously_low", "usage continuously below"),
                TRANSLATIONS.get(locale, "alert.scale.avg_value", "Average"),
                avg_value,
                TRANSLATIONS.get(locale, "alert.scale.trend", "Trend"),
                trend_str,
                TRANSLATIONS.get(locale, "alert.scale.in.action", "Consider reducing instances or downgrading specifications to save costs.")
            );

            return Some(AlertEvent {
                id: oxmon_common::id::next_id(),
                rule_id: self.id.clone(),
                rule_name: self.name.clone(),
                agent_id: latest.agent_id.clone(),
                metric_name: latest.metric_name.clone(),
                severity: self.severity,
                message,
                value: latest.value,
                threshold: self.low_threshold,
                timestamp: now,
                predicted_breach: None,
                status: 1, // 未处理
                labels: latest.labels.clone(),
                first_triggered_at: None,
                created_at: now,
                updated_at: now,
            });
        }

        None
    }
}
