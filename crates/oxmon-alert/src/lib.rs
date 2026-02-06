pub mod engine;
pub mod rules;
pub mod window;

#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricDataPoint, Severity};

pub trait AlertRule: Send + Sync {
    fn id(&self) -> &str;
    fn metric(&self) -> &str;
    fn agent_pattern(&self) -> &str;
    fn severity(&self) -> Severity;
    fn silence_secs(&self) -> u64;
    fn evaluate(&self, window: &[MetricDataPoint], now: DateTime<Utc>) -> Option<AlertEvent>;
}
