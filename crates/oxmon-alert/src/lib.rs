//! Alert rule engine for evaluating metrics against configurable thresholds.
//!
//! The engine maintains per-(rule, agent) sliding windows and evaluates
//! incoming metrics through registered [`AlertRule`] implementations.
//! Built-in rule types include threshold, rate-of-change, trend prediction,
//! and certificate expiration.

pub mod engine;
pub mod rules;
pub mod window;

#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricDataPoint, Severity};

/// An alert rule that evaluates a sliding window of metric data points
/// and optionally produces an [`AlertEvent`].
///
/// Implementations are registered in the [`engine::AlertEngine`] and
/// evaluated on each incoming data point whose metric name and agent ID
/// match the rule's criteria. The engine handles deduplication via
/// per-rule silence periods.
pub trait AlertRule: Send + Sync {
    /// Unique identifier for this rule instance (e.g., `"cpu-high-1"`).
    fn id(&self) -> &str;

    /// Human-readable name for this rule (e.g., `"生产环境 CPU 过高"`).
    fn name(&self) -> &str;

    /// The metric name this rule applies to (e.g., `"cpu.usage"`).
    fn metric(&self) -> &str;

    /// A glob pattern matching agent IDs (e.g., `"prod-*"` or `"*"`).
    fn agent_pattern(&self) -> &str;

    /// The severity level assigned to alerts produced by this rule.
    fn severity(&self) -> Severity;

    /// Minimum seconds between consecutive alerts for the same rule/agent pair.
    fn silence_secs(&self) -> u64;

    /// Evaluates the sliding window and returns an alert event if the
    /// rule condition is met, or `None` otherwise.
    fn evaluate(&self, window: &[MetricDataPoint], now: DateTime<Utc>) -> Option<AlertEvent>;
}
