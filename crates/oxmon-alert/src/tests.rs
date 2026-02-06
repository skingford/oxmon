use crate::engine::AlertEngine;
use crate::rules::rate_of_change::RateOfChangeRule;
use crate::rules::threshold::{CompareOp, ThresholdRule};
use crate::rules::trend_prediction::TrendPredictionRule;
use crate::AlertRule;
use chrono::{Duration, Utc};
use oxmon_common::types::{MetricDataPoint, Severity};
use std::collections::HashMap;

fn make_dp(agent: &str, metric: &str, value: f64, secs_ago: i64) -> MetricDataPoint {
    MetricDataPoint {
        timestamp: Utc::now() - Duration::seconds(secs_ago),
        agent_id: agent.to_string(),
        metric_name: metric.to_string(),
        value,
        labels: HashMap::new(),
    }
}

#[test]
fn threshold_rule_fires_when_sustained() {
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        metric: "cpu.usage".into(),
        agent_pattern: "*".into(),
        severity: Severity::Critical,
        operator: CompareOp::GreaterThan,
        value: 90.0,
        duration_secs: 60,
        silence_secs: 300,
    };

    // All points above threshold within duration window
    let window: Vec<MetricDataPoint> = (0..5)
        .map(|i| make_dp("web-01", "cpu.usage", 95.0, 50 - i * 10))
        .collect();

    let event = rule.evaluate(&window, Utc::now());
    assert!(event.is_some());
    let event = event.unwrap();
    assert_eq!(event.severity, Severity::Critical);
    assert_eq!(event.agent_id, "web-01");
}

#[test]
fn threshold_rule_does_not_fire_below_threshold() {
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        metric: "cpu.usage".into(),
        agent_pattern: "*".into(),
        severity: Severity::Critical,
        operator: CompareOp::GreaterThan,
        value: 90.0,
        duration_secs: 60,
        silence_secs: 300,
    };

    let window: Vec<MetricDataPoint> = (0..5)
        .map(|i| make_dp("web-01", "cpu.usage", 50.0, 50 - i * 10))
        .collect();

    assert!(rule.evaluate(&window, Utc::now()).is_none());
}

#[test]
fn threshold_rule_does_not_fire_when_partially_exceeded() {
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        metric: "cpu.usage".into(),
        agent_pattern: "*".into(),
        severity: Severity::Warning,
        operator: CompareOp::GreaterThan,
        value: 90.0,
        duration_secs: 60,
        silence_secs: 300,
    };

    let window = vec![
        make_dp("web-01", "cpu.usage", 95.0, 30),
        make_dp("web-01", "cpu.usage", 80.0, 20), // below threshold
        make_dp("web-01", "cpu.usage", 95.0, 10),
    ];

    assert!(rule.evaluate(&window, Utc::now()).is_none());
}

#[test]
fn rate_of_change_fires_on_spike() {
    let rule = RateOfChangeRule {
        id: "mem-spike".into(),
        metric: "memory.used_percent".into(),
        agent_pattern: "*".into(),
        severity: Severity::Warning,
        rate_threshold: 20.0,
        window_secs: 300,
        silence_secs: 600,
    };

    let window = vec![
        make_dp("web-01", "memory.used_percent", 50.0, 60),
        make_dp("web-01", "memory.used_percent", 75.0, 0), // 50% increase
    ];

    let event = rule.evaluate(&window, Utc::now());
    assert!(event.is_some());
}

#[test]
fn rate_of_change_does_not_fire_on_small_change() {
    let rule = RateOfChangeRule {
        id: "mem-spike".into(),
        metric: "memory.used_percent".into(),
        agent_pattern: "*".into(),
        severity: Severity::Warning,
        rate_threshold: 20.0,
        window_secs: 300,
        silence_secs: 600,
    };

    let window = vec![
        make_dp("web-01", "memory.used_percent", 50.0, 60),
        make_dp("web-01", "memory.used_percent", 55.0, 0), // 10% change
    ];

    assert!(rule.evaluate(&window, Utc::now()).is_none());
}

#[test]
fn trend_prediction_fires_when_breach_within_horizon() {
    let rule = TrendPredictionRule {
        id: "disk-full".into(),
        metric: "disk.used_percent".into(),
        agent_pattern: "*".into(),
        severity: Severity::Info,
        predict_threshold: 95.0,
        horizon_secs: 86400, // 24h
        min_data_points: 3,
        silence_secs: 3600,
    };

    // Linearly increasing: 60, 70, 80 over 3 hours
    let now = Utc::now();
    let window = vec![
        MetricDataPoint {
            timestamp: now - Duration::hours(2),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 60.0,
            labels: HashMap::new(),
        },
        MetricDataPoint {
            timestamp: now - Duration::hours(1),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 70.0,
            labels: HashMap::new(),
        },
        MetricDataPoint {
            timestamp: now,
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 80.0,
            labels: HashMap::new(),
        },
    ];

    let event = rule.evaluate(&window, now);
    assert!(event.is_some());
    let event = event.unwrap();
    assert!(event.predicted_breach.is_some());
}

#[test]
fn trend_prediction_does_not_fire_when_decreasing() {
    let rule = TrendPredictionRule {
        id: "disk-full".into(),
        metric: "disk.used_percent".into(),
        agent_pattern: "*".into(),
        severity: Severity::Info,
        predict_threshold: 95.0,
        horizon_secs: 86400,
        min_data_points: 3,
        silence_secs: 3600,
    };

    let now = Utc::now();
    let window = vec![
        MetricDataPoint {
            timestamp: now - Duration::hours(2),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 80.0,
            labels: HashMap::new(),
        },
        MetricDataPoint {
            timestamp: now - Duration::hours(1),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 70.0,
            labels: HashMap::new(),
        },
        MetricDataPoint {
            timestamp: now,
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 60.0,
            labels: HashMap::new(),
        },
    ];

    assert!(rule.evaluate(&window, now).is_none());
}

#[test]
fn engine_deduplication() {
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        metric: "cpu.usage".into(),
        agent_pattern: "*".into(),
        severity: Severity::Critical,
        operator: CompareOp::GreaterThan,
        value: 90.0,
        duration_secs: 5,
        silence_secs: 600,
    };

    let mut engine = AlertEngine::new(vec![Box::new(rule)]);

    let dp1 = make_dp("web-01", "cpu.usage", 95.0, 0);
    let events1 = engine.ingest(&dp1);
    assert_eq!(events1.len(), 1);

    // Second ingest within silence period should be suppressed
    let dp2 = make_dp("web-01", "cpu.usage", 96.0, 0);
    let events2 = engine.ingest(&dp2);
    assert_eq!(events2.len(), 0);
}

#[test]
fn engine_glob_pattern_matching() {
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        metric: "cpu.usage".into(),
        agent_pattern: "web-*".into(),
        severity: Severity::Warning,
        operator: CompareOp::GreaterThan,
        value: 90.0,
        duration_secs: 5,
        silence_secs: 0,
    };

    let mut engine = AlertEngine::new(vec![Box::new(rule)]);

    // Matching agent
    let dp1 = make_dp("web-01", "cpu.usage", 95.0, 0);
    assert_eq!(engine.ingest(&dp1).len(), 1);

    // Non-matching agent
    let dp2 = make_dp("db-01", "cpu.usage", 95.0, 0);
    assert_eq!(engine.ingest(&dp2).len(), 0);
}
