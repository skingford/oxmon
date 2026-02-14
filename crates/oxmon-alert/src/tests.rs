use crate::engine::{AlertEngine, AlertOutput};
use crate::rules::rate_of_change::RateOfChangeRule;
use crate::rules::threshold::{CompareOp, ThresholdRule};
use crate::rules::trend_prediction::TrendPredictionRule;
use crate::AlertRule;
use chrono::{Duration, Utc};
use oxmon_common::types::{MetricDataPoint, Severity};
use std::collections::HashMap;

fn make_dp(agent: &str, metric: &str, value: f64, secs_ago: i64) -> MetricDataPoint {
    let ts = Utc::now() - Duration::seconds(secs_ago);
    MetricDataPoint {
        id: oxmon_common::id::next_id(),
        timestamp: ts,
        agent_id: agent.to_string(),
        metric_name: metric.to_string(),
        value,
        labels: HashMap::new(),
        created_at: ts,
        updated_at: ts,
    }
}

#[test]
fn threshold_rule_fires_when_sustained() {
    oxmon_common::id::init(1, 1);
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        name: "CPU 使用率过高".into(),
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
    assert_eq!(event.rule_name, "CPU 使用率过高");
}

#[test]
fn threshold_rule_does_not_fire_below_threshold() {
    oxmon_common::id::init(1, 1);
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        name: "CPU 使用率过高".into(),
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
    oxmon_common::id::init(1, 1);
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        name: "CPU 使用率过高".into(),
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
    oxmon_common::id::init(1, 1);
    let rule = RateOfChangeRule {
        id: "mem-spike".into(),
        name: "内存变化率过高".into(),
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
    oxmon_common::id::init(1, 1);
    let rule = RateOfChangeRule {
        id: "mem-spike".into(),
        name: "内存变化率过高".into(),
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
    oxmon_common::id::init(1, 1);
    let rule = TrendPredictionRule {
        id: "disk-full".into(),
        name: "磁盘容量趋势预测".into(),
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
            id: oxmon_common::id::next_id(),
            timestamp: now - Duration::hours(2),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 60.0,
            labels: HashMap::new(),
            created_at: now - Duration::hours(2),
            updated_at: now - Duration::hours(2),
        },
        MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now - Duration::hours(1),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 70.0,
            labels: HashMap::new(),
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::hours(1),
        },
        MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now,
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 80.0,
            labels: HashMap::new(),
            created_at: now,
            updated_at: now,
        },
    ];

    let event = rule.evaluate(&window, now);
    assert!(event.is_some());
    let event = event.unwrap();
    assert!(event.predicted_breach.is_some());
}

#[test]
fn trend_prediction_does_not_fire_when_decreasing() {
    oxmon_common::id::init(1, 1);
    let rule = TrendPredictionRule {
        id: "disk-full".into(),
        name: "磁盘容量趋势预测".into(),
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
            id: oxmon_common::id::next_id(),
            timestamp: now - Duration::hours(2),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 80.0,
            labels: HashMap::new(),
            created_at: now - Duration::hours(2),
            updated_at: now - Duration::hours(2),
        },
        MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now - Duration::hours(1),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 70.0,
            labels: HashMap::new(),
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::hours(1),
        },
        MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now,
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 60.0,
            labels: HashMap::new(),
            created_at: now,
            updated_at: now,
        },
    ];

    assert!(rule.evaluate(&window, now).is_none());
}

#[test]
fn trend_prediction_does_not_fire_when_too_soon() {
    oxmon_common::id::init(1, 1);
    let rule = TrendPredictionRule {
        id: "disk-full".into(),
        name: "磁盘容量趋势预测".into(),
        metric: "disk.used_percent".into(),
        agent_pattern: "*".into(),
        severity: Severity::Info,
        predict_threshold: 95.0,
        horizon_secs: 86400, // 24h
        min_data_points: 3,
        silence_secs: 3600,
    };

    // 快速增长：90, 92, 94 在 1 分钟内（预计 30 秒后达到 95）
    // 这种情况下预测时间小于 5 分钟，不应该触发预测告警
    let now = Utc::now();
    let window = vec![
        MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now - Duration::seconds(60),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 90.0,
            labels: HashMap::new(),
            created_at: now - Duration::seconds(60),
            updated_at: now - Duration::seconds(60),
        },
        MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now - Duration::seconds(30),
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 92.0,
            labels: HashMap::new(),
            created_at: now - Duration::seconds(30),
            updated_at: now - Duration::seconds(30),
        },
        MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: now,
            agent_id: "db-01".into(),
            metric_name: "disk.used_percent".into(),
            value: 94.0,
            labels: HashMap::new(),
            created_at: now,
            updated_at: now,
        },
    ];

    // 应该返回 None，因为预测时间小于 5 分钟
    let event = rule.evaluate(&window, now);
    assert!(
        event.is_none(),
        "Should not fire when prediction time is less than 5 minutes"
    );
}

#[test]
fn engine_deduplication() {
    oxmon_common::id::init(1, 1);
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        name: "CPU 使用率过高".into(),
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
    let outputs1 = engine.ingest(&dp1);
    assert_eq!(outputs1.len(), 1);
    assert!(matches!(&outputs1[0], AlertOutput::Fired(_)));

    // Second ingest within silence period should be suppressed
    let dp2 = make_dp("web-01", "cpu.usage", 96.0, 0);
    let outputs2 = engine.ingest(&dp2);
    assert_eq!(outputs2.len(), 0);
}

#[test]
fn engine_glob_pattern_matching() {
    oxmon_common::id::init(1, 1);
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        name: "CPU 使用率过高".into(),
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

#[test]
fn engine_recovery_after_consecutive_ok() {
    oxmon_common::id::init(1, 1);
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        name: "CPU 使用率过高".into(),
        metric: "cpu.usage".into(),
        agent_pattern: "*".into(),
        severity: Severity::Critical,
        operator: CompareOp::GreaterThan,
        value: 90.0,
        duration_secs: 5,
        silence_secs: 0,
    };

    let mut engine = AlertEngine::new(vec![Box::new(rule)]);

    // Trigger alert
    let dp1 = make_dp("web-01", "cpu.usage", 95.0, 0);
    let outputs1 = engine.ingest(&dp1);
    assert_eq!(outputs1.len(), 1);
    assert!(matches!(&outputs1[0], AlertOutput::Fired(_)));

    // 3 consecutive OK evaluations (below threshold) should trigger recovery
    for _ in 0..2 {
        let dp = make_dp("web-01", "cpu.usage", 50.0, 0);
        let outputs = engine.ingest(&dp);
        assert_eq!(outputs.len(), 0, "Should not recover yet");
    }

    // Third OK should trigger recovery
    let dp_final = make_dp("web-01", "cpu.usage", 50.0, 0);
    let outputs_final = engine.ingest(&dp_final);
    assert_eq!(outputs_final.len(), 1);
    assert!(matches!(&outputs_final[0], AlertOutput::Recovered(_)));
    let event = outputs_final[0].event();
    assert_eq!(event.status, 3);
    assert!(event.message.contains("RECOVERED"));
    assert!(event.first_triggered_at.is_some());
}

#[test]
fn engine_no_recovery_if_fires_again() {
    oxmon_common::id::init(1, 1);

    // RateOfChange compares first and last in window: rate = (last - first) / first * 100.
    // Fires when |rate| > 20%.
    let rule = RateOfChangeRule {
        id: "mem-spike".into(),
        name: "内存变化率过高".into(),
        metric: "memory.used_percent".into(),
        agent_pattern: "*".into(),
        severity: Severity::Warning,
        rate_threshold: 20.0,
        window_secs: 300,
        silence_secs: 0,
    };

    let mut engine = AlertEngine::new(vec![Box::new(rule)]);

    // Step 1: Base point + spike → fires
    // Window: [50, 75], rate = (75-50)/50 = 50% > 20% → fires
    let dp_base = make_dp("web-01", "memory.used_percent", 50.0, 60);
    engine.ingest(&dp_base);
    let dp_spike = make_dp("web-01", "memory.used_percent", 75.0, 0);
    let outputs = engine.ingest(&dp_spike);
    assert_eq!(outputs.len(), 1);
    assert!(matches!(&outputs[0], AlertOutput::Fired(_)));

    // Step 2: 2 OK evaluations with values close to first (rate < 20%)
    // Window: [50, 75, 55], rate = (55-50)/50 = 10% < 20% → OK
    for _ in 0..2 {
        let dp = make_dp("web-01", "memory.used_percent", 55.0, 0);
        let outputs = engine.ingest(&dp);
        assert_eq!(outputs.len(), 0, "Should not recover or fire yet");
    }

    // Step 3: Big spike again → fires, resets recovery counter
    // Window: [50, 75, 55, 55, 100], rate = (100-50)/50 = 100% > 20% → fires
    let dp_spike2 = make_dp("web-01", "memory.used_percent", 100.0, 0);
    let outputs = engine.ingest(&dp_spike2);
    assert_eq!(outputs.len(), 1);
    assert!(matches!(&outputs[0], AlertOutput::Fired(_)));

    // Step 4: Need another 3 consecutive OKs for recovery
    // Window continues growing: [50, 75, 55, 55, 100, 51], rate = (51-50)/50 = 2% → OK
    for _ in 0..2 {
        let dp = make_dp("web-01", "memory.used_percent", 51.0, 0);
        assert_eq!(engine.ingest(&dp).len(), 0);
    }

    let dp_final = make_dp("web-01", "memory.used_percent", 51.0, 0);
    let outputs = engine.ingest(&dp_final);
    assert_eq!(outputs.len(), 1);
    assert!(matches!(&outputs[0], AlertOutput::Recovered(_)));
}

#[test]
fn engine_replace_rules_clears_active_alerts() {
    oxmon_common::id::init(1, 1);
    let rule = ThresholdRule {
        id: "high-cpu".into(),
        name: "CPU 使用率过高".into(),
        metric: "cpu.usage".into(),
        agent_pattern: "*".into(),
        severity: Severity::Critical,
        operator: CompareOp::GreaterThan,
        value: 90.0,
        duration_secs: 5,
        silence_secs: 0,
    };

    let mut engine = AlertEngine::new(vec![Box::new(rule)]);

    // Trigger alert
    let dp1 = make_dp("web-01", "cpu.usage", 95.0, 0);
    assert_eq!(engine.ingest(&dp1).len(), 1);

    // Replace rules — should clear active state
    let new_rule = ThresholdRule {
        id: "high-cpu".into(),
        name: "CPU 使用率过高".into(),
        metric: "cpu.usage".into(),
        agent_pattern: "*".into(),
        severity: Severity::Critical,
        operator: CompareOp::GreaterThan,
        value: 90.0,
        duration_secs: 5,
        silence_secs: 0,
    };
    engine.replace_rules(vec![Box::new(new_rule)]);

    // OK evaluations should NOT produce recovery since state was cleared
    for _ in 0..3 {
        let dp = make_dp("web-01", "cpu.usage", 50.0, 0);
        let outputs = engine.ingest(&dp);
        assert_eq!(outputs.len(), 0, "No recovery after replace_rules");
    }
}

#[test]
fn threshold_rule_includes_labels_in_message() {
    oxmon_common::id::init(1, 1);
    let rule = ThresholdRule {
        id: "disk-high".into(),
        name: "磁盘使用率过高".into(),
        metric: "disk.used_percent".into(),
        agent_pattern: "*".into(),
        severity: Severity::Warning,
        operator: CompareOp::GreaterThan,
        value: 80.0,
        duration_secs: 5,
        silence_secs: 300,
    };

    let ts = Utc::now();
    let mut labels = HashMap::new();
    labels.insert("mount".to_string(), "/data".to_string());
    let dp = MetricDataPoint {
        id: oxmon_common::id::next_id(),
        timestamp: ts,
        agent_id: "web-01".to_string(),
        metric_name: "disk.used_percent".to_string(),
        value: 95.0,
        labels,
        created_at: ts,
        updated_at: ts,
    };

    let event = rule.evaluate(&[dp], Utc::now());
    assert!(event.is_some());
    let event = event.unwrap();
    assert!(
        event.message.contains("mount=/data"),
        "message should contain labels: {}",
        event.message
    );
    assert_eq!(event.labels.get("mount").unwrap(), "/data");
    assert_eq!(event.rule_name, "磁盘使用率过高");
}
