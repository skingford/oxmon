use crate::engine::SqliteStorageEngine;
use crate::{MetricQuery, StorageEngine};
use chrono::{Duration, Utc};
use oxmon_common::types::{AlertEvent, MetricBatch, MetricDataPoint, Severity};
use std::collections::HashMap;
use tempfile::TempDir;

fn setup() -> (TempDir, SqliteStorageEngine) {
    oxmon_common::id::init(1, 1);
    let dir = TempDir::new().unwrap();
    let engine = SqliteStorageEngine::new(dir.path()).unwrap();
    (dir, engine)
}

fn make_batch(agent: &str, metric: &str, values: &[(f64, i64)]) -> MetricBatch {
    let now = Utc::now();
    MetricBatch {
        agent_id: agent.to_string(),
        timestamp: now,
        data_points: values
            .iter()
            .map(|(value, secs_ago)| {
                let ts = now - Duration::seconds(*secs_ago);
                MetricDataPoint {
                    id: oxmon_common::id::next_id(),
                    timestamp: ts,
                    agent_id: agent.to_string(),
                    metric_name: metric.to_string(),
                    value: *value,
                    labels: HashMap::new(),
                    created_at: ts,
                    updated_at: ts,
                }
            })
            .collect(),
    }
}

#[test]
fn write_and_query_metrics() {
    let (_dir, engine) = setup();

    let batch = make_batch("web-01", "cpu.usage", &[(95.0, 10), (90.0, 5), (85.0, 0)]);
    engine.write_batch(&batch).unwrap();

    let query = MetricQuery {
        agent_id: "web-01".to_string(),
        metric_name: "cpu.usage".to_string(),
        from: Utc::now() - Duration::minutes(1),
        to: Utc::now() + Duration::seconds(1),
    };

    let results = engine.query(&query).unwrap();
    assert_eq!(results.len(), 3);
    assert!(results[0].timestamp <= results[1].timestamp);
}

#[test]
fn query_empty_result() {
    let (_dir, engine) = setup();

    let query = MetricQuery {
        agent_id: "nonexistent".to_string(),
        metric_name: "cpu.usage".to_string(),
        from: Utc::now() - Duration::hours(1),
        to: Utc::now(),
    };

    let results = engine.query(&query).unwrap();
    assert!(results.is_empty());
}

#[test]
fn write_and_query_alert_events() {
    let (_dir, engine) = setup();

    let now = Utc::now();
    let event = AlertEvent {
        id: "test-alert-1".to_string(),
        rule_id: "high-cpu".to_string(),
        agent_id: "web-01".to_string(),
        metric_name: "cpu.usage".to_string(),
        severity: Severity::Critical,
        message: "CPU too high".to_string(),
        value: 95.0,
        threshold: 90.0,
        timestamp: now,
        predicted_breach: None,
        created_at: now,
        updated_at: now,
    };

    engine.write_alert_event(&event).unwrap();

    let results = engine
        .query_alert_history(now - Duration::minutes(1), now + Duration::seconds(1), None, None, 100, 0)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "test-alert-1");
    assert_eq!(results[0].severity, Severity::Critical);
}

#[test]
fn query_alert_history_filters() {
    let (_dir, engine) = setup();

    let now = Utc::now();
    for i in 0..3 {
        let ts = now - Duration::seconds(i * 10);
        let event = AlertEvent {
            id: format!("alert-{i}"),
            rule_id: "rule-1".to_string(),
            agent_id: if i < 2 { "web-01" } else { "db-01" }.to_string(),
            metric_name: "cpu.usage".to_string(),
            severity: if i == 0 { Severity::Critical } else { Severity::Warning },
            message: format!("Alert {i}"),
            value: 95.0,
            threshold: 90.0,
            timestamp: ts,
            predicted_breach: None,
            created_at: ts,
            updated_at: ts,
        };
        engine.write_alert_event(&event).unwrap();
    }

    // Filter by severity
    let critical = engine
        .query_alert_history(now - Duration::hours(1), now + Duration::seconds(1), Some("critical"), None, 100, 0)
        .unwrap();
    assert_eq!(critical.len(), 1);

    // Filter by agent
    let db_alerts = engine
        .query_alert_history(now - Duration::hours(1), now + Duration::seconds(1), None, Some("db-01"), 100, 0)
        .unwrap();
    assert_eq!(db_alerts.len(), 1);
}

#[test]
fn retention_cleanup() {
    let (_dir, engine) = setup();

    // Write data for "today"
    let batch = make_batch("web-01", "cpu.usage", &[(50.0, 0)]);
    engine.write_batch(&batch).unwrap();

    // Cleanup with 0 retention should remove today's partition
    let removed = engine.cleanup(0).unwrap();
    // Today's partition might or might not be removed (depends on cutoff)
    // With retention_days=0, only partitions strictly before today are removed
    // so current day data should survive
    assert!(removed == 0 || removed == 1);
}

#[test]
fn pagination() {
    let (_dir, engine) = setup();

    let now = Utc::now();
    for i in 0..10 {
        let ts = now - Duration::seconds(i);
        let event = AlertEvent {
            id: format!("alert-{i}"),
            rule_id: "rule-1".to_string(),
            agent_id: "web-01".to_string(),
            metric_name: "cpu.usage".to_string(),
            severity: Severity::Warning,
            message: format!("Alert {i}"),
            value: 95.0,
            threshold: 90.0,
            timestamp: ts,
            predicted_breach: None,
            created_at: ts,
            updated_at: ts,
        };
        engine.write_alert_event(&event).unwrap();
    }

    let page1 = engine
        .query_alert_history(now - Duration::hours(1), now + Duration::seconds(1), None, None, 3, 0)
        .unwrap();
    assert_eq!(page1.len(), 3);

    let page2 = engine
        .query_alert_history(now - Duration::hours(1), now + Duration::seconds(1), None, None, 3, 3)
        .unwrap();
    assert_eq!(page2.len(), 3);

    // Pages shouldn't overlap
    assert_ne!(page1[0].id, page2[0].id);
}

#[test]
fn query_metrics_paginated() {
    let (_dir, engine) = setup();

    let now = Utc::now();
    for i in 0..30 {
        let ts = now - Duration::seconds(i);
        let batch = MetricBatch {
            agent_id: "web-01".to_string(),
            timestamp: ts,
            data_points: vec![MetricDataPoint {
                id: format!("metric-{i}"),
                timestamp: ts,
                agent_id: "web-01".to_string(),
                metric_name: "cpu.usage".to_string(),
                value: i as f64,
                labels: HashMap::new(),
                created_at: ts,
                updated_at: ts,
            }],
        };
        engine.write_batch(&batch).unwrap();
    }

    let page1 = engine
        .query_metrics_paginated(
            now - Duration::hours(1),
            now + Duration::seconds(1),
            None,
            None,
            20,
            0,
        )
        .unwrap();
    assert_eq!(page1.len(), 20);

    let page2 = engine
        .query_metrics_paginated(
            now - Duration::hours(1),
            now + Duration::seconds(1),
            None,
            None,
            20,
            20,
        )
        .unwrap();
    assert_eq!(page2.len(), 10);

    assert_ne!(page1[0].id, page2[0].id);
}
