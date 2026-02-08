use crate::Collector;
use anyhow::Result;
use chrono::Utc;
use oxmon_common::types::MetricDataPoint;
use std::collections::HashMap;
use sysinfo::System;

pub struct LoadCollector;

impl Default for LoadCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Collector for LoadCollector {
    fn name(&self) -> &str {
        "load"
    }

    fn collect(&mut self, agent_id: &str) -> Result<Vec<MetricDataPoint>> {
        let now = Utc::now();
        let load_avg = System::load_average();
        let uptime = System::uptime();

        let points = vec![
            MetricDataPoint {
                id: oxmon_common::id::next_id(),
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "system.load_1".to_string(),
                value: load_avg.one,
                labels: HashMap::new(),
                created_at: now,
                updated_at: now,
            },
            MetricDataPoint {
                id: oxmon_common::id::next_id(),
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "system.load_5".to_string(),
                value: load_avg.five,
                labels: HashMap::new(),
                created_at: now,
                updated_at: now,
            },
            MetricDataPoint {
                id: oxmon_common::id::next_id(),
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "system.load_15".to_string(),
                value: load_avg.fifteen,
                labels: HashMap::new(),
                created_at: now,
                updated_at: now,
            },
            MetricDataPoint {
                id: oxmon_common::id::next_id(),
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "system.uptime".to_string(),
                value: uptime as f64,
                labels: HashMap::new(),
                created_at: now,
                updated_at: now,
            },
        ];

        Ok(points)
    }
}
