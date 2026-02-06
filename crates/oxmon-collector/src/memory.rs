use crate::Collector;
use anyhow::Result;
use chrono::Utc;
use oxmon_common::types::MetricDataPoint;
use std::collections::HashMap;
use sysinfo::System;

pub struct MemoryCollector {
    system: System,
}

impl MemoryCollector {
    pub fn new() -> Self {
        Self {
            system: System::new(),
        }
    }
}

impl Collector for MemoryCollector {
    fn name(&self) -> &str {
        "memory"
    }

    fn collect(&mut self, agent_id: &str) -> Result<Vec<MetricDataPoint>> {
        self.system.refresh_memory();
        let now = Utc::now();
        let mut points = Vec::new();

        let total = self.system.total_memory();
        let used = self.system.used_memory();
        let available = self.system.available_memory();
        let usage_pct = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.to_string(),
            metric_name: "memory.total".to_string(),
            value: total as f64,
            labels: HashMap::new(),
        });
        points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.to_string(),
            metric_name: "memory.used".to_string(),
            value: used as f64,
            labels: HashMap::new(),
        });
        points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.to_string(),
            metric_name: "memory.available".to_string(),
            value: available as f64,
            labels: HashMap::new(),
        });
        points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.to_string(),
            metric_name: "memory.used_percent".to_string(),
            value: usage_pct,
            labels: HashMap::new(),
        });

        // Swap
        let swap_total = self.system.total_swap();
        let swap_used = self.system.used_swap();
        let swap_pct = if swap_total > 0 {
            (swap_used as f64 / swap_total as f64) * 100.0
        } else {
            0.0
        };

        points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.to_string(),
            metric_name: "memory.swap_total".to_string(),
            value: swap_total as f64,
            labels: HashMap::new(),
        });
        points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.to_string(),
            metric_name: "memory.swap_used".to_string(),
            value: swap_used as f64,
            labels: HashMap::new(),
        });
        points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.to_string(),
            metric_name: "memory.swap_percent".to_string(),
            value: swap_pct,
            labels: HashMap::new(),
        });

        Ok(points)
    }
}
