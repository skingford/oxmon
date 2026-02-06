use crate::Collector;
use anyhow::Result;
use chrono::Utc;
use oxmon_common::types::MetricDataPoint;
use std::collections::HashMap;
use sysinfo::System;

pub struct CpuCollector {
    system: System,
}

impl CpuCollector {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_cpu_all();
        Self { system }
    }
}

impl Collector for CpuCollector {
    fn name(&self) -> &str {
        "cpu"
    }

    fn collect(&mut self, agent_id: &str) -> Result<Vec<MetricDataPoint>> {
        self.system.refresh_cpu_all();
        let now = Utc::now();
        let mut points = Vec::new();

        let global_usage = self.system.global_cpu_usage();
        points.push(MetricDataPoint {
            timestamp: now,
            agent_id: agent_id.to_string(),
            metric_name: "cpu.usage".to_string(),
            value: global_usage as f64,
            labels: HashMap::new(),
        });

        for (i, cpu) in self.system.cpus().iter().enumerate() {
            let mut labels = HashMap::new();
            labels.insert("core".to_string(), i.to_string());
            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "cpu.core_usage".to_string(),
                value: cpu.cpu_usage() as f64,
                labels,
            });
        }

        Ok(points)
    }
}
