use crate::Collector;
use anyhow::Result;
use chrono::Utc;
use oxmon_common::types::MetricDataPoint;
use std::collections::HashMap;
use sysinfo::Disks;

pub struct DiskCollector {
    disks: Disks,
}

impl DiskCollector {
    pub fn new() -> Self {
        Self {
            disks: Disks::new_with_refreshed_list(),
        }
    }
}

impl Collector for DiskCollector {
    fn name(&self) -> &str {
        "disk"
    }

    fn collect(&mut self, agent_id: &str) -> Result<Vec<MetricDataPoint>> {
        self.disks.refresh();
        let now = Utc::now();
        let mut points = Vec::new();

        for disk in self.disks.iter() {
            let mount = disk.mount_point().to_string_lossy().to_string();
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            let usage_pct = if total > 0 {
                (used as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let mut labels = HashMap::new();
            labels.insert("mount".to_string(), mount);

            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "disk.total".to_string(),
                value: total as f64,
                labels: labels.clone(),
            });
            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "disk.used".to_string(),
                value: used as f64,
                labels: labels.clone(),
            });
            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "disk.available".to_string(),
                value: available as f64,
                labels: labels.clone(),
            });
            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "disk.used_percent".to_string(),
                value: usage_pct,
                labels,
            });
        }

        Ok(points)
    }
}
