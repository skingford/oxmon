use crate::Collector;
use anyhow::Result;
use chrono::Utc;
use oxmon_common::types::MetricDataPoint;
use std::collections::HashMap;
use sysinfo::Networks;

pub struct NetworkCollector {
    networks: Networks,
    prev_received: HashMap<String, u64>,
    prev_transmitted: HashMap<String, u64>,
    prev_packets_received: HashMap<String, u64>,
    prev_packets_transmitted: HashMap<String, u64>,
}

impl NetworkCollector {
    pub fn new() -> Self {
        let networks = Networks::new_with_refreshed_list();
        Self {
            networks,
            prev_received: HashMap::new(),
            prev_transmitted: HashMap::new(),
            prev_packets_received: HashMap::new(),
            prev_packets_transmitted: HashMap::new(),
        }
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &str {
        "network"
    }

    fn collect(&mut self, agent_id: &str) -> Result<Vec<MetricDataPoint>> {
        self.networks.refresh();
        let now = Utc::now();
        let mut points = Vec::new();

        for (name, data) in self.networks.iter() {
            let mut labels = HashMap::new();
            labels.insert("interface".to_string(), name.clone());

            let received = data.total_received();
            let transmitted = data.total_transmitted();
            let packets_received = data.total_packets_received();
            let packets_transmitted = data.total_packets_transmitted();

            // Calculate delta (bytes/sec approximation per collection interval)
            let rx_delta = received.saturating_sub(
                *self.prev_received.get(name).unwrap_or(&received),
            );
            let tx_delta = transmitted.saturating_sub(
                *self.prev_transmitted.get(name).unwrap_or(&transmitted),
            );
            let prx_delta = packets_received.saturating_sub(
                *self.prev_packets_received.get(name).unwrap_or(&packets_received),
            );
            let ptx_delta = packets_transmitted.saturating_sub(
                *self.prev_packets_transmitted.get(name).unwrap_or(&packets_transmitted),
            );

            self.prev_received.insert(name.clone(), received);
            self.prev_transmitted.insert(name.clone(), transmitted);
            self.prev_packets_received.insert(name.clone(), packets_received);
            self.prev_packets_transmitted.insert(name.clone(), packets_transmitted);

            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "network.bytes_recv".to_string(),
                value: rx_delta as f64,
                labels: labels.clone(),
            });
            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "network.bytes_sent".to_string(),
                value: tx_delta as f64,
                labels: labels.clone(),
            });
            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "network.packets_recv".to_string(),
                value: prx_delta as f64,
                labels: labels.clone(),
            });
            points.push(MetricDataPoint {
                timestamp: now,
                agent_id: agent_id.to_string(),
                metric_name: "network.packets_sent".to_string(),
                value: ptx_delta as f64,
                labels,
            });
        }

        Ok(points)
    }
}
