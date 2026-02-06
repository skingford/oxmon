pub mod cpu;
pub mod disk;
pub mod load;
pub mod memory;
pub mod network;

use anyhow::Result;
use oxmon_common::types::MetricDataPoint;

pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    fn collect(&mut self, agent_id: &str) -> Result<Vec<MetricDataPoint>>;
}
