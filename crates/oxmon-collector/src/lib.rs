//! Metric collection framework for the oxmon agent.
//!
//! Each [`Collector`] implementation gathers a specific category of system
//! metrics (CPU, memory, disk, network, load) and returns them as a vector
//! of [`MetricDataPoint`]s ready for gRPC transport.

pub mod cpu;
pub mod disk;
pub mod load;
pub mod memory;
pub mod network;

use anyhow::Result;
use oxmon_common::types::MetricDataPoint;

/// A system metric collector that runs on the agent host.
///
/// Implementations are registered in the agent's collection loop and called
/// at each collection interval. The trait requires `Send + Sync` to support
/// concurrent collection across multiple threads.
pub trait Collector: Send + Sync {
    /// Returns the collector name (e.g., `"cpu"`, `"disk"`), used for logging
    /// and metric namespacing.
    fn name(&self) -> &str;

    /// Collects current metric values for the given `agent_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying system API call fails.
    fn collect(&mut self, agent_id: &str) -> Result<Vec<MetricDataPoint>>;
}
