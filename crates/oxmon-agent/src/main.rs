mod config;

use anyhow::Result;
use chrono::Utc;
use oxmon_collector::cpu::CpuCollector;
use oxmon_collector::disk::DiskCollector;
use oxmon_collector::load::LoadCollector;
use oxmon_collector::memory::MemoryCollector;
use oxmon_collector::network::NetworkCollector;
use oxmon_collector::Collector;
use oxmon_common::proto::metric_service_client::MetricServiceClient;
use oxmon_common::proto::{MetricBatchProto, MetricDataPointProto};
use oxmon_common::types::MetricDataPoint;
use std::collections::VecDeque;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tonic::transport::Channel;
use tracing_subscriber::EnvFilter;

struct MetricBuffer {
    buffer: VecDeque<MetricDataPoint>,
    max_size: usize,
}

impl MetricBuffer {
    fn new(max_size: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    fn push_batch(&mut self, points: Vec<MetricDataPoint>) {
        for point in points {
            if self.buffer.len() >= self.max_size {
                self.buffer.pop_front();
            }
            self.buffer.push_back(point);
        }
    }

    fn drain_all(&mut self) -> Vec<MetricDataPoint> {
        self.buffer.drain(..).collect()
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }
}

fn to_proto_batch(agent_id: &str, points: &[MetricDataPoint]) -> MetricBatchProto {
    MetricBatchProto {
        agent_id: agent_id.to_string(),
        timestamp_ms: Utc::now().timestamp_millis(),
        data_points: points
            .iter()
            .map(|dp| MetricDataPointProto {
                timestamp_ms: dp.timestamp.timestamp_millis(),
                agent_id: dp.agent_id.clone(),
                metric_name: dp.metric_name.clone(),
                value: dp.value,
                labels: dp.labels.clone(),
            })
            .collect(),
    }
}

async fn try_connect(endpoint: &str) -> Option<MetricServiceClient<Channel>> {
    match MetricServiceClient::connect(endpoint.to_string()).await {
        Ok(client) => {
            tracing::info!("Connected to server");
            Some(client)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to connect to server");
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("oxmon=info".parse()?))
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config/agent.toml".to_string());

    let config = config::AgentConfig::load(&config_path)?;
    tracing::info!(agent_id = %config.agent_id, "oxmon-agent starting");

    let mut collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(CpuCollector::new()),
        Box::new(MemoryCollector::new()),
        Box::new(DiskCollector::new()),
        Box::new(NetworkCollector::new()),
        Box::new(LoadCollector::new()),
    ];

    let buffer = std::sync::Arc::new(Mutex::new(MetricBuffer::new(config.buffer_max_size)));
    let mut tick = interval(Duration::from_secs(config.collection_interval_secs));
    let mut client: Option<MetricServiceClient<Channel>> = None;

    tracing::info!(
        interval_secs = config.collection_interval_secs,
        buffer_max = config.buffer_max_size,
        server = %config.server_endpoint,
        "Starting collection loop"
    );

    loop {
        tokio::select! {
            _ = tick.tick() => {
                // Collect metrics
                let mut all_points = Vec::new();
                for collector in &mut collectors {
                    match collector.collect(&config.agent_id) {
                        Ok(points) => all_points.extend(points),
                        Err(e) => tracing::warn!(collector = collector.name(), error = %e, "Collection failed"),
                    }
                }

                tracing::debug!(count = all_points.len(), "Collected metrics");

                // Try to connect if not connected
                if client.is_none() {
                    client = try_connect(&config.server_endpoint).await;
                }

                // Try to send (current batch + buffered)
                if let Some(ref mut c) = client {
                    let mut buf = buffer.lock().await;
                    buf.push_batch(all_points);
                    let to_send = buf.drain_all();

                    if !to_send.is_empty() {
                        let batch = to_proto_batch(&config.agent_id, &to_send);
                        match c.report_metrics(batch).await {
                            Ok(resp) => {
                                let resp = resp.into_inner();
                                if resp.success {
                                    tracing::debug!(count = to_send.len(), "Metrics reported");
                                } else {
                                    tracing::warn!(message = %resp.message, "Server rejected batch");
                                    buf.push_batch(to_send);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to send metrics, buffering");
                                buf.push_batch(to_send);
                                client = None; // Force reconnect
                            }
                        }
                    }
                } else {
                    // Buffer for later
                    let mut buf = buffer.lock().await;
                    let buffered = buf.len();
                    buf.push_batch(all_points);
                    tracing::debug!(buffered = buf.len(), "No connection, buffering metrics (was {buffered})");
                }
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Shutting down gracefully");
                break;
            }
        }
    }

    Ok(())
}
