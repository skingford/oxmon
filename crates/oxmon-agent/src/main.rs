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
use oxmon_common::proto::{MetricBatchProto, MetricDataPointProto, SystemInfoProto};
use oxmon_common::types::MetricDataPoint;
use sysinfo::{Disks, System};
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

fn collect_system_info() -> SystemInfoProto {
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = System::host_name().unwrap_or_default();
    let os = System::name().unwrap_or_default();
    let os_version = System::os_version().unwrap_or_default();
    let arch = System::cpu_arch();
    let kernel_version = System::kernel_version().unwrap_or_default();
    let cpu_cores = sys.cpus().len() as i32;
    let memory_gb = sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0;

    let disks = Disks::new_with_refreshed_list();
    let disk_gb = disks
        .iter()
        .map(|d| d.total_space() as f64)
        .sum::<f64>()
        / 1024.0
        / 1024.0
        / 1024.0;

    SystemInfoProto {
        hostname,
        os,
        os_version,
        arch,
        kernel_version,
        cpu_cores,
        memory_gb,
        disk_gb,
    }
}

fn to_proto_batch(
    agent_id: &str,
    points: &[MetricDataPoint],
    system_info: Option<SystemInfoProto>,
) -> MetricBatchProto {
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
        system_info,
    }
}

async fn try_connect(endpoint: &str) -> Option<MetricServiceClient<Channel>> {
    match MetricServiceClient::connect(endpoint.to_string()).await {
        Ok(client) => {
            tracing::info!("Connected to server");
            Some(
                client
                    .max_encoding_message_size(32 * 1024 * 1024)
                    .max_decoding_message_size(32 * 1024 * 1024),
            )
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

    // Max points per gRPC request to avoid HTTP/2 FRAME_SIZE_ERROR
    const SEND_CHUNK_SIZE: usize = 500;
    // 每隔多少 tick 重新上报一次系统信息（默认 60 次，约 10 分钟）
    const SYSTEM_INFO_INTERVAL_TICKS: u64 = 60;
    let mut tick_count: u64 = 0;

    tracing::info!(
        interval_secs = config.collection_interval_secs,
        buffer_max = config.buffer_max_size,
        server = %config.grpc_endpoint(),
        "Starting collection loop"
    );

    loop {
        tokio::select! {
            _ = tick.tick() => {
                tick_count += 1;

                // Collect metrics
                let mut all_points = Vec::new();
                for collector in &mut collectors {
                    match collector.collect(&config.agent_id) {
                        Ok(points) => all_points.extend(points),
                        Err(e) => tracing::warn!(collector = collector.name(), error = %e, "Collection failed"),
                    }
                }

                tracing::info!(count = all_points.len(), "Collected metrics");

                // Try to connect if not connected
                if client.is_none() {
                    client = try_connect(&config.grpc_endpoint()).await;
                }

                // Try to send (current batch + buffered)
                let mut connection_failed = false;
                if let Some(ref mut c) = client {
                    // Drain any previously buffered data and combine with current batch
                    let mut buf = buffer.lock().await;
                    let mut to_send = buf.drain_all();
                    to_send.extend(all_points);

                    if !to_send.is_empty() {
                        let total = to_send.len();
                        let mut failed_idx: Option<usize> = None;

                        // 每 SYSTEM_INFO_INTERVAL_TICKS 次采集一次系统信息，附在第一个 chunk
                        let should_send_sysinfo = tick_count == 1
                            || tick_count % SYSTEM_INFO_INTERVAL_TICKS == 0;
                        let sysinfo = if should_send_sysinfo {
                            Some(collect_system_info())
                        } else {
                            None
                        };

                        // Send in chunks to avoid oversized gRPC messages
                        for (chunk_idx, chunk) in to_send.chunks(SEND_CHUNK_SIZE).enumerate() {
                            // 系统信息只附在第一个 chunk
                            let si = if chunk_idx == 0 { sysinfo.clone() } else { None };
                            let batch = to_proto_batch(&config.agent_id, chunk, si);

                            let mut request = tonic::Request::new(batch);
                            if let Some(ref token) = config.auth_token {
                                if let Ok(auth_val) = format!("Bearer {}", token).parse() {
                                    request.metadata_mut().insert("authorization", auth_val);
                                }
                                if let Ok(agent_val) = config.agent_id.parse() {
                                    request.metadata_mut().insert("agent-id", agent_val);
                                }
                            }

                            match c.report_metrics(request).await {
                                Ok(resp) => {
                                    let resp = resp.into_inner();
                                    if resp.success {
                                        tracing::info!(count = chunk.len(), "Metrics chunk reported");
                                    } else {
                                        tracing::warn!(message = %resp.message, "Server rejected batch chunk");
                                        failed_idx = Some(chunk_idx * SEND_CHUNK_SIZE);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to send metrics, buffering");
                                    failed_idx = Some(chunk_idx * SEND_CHUNK_SIZE);
                                    connection_failed = true;
                                    break;
                                }
                            }
                        }

                        if let Some(idx) = failed_idx {
                            buf.push_batch(to_send[idx..].to_vec());
                        } else {
                            tracing::info!(total, "All metrics reported successfully");
                        }
                    }
                } else {
                    // Buffer for later
                    let mut buf = buffer.lock().await;
                    let buffered = buf.len();
                    buf.push_batch(all_points);
                    tracing::debug!(buffered = buf.len(), "No connection, buffering metrics (was {buffered})");
                }

                if connection_failed {
                    client = None; // Force reconnect next tick
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
