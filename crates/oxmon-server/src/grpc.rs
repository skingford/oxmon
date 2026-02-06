use crate::state::AppState;
use oxmon_storage::StorageEngine;
use chrono::{DateTime, Utc};
use oxmon_common::proto::metric_service_server::MetricService;
use oxmon_common::proto::{MetricBatchProto, ReportResponse};
use oxmon_common::types::{MetricBatch, MetricDataPoint};
use tonic::{Request, Response, Status};

pub struct MetricServiceImpl {
    state: AppState,
}

impl MetricServiceImpl {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl MetricService for MetricServiceImpl {
    async fn report_metrics(
        &self,
        request: Request<MetricBatchProto>,
    ) -> Result<Response<ReportResponse>, Status> {
        let proto = request.into_inner();

        // Validate
        if proto.agent_id.is_empty() {
            return Ok(Response::new(ReportResponse {
                success: false,
                message: "agent_id is required".to_string(),
            }));
        }
        if proto.data_points.is_empty() {
            return Ok(Response::new(ReportResponse {
                success: false,
                message: "data_points cannot be empty".to_string(),
            }));
        }

        // Convert proto to domain types
        let data_points: Vec<MetricDataPoint> = proto
            .data_points
            .into_iter()
            .filter_map(|dp| {
                let timestamp = DateTime::from_timestamp_millis(dp.timestamp_ms)?;
                Some(MetricDataPoint {
                    timestamp,
                    agent_id: dp.agent_id,
                    metric_name: dp.metric_name,
                    value: dp.value,
                    labels: dp.labels,
                })
            })
            .collect();

        let batch_ts = DateTime::from_timestamp_millis(proto.timestamp_ms).unwrap_or_else(Utc::now);

        let batch = MetricBatch {
            agent_id: proto.agent_id.clone(),
            timestamp: batch_ts,
            data_points,
        };

        // Write to storage
        if let Err(e) = self.state.storage.write_batch(&batch) {
            tracing::error!(error = %e, "Failed to write metric batch");
            return Ok(Response::new(ReportResponse {
                success: false,
                message: format!("storage error: {e}"),
            }));
        }

        // Register/update agent
        self.state
            .agent_registry
            .lock()
            .unwrap()
            .update_agent(&proto.agent_id);

        // Feed metrics to alert engine
        {
            let mut engine = self.state.alert_engine.lock().unwrap();
            for dp in &batch.data_points {
                let events = engine.ingest(dp);
                for event in events {
                    // Store alert event
                    if let Err(e) = self.state.storage.write_alert_event(&event) {
                        tracing::error!(error = %e, "Failed to write alert event");
                    }
                    // Send notification
                    let notifier = self.state.notifier.clone();
                    let event_clone = event.clone();
                    tokio::spawn(async move {
                        notifier.notify(&event_clone).await;
                    });
                }
            }
        }

        tracing::debug!(
            agent_id = %proto.agent_id,
            count = batch.data_points.len(),
            "Metrics ingested"
        );

        Ok(Response::new(ReportResponse {
            success: true,
            message: "ok".to_string(),
        }))
    }
}
