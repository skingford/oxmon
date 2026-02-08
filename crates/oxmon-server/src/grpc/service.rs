use crate::state::AppState;
use crate::grpc::auth::AuthInterceptor;
use oxmon_storage::StorageEngine;
use chrono::{DateTime, Utc};
use oxmon_common::proto::metric_service_server::MetricService;
use oxmon_common::proto::{MetricBatchProto, ReportResponse};
use oxmon_common::types::{MetricBatch, MetricDataPoint};
use tonic::{Request, Response, Status};

pub struct MetricServiceImpl {
    state: AppState,
    auth: AuthInterceptor,
}

impl MetricServiceImpl {
    pub fn new(state: AppState, require_auth: bool) -> Self {
        let auth = AuthInterceptor::new(state.cert_store.clone(), require_auth);
        Self { state, auth }
    }
}

#[tonic::async_trait]
impl MetricService for MetricServiceImpl {
    async fn report_metrics(
        &self,
        mut request: Request<MetricBatchProto>,
    ) -> Result<Response<ReportResponse>, Status> {
        // 认证检查（如果启用）
        if self.auth.require_auth {
            // 从 metadata 中提取并验证
            let metadata = request.metadata();

            let token = metadata
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or_else(|| Status::unauthenticated("Missing or invalid authorization header"))?
                .to_string();

            let agent_id = metadata
                .get("agent-id")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Status::unauthenticated("Missing agent-id in metadata"))?
                .to_string();

            // 从数据库获取 token 和 hash
            let (stored_token, token_hash) = self
                .state
                .cert_store
                .get_agent_auth(&agent_id)
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to query agent whitelist");
                    Status::internal("Authentication error")
                })?
                .ok_or_else(|| {
                    tracing::warn!(agent_id = %agent_id, "Agent not in whitelist");
                    Status::unauthenticated("Agent not authorized")
                })?;

            // 验证 token：优先直接比对，兼容旧 bcrypt 数据
            let valid = if let Some(ref stored) = stored_token {
                stored == &token
            } else {
                oxmon_storage::auth::verify_token(&token, &token_hash).map_err(|e| {
                    tracing::error!(error = %e, "Token verification failed");
                    Status::internal("Authentication error")
                })?
            };

            if !valid {
                tracing::warn!(agent_id = %agent_id, "Invalid token");
                return Err(Status::unauthenticated("Invalid token"));
            }

            // 将 agent_id 注入到 request extensions 中
            request.extensions_mut().insert(agent_id.clone());
            tracing::debug!(agent_id = %agent_id, "Agent authenticated successfully");
        }

        // 从 extensions 中获取认证的 agent_id（如果有）
        let authenticated_agent_id = request.extensions().get::<String>().cloned();

        if let Some(agent_id) = &authenticated_agent_id {
            tracing::debug!(agent_id = %agent_id, "Request from authenticated agent");
        }

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
                    id: oxmon_common::id::next_id(),
                    timestamp,
                    agent_id: dp.agent_id,
                    metric_name: dp.metric_name,
                    value: dp.value,
                    labels: dp.labels,
                    created_at: timestamp,
                    updated_at: timestamp,
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
