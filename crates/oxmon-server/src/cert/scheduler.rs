use anyhow::Result;
use chrono::Utc;
use oxmon_common::types::MetricDataPoint;
use oxmon_storage::cert_store::CertStore;
use oxmon_storage::StorageEngine;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{interval, Duration};

use super::checker::check_certificate;

pub struct CertCheckScheduler {
    cert_store: Arc<CertStore>,
    storage: Arc<dyn StorageEngine>,
    default_interval_secs: u64,
    tick_secs: u64,
    connect_timeout_secs: u64,
    max_concurrent: usize,
}

impl CertCheckScheduler {
    pub fn new(
        cert_store: Arc<CertStore>,
        storage: Arc<dyn StorageEngine>,
        default_interval_secs: u64,
        tick_secs: u64,
        connect_timeout_secs: u64,
        max_concurrent: usize,
    ) -> Self {
        Self {
            cert_store,
            storage,
            default_interval_secs,
            tick_secs,
            connect_timeout_secs,
            max_concurrent,
        }
    }

    pub async fn run(&self) {
        tracing::info!(
            tick_secs = self.tick_secs,
            default_interval = self.default_interval_secs,
            max_concurrent = self.max_concurrent,
            "Certificate check scheduler started"
        );

        let mut tick = interval(Duration::from_secs(self.tick_secs));
        loop {
            tick.tick().await;
            if let Err(e) = self.check_due_domains().await {
                tracing::error!(error = %e, "Certificate check cycle failed");
            }
        }
    }

    async fn check_due_domains(&self) -> Result<()> {
        let domains = self
            .cert_store
            .query_domains_due_for_check(self.default_interval_secs)?;

        if domains.is_empty() {
            return Ok(());
        }

        tracing::info!(count = domains.len(), "Checking certificates for due domains");

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut handles = Vec::new();

        for domain in domains {
            let permit = semaphore.clone().acquire_owned().await?;
            let cert_store = self.cert_store.clone();
            let storage = self.storage.clone();
            let timeout = self.connect_timeout_secs;

            let handle = tokio::spawn(async move {
                let result = check_certificate(
                    &domain.domain,
                    domain.port,
                    &domain.id,
                    timeout,
                )
                .await;

                // Write detailed result to cert store
                if let Err(e) = cert_store.insert_check_result(&result) {
                    tracing::error!(domain = %domain.domain, error = %e, "Failed to store check result");
                }

                // Update last_checked_at
                if let Err(e) = cert_store.update_last_checked_at(&domain.id, Utc::now()) {
                    tracing::error!(domain = %domain.domain, error = %e, "Failed to update last_checked_at");
                }

                // Emit MetricDataPoints to partitioned storage
                let now = Utc::now();
                let agent_id = "cert-checker".to_string();
                let mut labels = HashMap::new();
                labels.insert("domain".to_string(), domain.domain.clone());

                let mut data_points = Vec::new();

                // certificate.is_valid
                data_points.push(MetricDataPoint {
                    timestamp: now,
                    agent_id: agent_id.clone(),
                    metric_name: "certificate.is_valid".to_string(),
                    value: if result.is_valid { 1.0 } else { 0.0 },
                    labels: labels.clone(),
                });

                // certificate.days_until_expiry
                if let Some(days) = result.days_until_expiry {
                    data_points.push(MetricDataPoint {
                        timestamp: now,
                        agent_id: agent_id.clone(),
                        metric_name: "certificate.days_until_expiry".to_string(),
                        value: days as f64,
                        labels: labels.clone(),
                    });
                }

                let batch = oxmon_common::types::MetricBatch {
                    agent_id,
                    timestamp: now,
                    data_points,
                };

                if let Err(e) = storage.write_batch(&batch) {
                    tracing::error!(domain = %domain.domain, error = %e, "Failed to write cert metrics");
                }

                if let Some(ref err) = result.error {
                    tracing::warn!(domain = %domain.domain, error = %err, "Certificate check failed");
                } else {
                    tracing::info!(
                        domain = %domain.domain,
                        valid = result.is_valid,
                        days_left = ?result.days_until_expiry,
                        "Certificate checked"
                    );
                }

                drop(permit);
            });

            handles.push(handle);
        }

        for handle in handles {
            if let Err(e) = handle.await {
                tracing::error!(error = %e, "Certificate check task panicked");
            }
        }

        Ok(())
    }
}
