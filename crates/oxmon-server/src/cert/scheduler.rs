use anyhow::Result;
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_common::types::MetricDataPoint;
use oxmon_notify::manager::NotificationManager;
use oxmon_storage::cert_store::CertStore;
use oxmon_storage::StorageEngine;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tokio::time::{interval, Duration};

use super::checker::check_certificate;
use super::collector::CertificateCollector;

pub struct CertCheckScheduler {
    cert_store: Arc<CertStore>,
    storage: Arc<dyn StorageEngine>,
    alert_engine: Arc<Mutex<AlertEngine>>,
    notifier: Arc<NotificationManager>,
    default_interval_secs: u64,
    tick_secs: u64,
    connect_timeout_secs: u64,
    max_concurrent: usize,
}

impl CertCheckScheduler {
    pub fn new(
        cert_store: Arc<CertStore>,
        storage: Arc<dyn StorageEngine>,
        alert_engine: Arc<Mutex<AlertEngine>>,
        notifier: Arc<NotificationManager>,
        default_interval_secs: u64,
        tick_secs: u64,
        connect_timeout_secs: u64,
        max_concurrent: usize,
    ) -> Self {
        Self {
            cert_store,
            storage,
            alert_engine,
            notifier,
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

        tracing::info!(
            count = domains.len(),
            "Checking certificates for due domains"
        );

        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut handles = Vec::new();

        for domain in domains {
            let permit = semaphore.clone().acquire_owned().await?;
            let cert_store = self.cert_store.clone();
            let storage = self.storage.clone();
            let alert_engine = self.alert_engine.clone();
            let notifier = self.notifier.clone();
            let timeout = self.connect_timeout_secs;

            let handle = tokio::spawn(async move {
                let result =
                    check_certificate(&domain.domain, domain.port, &domain.id, timeout).await;

                // Write detailed result to cert store
                if let Err(e) = cert_store.insert_check_result(&result) {
                    tracing::error!(domain = %domain.domain, error = %e, "Failed to store check result");
                }

                // Collect detailed certificate information
                match CertificateCollector::new(timeout).await {
                    Ok(collector) => {
                        match collector.collect(&domain.domain, domain.port as u16).await {
                            Ok(details) => {
                                if let Err(e) = cert_store.upsert_certificate_details(&details) {
                                    tracing::error!(domain = %domain.domain, error = %e, "Failed to store certificate details");
                                } else {
                                    tracing::debug!(domain = %domain.domain, "Certificate details stored");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(domain = %domain.domain, error = %e, "Failed to collect certificate details");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to create certificate collector");
                    }
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
                    id: oxmon_common::id::next_id(),
                    timestamp: now,
                    agent_id: agent_id.clone(),
                    metric_name: "certificate.is_valid".to_string(),
                    value: if result.is_valid { 1.0 } else { 0.0 },
                    labels: labels.clone(),
                    created_at: now,
                    updated_at: now,
                });

                // certificate.days_until_expiry
                if let Some(days) = result.days_until_expiry {
                    data_points.push(MetricDataPoint {
                        id: oxmon_common::id::next_id(),
                        timestamp: now,
                        agent_id: agent_id.clone(),
                        metric_name: "certificate.days_until_expiry".to_string(),
                        value: days as f64,
                        labels: labels.clone(),
                        created_at: now,
                        updated_at: now,
                    });
                }

                let batch = oxmon_common::types::MetricBatch {
                    agent_id,
                    timestamp: now,
                    data_points,
                };

                if let Err(e) = storage.write_batch(&batch) {
                    tracing::error!(domain = %domain.domain, error = %e, "Failed to write cert metrics");
                } else {
                    // Feed cert metrics to alert engine
                    evaluate_alerts_for_cert(
                        &batch.data_points,
                        &cert_store,
                        &alert_engine,
                        &storage,
                        &notifier,
                    )
                    .await;
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

/// Feed cert metrics to the alert engine and dispatch any triggered notifications.
async fn evaluate_alerts_for_cert(
    data_points: &[MetricDataPoint],
    cert_store: &CertStore,
    alert_engine: &Arc<std::sync::Mutex<AlertEngine>>,
    storage: &Arc<dyn StorageEngine>,
    notifier: &Arc<NotificationManager>,
) {
    let locale =
        cert_store.get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE);

    let mut engine = alert_engine
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    for dp in data_points {
        let outputs = engine.ingest_with_locale(dp, &locale);
        for output in outputs {
            let event = output.event().clone();
            if let Err(e) = storage.write_alert_event(&event) {
                tracing::error!(error = %e, "Failed to write cert alert event");
            }
            if event.status == 3 {
                tracing::info!(
                    rule_id = %event.rule_id,
                    agent_id = %event.agent_id,
                    "Cert alert auto-recovered"
                );
            }
            let notifier = notifier.clone();
            tokio::spawn(async move {
                notifier.notify(&event).await;
            });
        }
    }
}
