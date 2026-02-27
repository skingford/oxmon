use anyhow::Result;
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_common::types::MetricDataPoint;
use oxmon_notify::cert_report_template::CertAlertDetail;
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

        let total_checked = domains.len() as i32;
        tracing::info!(
            count = total_checked,
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

            // 每个 task 返回 Option<CertAlertDetail>：
            //   - None  → 本域名无告警
            //   - Some  → 有告警，附带结构化信息供批量报告使用
            let handle = tokio::spawn(async move {
                let result =
                    check_certificate(&domain.domain, domain.port, &domain.id, timeout).await;

                // 写入详细检查结果
                if let Err(e) = cert_store.insert_check_result(&result) {
                    tracing::error!(domain = %domain.domain, error = %e, "Failed to store check result");
                }

                // 收集证书详情
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

                // 更新最后检查时间
                if let Err(e) = cert_store.update_last_checked_at(&domain.id, Utc::now()) {
                    tracing::error!(domain = %domain.domain, error = %e, "Failed to update last_checked_at");
                }

                // 写入指标数据点
                let now = Utc::now();
                let agent_id = "cert-checker".to_string();
                let mut labels = HashMap::new();
                labels.insert("domain".to_string(), domain.domain.clone());

                let mut data_points = Vec::new();

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

                // 告警评估：返回 Option<CertAlertDetail>
                let alert_detail = if let Err(e) = storage.write_batch(&batch) {
                    tracing::error!(domain = %domain.domain, error = %e, "Failed to write cert metrics");
                    None
                } else {
                    evaluate_alerts_for_cert(
                        &batch.data_points,
                        &cert_store,
                        &alert_engine,
                        &storage,
                        &notifier,
                        &result,
                    )
                    .await
                };

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
                alert_detail
            });

            handles.push(handle);
        }

        // 收集所有域名的告警明细
        let mut alert_items: Vec<CertAlertDetail> = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Some(item)) => alert_items.push(item),
                Ok(None) => {}
                Err(e) => tracing::error!(error = %e, "Certificate check task panicked"),
            }
        }

        // 有告警则一次性发送批量报告
        if !alert_items.is_empty() {
            let report_date = Utc::now().format("%Y-%m-%d").to_string();
            let locale = self
                .cert_store
                .get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE);

            tracing::info!(
                alert_count = alert_items.len(),
                total_checked = total_checked,
                "Sending cert alert batch report"
            );

            self.notifier
                .send_cert_report(&alert_items, total_checked, &report_date, &locale)
                .await;
        }

        Ok(())
    }
}

/// 评估证书告警规则，将触发的事件写入存储。
///
/// - **恢复事件**（status == 3）：立即通过 `notifier.notify` 单独发送，因为恢复是积极信号，
///   不需要批量聚合。
/// - **非恢复告警**：返回 `Some(CertAlertDetail)` 供调用方批量汇总后统一发送。
/// - **无告警**：返回 `None`。
async fn evaluate_alerts_for_cert(
    data_points: &[MetricDataPoint],
    cert_store: &CertStore,
    alert_engine: &Arc<Mutex<AlertEngine>>,
    storage: &Arc<dyn StorageEngine>,
    notifier: &Arc<NotificationManager>,
    check_result: &oxmon_common::types::CertCheckResult,
) -> Option<CertAlertDetail> {
    let locale =
        cert_store.get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE);

    let mut engine = alert_engine
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut triggered_alerts: Vec<oxmon_common::types::AlertEvent> = Vec::new();

    for dp in data_points {
        let outputs = engine.ingest_with_locale(dp, &locale);
        for output in outputs {
            let event = output.event().clone();

            // 总是写入存储（用于历史查询）
            if let Err(e) = storage.write_alert_event(&event) {
                tracing::error!(error = %e, "Failed to write cert alert event");
            }

            if event.status == 3 {
                // 恢复事件：立即单独通知
                tracing::info!(
                    rule_id = %event.rule_id,
                    agent_id = %event.agent_id,
                    domain = ?event.labels.get("domain"),
                    "Cert alert auto-recovered"
                );
                let notifier_clone = notifier.clone();
                let ev = event.clone();
                tokio::spawn(async move {
                    notifier_clone.notify(&ev).await;
                });
            } else {
                // 普通告警：收集后批量发送
                triggered_alerts.push(event);
            }
        }
    }

    if triggered_alerts.is_empty() {
        return None;
    }

    // 取最严重的事件作为该域名的告警代表
    triggered_alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
    let rep = &triggered_alerts[0];

    let domain = rep
        .labels
        .get("domain")
        .cloned()
        .unwrap_or_else(|| check_result.domain.clone());

    let days = check_result.days_until_expiry.unwrap_or(rep.value as i64);

    let not_after = check_result
        .not_after
        .map(|dt| dt.format("%Y-%m-%d").to_string());

    let issuer = check_result.issuer.clone();

    let severity = match rep.severity {
        oxmon_common::types::Severity::Critical => "critical",
        oxmon_common::types::Severity::Warning => "warning",
        _ => "info",
    };

    Some(CertAlertDetail {
        domain,
        days_until_expiry: days,
        severity: severity.to_string(),
        not_after,
        issuer,
        message: rep.message.clone(),
    })
}
