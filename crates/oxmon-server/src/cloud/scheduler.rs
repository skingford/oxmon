use anyhow::{Context, Result};
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_cloud::collector::CloudCollector;
use oxmon_cloud::{build_provider, CloudAccountConfig, CloudMetrics};
use oxmon_common::id::next_id;
use oxmon_common::types::{MetricBatch, MetricDataPoint};
use oxmon_notify::manager::NotificationManager;
use oxmon_storage::cert_store::CertStore;
use oxmon_storage::StorageEngine;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};

pub struct CloudCheckScheduler {
    cert_store: Arc<CertStore>,
    storage: Arc<dyn StorageEngine>,
    alert_engine: Arc<Mutex<AlertEngine>>,
    notifier: Arc<NotificationManager>,
    default_account_collection_interval_secs: u64,
    tick_secs: u64,
    max_concurrent: usize,
}

impl CloudCheckScheduler {
    pub fn new(
        cert_store: Arc<CertStore>,
        storage: Arc<dyn StorageEngine>,
        alert_engine: Arc<Mutex<AlertEngine>>,
        notifier: Arc<NotificationManager>,
        default_account_collection_interval_secs: u64,
        tick_secs: u64,
        max_concurrent: usize,
    ) -> Self {
        Self {
            cert_store,
            storage,
            alert_engine,
            notifier,
            default_account_collection_interval_secs,
            tick_secs,
            max_concurrent,
        }
    }

    pub async fn run(&self) {
        tracing::info!(
            default_account_collection_interval_secs =
                self.default_account_collection_interval_secs,
            tick_secs = self.tick_secs,
            max_concurrent = self.max_concurrent,
            "Cloud metrics scheduler started"
        );

        let mut tick = interval(Duration::from_secs(self.tick_secs));
        loop {
            tick.tick().await;
            if let Err(e) = self.collect_due_accounts().await {
                tracing::error!(error = %e, "Cloud metrics collection cycle failed");
            }
        }
    }

    async fn collect_due_accounts(&self) -> Result<()> {
        // Load all cloud accounts from system_configs
        let configs = self
            .cert_store
            .list_system_configs(Some("cloud_account"), None, Some(true), 1000, 0)
            .context("Failed to load cloud accounts")?;

        if configs.is_empty() {
            return Ok(());
        }

        let now = Utc::now().timestamp();
        let mut due_accounts = Vec::new();

        for config in configs {
            // Check if this account is due for collection
            let mut config_value: serde_json::Value = serde_json::from_str(&config.config_json)
                .context("Failed to parse cloud account config json")?;
            if config_value
                .get("collection_interval_secs")
                .and_then(|v| v.as_u64())
                .is_none()
            {
                if let Some(obj) = config_value.as_object_mut() {
                    obj.insert(
                        "collection_interval_secs".to_string(),
                        serde_json::json!(self.default_account_collection_interval_secs),
                    );
                }
            }
            let account_config: CloudAccountConfig = serde_json::from_value(config_value)
                .context("Failed to parse cloud account config")?;

            // Check last collection time from cloud_collection_state table
            let state = self
                .cert_store
                .get_cloud_collection_state(&config.config_key)?;

            let is_due = if let Some(state) = state {
                let elapsed = now - state.last_collected_at;
                elapsed >= account_config.collection_interval_secs as i64
            } else {
                // Never collected before
                true
            };

            if is_due {
                // Parse provider type from config_key (e.g., "cloud_tencent_myacct" -> "tencent")
                let provider_type = config
                    .config_key
                    .strip_prefix("cloud_")
                    .and_then(|s| s.split('_').next())
                    .unwrap_or("unknown");

                // Account name is the part after "cloud_{provider}_" (e.g., "myacct")
                let account_name = config
                    .config_key
                    .strip_prefix(&format!("cloud_{}_", provider_type))
                    .unwrap_or("default");

                due_accounts.push((
                    config.config_key.clone(),
                    provider_type.to_string(),
                    account_name.to_string(),
                    account_config,
                ));
            }
        }

        if due_accounts.is_empty() {
            return Ok(());
        }

        tracing::info!(
            count = due_accounts.len(),
            "Collecting cloud metrics for due accounts"
        );

        // Build providers for due accounts
        let mut providers: Vec<Arc<dyn oxmon_cloud::CloudProvider>> = Vec::new();
        for (_config_key, provider_type, account_name, account_config) in &due_accounts {
            match build_provider(provider_type, account_name, account_config.clone()) {
                Ok(provider) => {
                    providers.push(Arc::from(provider));
                }
                Err(e) => {
                    tracing::error!(
                        provider = provider_type,
                        account = account_name,
                        error = %e,
                        "Failed to build cloud provider"
                    );
                }
            }
        }

        if providers.is_empty() {
            tracing::warn!("No valid cloud providers to collect from");
            return Ok(());
        }

        // First, discover and save all instances from all providers
        let mut all_instances = Vec::new();
        for provider in &providers {
            match provider.list_instances().await {
                Ok(instances) => {
                    all_instances.extend(instances);
                }
                Err(e) => {
                    tracing::error!(
                        provider = provider.name(),
                        error = %e,
                        "Failed to list instances"
                    );
                }
            }
        }

        // Write instances to database
        for instance in &all_instances {
            // Extract provider type from instance.provider (format: "tencent:account_name")
            let provider_type = instance.provider.split(':').next().unwrap_or("unknown");

            // Find the matching config_key for this instance
            let config_key = due_accounts
                .iter()
                .find(|(_, pt, _an, _)| pt == provider_type)
                .map(|(ck, _, _, _)| ck.clone())
                .unwrap_or_else(|| format!("cloud_{}_{}", provider_type, "unknown"));

            // 将安全组ID数组序列化为JSON字符串
            let security_group_ids_json = if instance.security_group_ids.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&instance.security_group_ids).unwrap_or_default())
            };

            // 将IPv6地址数组序列化为JSON字符串
            let ipv6_addresses_json = if instance.ipv6_addresses.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&instance.ipv6_addresses).unwrap_or_default())
            };

            // 将tags HashMap序列化为JSON字符串
            let tags_json = if instance.tags.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&instance.tags).unwrap_or_default())
            };

            if let Err(e) = self.cert_store.upsert_cloud_instance(
                &oxmon_storage::cert_store::CloudInstanceRow {
                    id: String::new(), // ID将由 upsert_cloud_instance 内部生成
                    instance_id: instance.instance_id.clone(),
                    instance_name: Some(instance.instance_name.clone()),
                    provider: provider_type.to_string(),
                    account_config_key: config_key,
                    region: instance.region.clone(),
                    public_ip: Some(instance.public_ip.clone()),
                    private_ip: Some(instance.private_ip.clone()),
                    os: Some(instance.os.clone()),
                    status: Some(instance.status.clone()),
                    last_seen_at: now,
                    created_at: now,
                    updated_at: now,
                    instance_type: Some(instance.instance_type.clone()),
                    cpu_cores: instance.cpu_cores.map(|v| v as i32),
                    memory_gb: instance.memory_gb,
                    disk_gb: instance.disk_gb,
                    created_time: instance.created_time,
                    expired_time: instance.expired_time,
                    charge_type: instance.charge_type.clone(),
                    vpc_id: instance.vpc_id.clone(),
                    subnet_id: instance.subnet_id.clone(),
                    security_group_ids: security_group_ids_json,
                    zone: instance.zone.clone(),
                    internet_max_bandwidth: instance.internet_max_bandwidth.map(|v| v as i32),
                    ipv6_addresses: ipv6_addresses_json,
                    eip_allocation_id: instance.eip_allocation_id.clone(),
                    internet_charge_type: instance.internet_charge_type.clone(),
                    image_id: instance.image_id.clone(),
                    hostname: instance.hostname.clone(),
                    description: instance.description.clone(),
                    gpu: instance.gpu.map(|v| v as i32),
                    io_optimized: instance.io_optimized.clone(),
                    latest_operation: instance.latest_operation.clone(),
                    latest_operation_state: instance.latest_operation_state.clone(),
                    tags: tags_json,
                    project_id: instance.project_id.clone(),
                    resource_group_id: instance.resource_group_id.clone(),
                    auto_renew_flag: instance.auto_renew_flag.clone(),
                },
            ) {
                tracing::error!(
                    instance_id = instance.instance_id,
                    error = %e,
                    "Failed to upsert cloud instance"
                );
            }
        }

        tracing::info!(
            instances = all_instances.len(),
            "Saved cloud instances to database"
        );

        // Collect metrics from all providers
        let collector = CloudCollector::new(providers, self.max_concurrent);
        let mut metrics = collector.collect_all().await?;

        tracing::info!(
            collected = metrics.len(),
            "Collected cloud metrics from all providers"
        );

        // Enrich metrics with hardware specs from instances
        let mut enriched_count = 0;
        let mut not_found_count = 0;
        for metric in &mut metrics {
            if let Some(instance) = all_instances
                .iter()
                .find(|i| i.instance_id == metric.instance_id)
            {
                metric.instance_type = instance.instance_type.clone();
                metric.cpu_cores = instance.cpu_cores;
                metric.memory_gb = instance.memory_gb;
                metric.disk_gb = instance.disk_gb;
                enriched_count += 1;
            } else {
                not_found_count += 1;
                tracing::warn!(
                    instance_id = metric.instance_id,
                    "Instance not found for metrics enrichment"
                );
            }
        }
        tracing::info!(
            enriched = enriched_count,
            not_found = not_found_count,
            "Hardware specs enrichment completed"
        );

        // Convert metrics to MetricDataPoint and write to storage
        let batch = self.metrics_to_batch(metrics);
        if !batch.data_points.is_empty() {
            self.storage
                .write_batch(&batch)
                .context("Failed to write cloud metrics batch")?;

            // Feed cloud metrics to alert engine
            self.evaluate_alerts(&batch.data_points).await;
        }

        // Update collection state for each account
        for (config_key, _provider_type, _account_name, _account_config) in &due_accounts {
            if let Err(e) = self.cert_store.upsert_cloud_collection_state(
                config_key,
                now,
                batch.data_points.len() as i32,
                None,
            ) {
                tracing::error!(
                    config_key = config_key,
                    error = %e,
                    "Failed to update collection state"
                );
            }
        }

        Ok(())
    }

    fn metrics_to_batch(&self, metrics: Vec<CloudMetrics>) -> MetricBatch {
        let now = Utc::now();
        let mut data_points = Vec::new();

        for m in metrics {
            // Extract provider type from m.provider (format: "tencent:account_name" or "alibaba:account_name")
            let provider_type = m.provider.split(':').next().unwrap_or("unknown");
            let agent_id = format!("cloud:{}:{}", provider_type, m.instance_id);

            let mut labels = HashMap::new();
            labels.insert("provider".to_string(), m.provider.clone());
            labels.insert("region".to_string(), m.region.clone());
            labels.insert("instance_name".to_string(), m.instance_name.clone());

            // Add hardware specifications as labels
            if !m.instance_type.is_empty() {
                labels.insert("instance_type".to_string(), m.instance_type.clone());
            }
            if let Some(cpu_cores) = m.cpu_cores {
                labels.insert("cpu_cores".to_string(), cpu_cores.to_string());
            }
            if let Some(memory_gb) = m.memory_gb {
                labels.insert("memory_gb".to_string(), format!("{:.1}", memory_gb));
            }
            if let Some(disk_gb) = m.disk_gb {
                labels.insert("disk_gb".to_string(), format!("{:.1}", disk_gb));
            }

            // CPU usage
            if let Some(cpu) = m.cpu_usage {
                data_points.push(MetricDataPoint {
                    id: next_id(),
                    timestamp: m.collected_at,
                    agent_id: agent_id.clone(),
                    metric_name: "cloud.cpu.usage".to_string(),
                    value: cpu,
                    labels: labels.clone(),
                    created_at: now,
                    updated_at: now,
                });
            }

            // Memory usage
            if let Some(memory) = m.memory_usage {
                data_points.push(MetricDataPoint {
                    id: next_id(),
                    timestamp: m.collected_at,
                    agent_id: agent_id.clone(),
                    metric_name: "cloud.memory.usage".to_string(),
                    value: memory,
                    labels: labels.clone(),
                    created_at: now,
                    updated_at: now,
                });
            }

            // Disk usage
            if let Some(disk) = m.disk_usage {
                data_points.push(MetricDataPoint {
                    id: next_id(),
                    timestamp: m.collected_at,
                    agent_id: agent_id.clone(),
                    metric_name: "cloud.disk.usage".to_string(),
                    value: disk,
                    labels: labels.clone(),
                    created_at: now,
                    updated_at: now,
                });
            }

            // Network in bytes
            if let Some(network_in) = m.network_in_bytes {
                data_points.push(MetricDataPoint {
                    id: next_id(),
                    timestamp: m.collected_at,
                    agent_id: agent_id.clone(),
                    metric_name: "cloud.network.in_bytes".to_string(),
                    value: network_in,
                    labels: labels.clone(),
                    created_at: now,
                    updated_at: now,
                });
            }

            // Network out bytes
            if let Some(network_out) = m.network_out_bytes {
                data_points.push(MetricDataPoint {
                    id: next_id(),
                    timestamp: m.collected_at,
                    agent_id: agent_id.clone(),
                    metric_name: "cloud.network.out_bytes".to_string(),
                    value: network_out,
                    labels: labels.clone(),
                    created_at: now,
                    updated_at: now,
                });
            }

            // Disk read IOPS
            if let Some(disk_read) = m.disk_iops_read {
                data_points.push(MetricDataPoint {
                    id: next_id(),
                    timestamp: m.collected_at,
                    agent_id: agent_id.clone(),
                    metric_name: "cloud.disk.iops_read".to_string(),
                    value: disk_read,
                    labels: labels.clone(),
                    created_at: now,
                    updated_at: now,
                });
            }

            // Disk write IOPS
            if let Some(disk_write) = m.disk_iops_write {
                data_points.push(MetricDataPoint {
                    id: next_id(),
                    timestamp: m.collected_at,
                    agent_id: agent_id.clone(),
                    metric_name: "cloud.disk.iops_write".to_string(),
                    value: disk_write,
                    labels: labels.clone(),
                    created_at: now,
                    updated_at: now,
                });
            }

            // TCP connections
            if let Some(conns) = m.connections {
                data_points.push(MetricDataPoint {
                    id: next_id(),
                    timestamp: m.collected_at,
                    agent_id: agent_id.clone(),
                    metric_name: "cloud.connections".to_string(),
                    value: conns,
                    labels,
                    created_at: now,
                    updated_at: now,
                });
            }
        }

        MetricBatch {
            agent_id: "cloud-scheduler".to_string(),
            timestamp: now,
            data_points,
        }
    }

    /// Evaluate alert rules for cloud metrics and send notifications
    async fn evaluate_alerts(&self, data_points: &[MetricDataPoint]) {
        let locale = self
            .cert_store
            .get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE);

        let mut engine = self
            .alert_engine
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        for dp in data_points {
            let outputs = engine.ingest_with_locale(dp, &locale);
            for output in outputs {
                let event = output.event().clone();
                // Store alert event
                if let Err(e) = self.storage.write_alert_event(&event) {
                    tracing::error!(error = %e, "Failed to write cloud alert event");
                }
                // Log recovery
                if event.status == 3 {
                    tracing::info!(
                        rule_id = %event.rule_id,
                        agent_id = %event.agent_id,
                        "Cloud alert auto-recovered"
                    );
                }
                // Send notification
                let notifier = self.notifier.clone();
                tokio::spawn(async move {
                    notifier.notify(&event).await;
                });
            }
        }
    }
}
