use anyhow::{Context, Result};
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_cloud::collector::CloudCollector;
use oxmon_cloud::{build_provider, CloudAccountConfig, CloudMetrics};
use oxmon_common::id::next_id;
use oxmon_common::types::{MetricBatch, MetricDataPoint};
use oxmon_notify::manager::NotificationManager;
use oxmon_storage::CertStore;
use oxmon_storage::StorageEngine;
use std::collections::{HashMap, HashSet};
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
        // Load all enabled cloud accounts from cloud_accounts table
        let accounts = self
            .cert_store
            .list_cloud_accounts(None, Some(true), 1000, 0)
            .await
            .context("Failed to load cloud accounts")?;

        if accounts.is_empty() {
            return Ok(());
        }

        let now = Utc::now().timestamp();
        let mut all_accounts = Vec::new();
        let mut due_accounts = Vec::new();

        for account in accounts {
            let account_config = CloudAccountConfig {
                secret_id: account.secret_id.clone(),
                secret_key: account.secret_key.clone(),
                regions: account.regions.clone(),
                endpoint: account.endpoint.clone(),
                region_for_sign: account.region_for_sign.clone(),
                collection_interval_secs: account.collection_interval_secs as u64,
                concurrency: 5,
                instance_filter: Default::default(),
            };

            // Check last collection time from cloud_collection_state table
            let state = self
                .cert_store
                .get_cloud_collection_state(&account.config_key)
                .await?;

            let is_due = if let Some(state) = state {
                let elapsed = now - state.last_collected_at;
                elapsed >= account.collection_interval_secs
            } else {
                // Never collected before
                true
            };

            all_accounts.push((
                account.config_key.clone(),
                account.provider.clone(),
                account.account_name.clone(),
                account_config.clone(),
            ));
            if is_due {
                due_accounts.push((
                    account.config_key.clone(),
                    account.provider.clone(),
                    account.account_name.clone(),
                    account_config,
                ));
            }
        }

        // Build providers for ALL enabled accounts to always sync instance status/metadata.
        // providers_for_sync 携带 (config_key, provider_type, provider) 以便后续标记消失实例
        let mut providers_for_sync: Vec<(String, String, Arc<dyn oxmon_cloud::CloudProvider>)> =
            Vec::new();
        let mut account_config_key_map: HashMap<(String, String), String> = HashMap::new();
        for (config_key, provider_type, account_name, account_config) in &all_accounts {
            account_config_key_map.insert(
                (provider_type.clone(), account_name.clone()),
                config_key.clone(),
            );
            match build_provider(provider_type, account_name, account_config.clone()) {
                Ok(provider) => {
                    providers_for_sync.push((
                        config_key.clone(),
                        provider_type.clone(),
                        Arc::from(provider),
                    ));
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

        if providers_for_sync.is_empty() {
            tracing::warn!("No valid cloud providers to sync from");
            return Ok(());
        }

        // First, discover and save all instances from all enabled providers.
        // This keeps cloud_instances status fresh even when metric collection is not due.
        // successful_synced: config_key -> 本次 API 返回的实例 ID 列表（仅成功调用的账号）
        let mut successful_synced: HashMap<String, Vec<String>> = HashMap::new();
        let mut all_instances = Vec::new();
        for (config_key, _provider_type, provider) in &providers_for_sync {
            match provider.list_instances().await {
                Ok(instances) => {
                    let ids: Vec<String> =
                        instances.iter().map(|i| i.instance_id.clone()).collect();
                    successful_synced.insert(config_key.clone(), ids);
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
            // Extract provider/account from instance.provider (format: "{provider}:{account_name}")
            let (provider_type, account_name) = instance
                .provider
                .split_once(':')
                .unwrap_or(("unknown", "unknown"));

            // Find the matching config_key by provider + account_name
            let config_key = account_config_key_map
                .get(&(provider_type.to_string(), account_name.to_string()))
                .cloned()
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

            if let Err(e) = self
                .cert_store
                .upsert_cloud_instance(&oxmon_storage::CloudInstanceRow {
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
                })
                .await
            {
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

        // 将本次 API 未返回的实例标记为 Unknown（仅针对成功完成 API 调用的账号）
        // 这解决了实例被释放后数据库状态停留在"运行中"的问题
        for (config_key, provider_type, _provider) in &providers_for_sync {
            if let Some(known_ids) = successful_synced.get(config_key.as_str()) {
                match self
                    .cert_store
                    .mark_missing_cloud_instances(provider_type, config_key, known_ids)
                    .await
                {
                    Ok(count) if count > 0 => {
                        tracing::info!(
                            config_key = config_key,
                            count = count,
                            "Marked released/missing cloud instances as Unknown"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            config_key = config_key,
                            error = %e,
                            "Failed to mark missing cloud instances"
                        );
                    }
                }
            }
        }

        if due_accounts.is_empty() {
            tracing::info!("No due cloud accounts for metrics collection; status sync only");
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

        // Collect metrics from all providers
        let collector = CloudCollector::new(providers, self.max_concurrent);
        let mut metrics = collector.collect_all().await?;

        // Diagnose collection gaps: discovered instances but no metrics object returned
        // (usually timeout/provider mismatch/error in collector task).
        let discovered_ids: HashSet<String> = all_instances
            .iter()
            .map(|i| i.instance_id.clone())
            .collect();
        let collected_ids: HashSet<String> =
            metrics.iter().map(|m| m.instance_id.clone()).collect();
        let mut missing_ids: Vec<String> =
            discovered_ids.difference(&collected_ids).cloned().collect();
        missing_ids.sort();
        if !missing_ids.is_empty() {
            let sample: Vec<String> = missing_ids.iter().take(20).cloned().collect();
            tracing::warn!(
                discovered_instances = discovered_ids.len(),
                collected_metrics_instances = collected_ids.len(),
                missing_count = missing_ids.len(),
                sample_missing_instance_ids = ?sample,
                "Some cloud instances were discovered but returned no metrics object"
            );
        }

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
                .await
                .context("Failed to write cloud metrics batch")?;

            // Feed cloud metrics to alert engine
            self.evaluate_alerts(&batch.data_points).await;
        }

        // Update collection state for each account
        for (config_key, _provider_type, _account_name, _account_config) in &due_accounts {
            if let Err(e) = self
                .cert_store
                .upsert_cloud_collection_state(
                    config_key,
                    now,
                    batch.data_points.len() as i32,
                    None,
                )
                .await
            {
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
            let core_metrics_all_missing =
                m.cpu_usage.is_none() && m.memory_usage.is_none() && m.disk_usage.is_none();
            if core_metrics_all_missing {
                tracing::warn!(
                    provider = %m.provider,
                    instance_id = %m.instance_id,
                    region = %m.region,
                    "Cloud instance returned no core usage metrics (cpu/memory/disk)"
                );
            }

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
                    timestamp: now,
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
                    timestamp: now,
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
                    timestamp: now,
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
                    timestamp: now,
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
                    timestamp: now,
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
                    timestamp: now,
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
                    timestamp: now,
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
                    timestamp: now,
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
            .get_runtime_setting_string("language", oxmon_common::i18n::DEFAULT_LOCALE)
            .await;

        // Collect all alert events while holding the lock, then drop the lock before awaiting
        let alert_events: Vec<oxmon_common::types::AlertEvent> = {
            let mut engine = self
                .alert_engine
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            let rule_count = engine.rules().len();
            tracing::debug!(
                data_points = data_points.len(),
                rules = rule_count,
                "Evaluating cloud metrics against alert rules"
            );

            data_points
                .iter()
                .flat_map(|dp| {
                    engine
                        .ingest_with_locale(dp, &locale)
                        .into_iter()
                        .map(|o| o.event().clone())
                        .collect::<Vec<_>>()
                })
                .collect()
        };

        let mut fired_count = 0usize;
        for event in alert_events {
            fired_count += 1;
            // Store alert event
            if let Err(e) = self.storage.write_alert_event(&event).await {
                tracing::error!(error = %e, "Failed to write cloud alert event");
            }
            // Log recovery
            if event.status == 3 {
                tracing::info!(
                    rule_id = %event.rule_id,
                    agent_id = %event.agent_id,
                    "Cloud alert auto-recovered"
                );
            } else {
                tracing::info!(
                    rule_id = %event.rule_id,
                    agent_id = %event.agent_id,
                    metric = %event.metric_name,
                    value = event.value,
                    "Cloud alert fired"
                );
            }
            // Send notification
            let notifier = self.notifier.clone();
            tokio::spawn(async move {
                notifier.notify(&event).await;
            });
        }

        if fired_count > 0 {
            tracing::info!(fired = fired_count, "Cloud alert evaluation completed");
        }
    }
}
