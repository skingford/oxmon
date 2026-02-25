use crate::{CloudMetrics, CloudProvider};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Cloud metrics collector that orchestrates concurrent collection from multiple providers
pub struct CloudCollector {
    providers: Vec<Arc<dyn CloudProvider>>,
    concurrency: usize,
    timeout_secs: u64,
}

impl CloudCollector {
    pub fn new(providers: Vec<Arc<dyn CloudProvider>>, concurrency: usize) -> Self {
        Self {
            providers,
            concurrency,
            timeout_secs: 30, // 30 seconds timeout per instance
        }
    }

    /// Collect metrics from all providers
    pub async fn collect_all(&self) -> Result<Vec<CloudMetrics>> {
        let mut all_metrics = Vec::new();

        // Step 1: Discover all instances from all providers
        let mut all_instances = Vec::new();
        for provider in &self.providers {
            match provider.list_instances().await {
                Ok(instances) => {
                    tracing::info!(
                        "Discovered {} instances from provider {}",
                        instances.len(),
                        provider.name()
                    );
                    all_instances.extend(instances);
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to list instances from provider {}: {}",
                        provider.name(),
                        e
                    );
                }
            }
        }

        if all_instances.is_empty() {
            tracing::warn!("No cloud instances discovered");
            return Ok(Vec::new());
        }

        // Step 2: Collect metrics concurrently with semaphore-bounded concurrency
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = Vec::new();

        for instance in all_instances {
            let sem = Arc::clone(&semaphore);
            let providers = self.providers.clone();
            let timeout_duration = Duration::from_secs(self.timeout_secs);

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                // Find the matching provider for this instance
                let provider_opt: Option<&Arc<dyn CloudProvider>> = providers.iter().find(|p| {
                    // Check if the instance provider matches this provider
                    // instance.provider format: "tencent:account_name" or "alibaba:account_name" or "mock:account_name"
                    instance.provider.ends_with(&format!(":{}", p.name()))
                });

                if provider_opt.is_none() {
                    tracing::warn!("No provider found for instance {}", instance.instance_id);
                    return None;
                }

                let provider = provider_opt.unwrap();

                // Collect metrics with timeout
                match timeout(
                    timeout_duration,
                    provider.get_metrics(&instance.instance_id, &instance.region),
                )
                .await
                {
                    Ok(Ok(mut metrics)) => {
                        // Fill in instance name from discovered metadata
                        metrics.instance_name = instance.instance_name.clone();
                        Some(metrics)
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            "Failed to collect metrics for instance {}: {}",
                            instance.instance_id,
                            e
                        );
                        None
                    }
                    Err(_) => {
                        tracing::warn!(
                            "Timeout collecting metrics for instance {} after {:?}",
                            instance.instance_id,
                            timeout_duration
                        );
                        None
                    }
                }
            });

            tasks.push(task);
        }

        // Wait for all tasks to complete
        for task in tasks {
            match task.await {
                Ok(Some(metrics)) => {
                    all_metrics.push(metrics);
                }
                Ok(None) => {
                    // Already logged in the task
                }
                Err(e) => {
                    tracing::error!("Task panicked: {}", e);
                }
            }
        }

        tracing::info!("Collected metrics from {} instances", all_metrics.len());
        Ok(all_metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CloudInstance, CloudProvider};
    use async_trait::async_trait;

    struct MockProvider {
        name: String,
        instances: Vec<CloudInstance>,
    }

    #[async_trait]
    impl CloudProvider for MockProvider {
        fn name(&self) -> &str {
            &self.name
        }

        async fn list_instances(&self) -> Result<Vec<CloudInstance>> {
            Ok(self.instances.clone())
        }

        async fn get_metrics(&self, instance_id: &str, region: &str) -> Result<CloudMetrics> {
            Ok(CloudMetrics {
                instance_id: instance_id.to_string(),
                instance_name: "test-instance".to_string(),
                provider: self.name.clone(),
                region: region.to_string(),
                cpu_usage: Some(50.0),
                memory_usage: Some(60.0),
                disk_usage: Some(70.0),
                network_in_bytes: Some(1024.0),
                network_out_bytes: Some(2048.0),
                disk_iops_read: Some(100.0),
                disk_iops_write: Some(50.0),
                connections: Some(200.0),
                collected_at: chrono::Utc::now(),
                instance_type: String::new(),
                cpu_cores: None,
                memory_gb: None,
                disk_gb: None,
            })
        }
    }

    #[tokio::test]
    async fn test_cloud_collector() {
        let mock_provider: Arc<dyn CloudProvider> = Arc::new(MockProvider {
            name: "mock".to_string(),
            instances: vec![CloudInstance {
                instance_id: "ins-123".to_string(),
                instance_name: "test-instance".to_string(),
                provider: "mock:mock".to_string(),
                region: "test-region".to_string(),
                public_ip: "1.2.3.4".to_string(),
                private_ip: "10.0.0.1".to_string(),
                os: "Linux".to_string(),
                status: "Running".to_string(),
                tags: std::collections::HashMap::new(),
                instance_type: "mock.large".to_string(),
                cpu_cores: Some(2),
                memory_gb: Some(4.0),
                disk_gb: Some(50.0),
                created_time: None,
                expired_time: None,
                charge_type: None,
                vpc_id: None,
                subnet_id: None,
                security_group_ids: vec![],
                zone: None,
                internet_max_bandwidth: None,
                ipv6_addresses: vec![],
                eip_allocation_id: None,
                internet_charge_type: None,
                image_id: None,
                hostname: None,
                description: None,
                gpu: None,
                io_optimized: None,
                latest_operation: None,
                latest_operation_state: None,
                project_id: None,
                resource_group_id: None,
                auto_renew_flag: None,
            }],
        });

        let collector = CloudCollector::new(vec![mock_provider], 5);
        let metrics = collector.collect_all().await.unwrap();

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].instance_id, "ins-123");
        assert_eq!(metrics[0].cpu_usage, Some(50.0));
    }
}
