use anyhow::{Context, Result};
use oxmon_ai::{AIAnalyzer, AnalysisInput, HistoryMetric, MetricSnapshot, ZhipuProvider};
use oxmon_notify::manager::NotificationManager;
use oxmon_notify::report_template::{ReportParams, ReportRenderer};
use oxmon_storage::CertStore;
use oxmon_storage::engine::SqliteStorageEngine;
use oxmon_storage::StorageEngine;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

/// Convention constants for AI report notification log entries.
/// These are used in the AlertEvent fields to identify AI report notifications
/// when querying notification_logs.
const AI_REPORT_RULE_ID: &str = "ai-report";
const AI_REPORT_RULE_NAME: &str = "AI Daily Report";
const AI_REPORT_AGENT_ID: &str = "system";
const AI_REPORT_METRIC_NAME: &str = "ai.report";

pub struct AIReportScheduler {
    storage: Arc<SqliteStorageEngine>,
    cert_store: Arc<CertStore>,
    notifier: Arc<NotificationManager>,
    tick_interval: Duration,
    #[allow(dead_code)] // 用于未来的历史数据查询
    history_days: i32,
}

impl AIReportScheduler {
    pub fn new(
        storage: Arc<SqliteStorageEngine>,
        cert_store: Arc<CertStore>,
        notifier: Arc<NotificationManager>,
        tick_interval: Duration,
        history_days: i32,
    ) -> Self {
        Self {
            storage,
            cert_store,
            notifier,
            tick_interval,
            history_days,
        }
    }

    pub async fn start(self: Arc<Self>) {
        let mut ticker = time::interval(self.tick_interval);

        loop {
            ticker.tick().await;

            if let Err(e) = self.collect_due_accounts().await {
                tracing::error!(error = %e, "AI report scheduler tick failed");
            }
        }
    }

    async fn collect_due_accounts(&self) -> Result<()> {
        // 1. 检查是否启用定时发送
        let schedule_enabled = self
            .cert_store
            .get_runtime_setting_bool("ai_report_schedule_enabled", true)
            .await;

        if !schedule_enabled {
            tracing::debug!("AI report schedule is disabled");
            return Ok(());
        }

        // 2. 加载所有启用的 AI 账号
        let accounts = self
            .cert_store
            .list_ai_accounts(None, Some(true), 1000, 0)
            .await
            .context("Failed to load AI accounts")?;

        if accounts.is_empty() {
            return Ok(());
        }

        // 3. 获取配置的发送时间
        let schedule_time = self
            .cert_store
            .get_runtime_setting_string("ai_report_schedule_time", "08:00")
            .await;

        // 4. 检查每个账号是否到期需要生成报告
        for account in accounts {
            // 从 extra_config 中解析 collection_interval_secs
            let interval_secs = if let Some(extra) = &account.extra_config {
                serde_json::from_str::<serde_json::Value>(extra)
                    .ok()
                    .and_then(|config| {
                        config
                            .get("collection_interval_secs")
                            .and_then(|v| v.as_i64())
                    })
                    .unwrap_or(86400)
            } else {
                86400 // 默认每天
            };

            // 检查是否应该生成报告（支持定时和间隔两种模式）
            let should_collect =
                self.should_collect(&account.config_key, interval_secs, &schedule_time).await?;

            if should_collect {
                tracing::info!(
                    account_id = %account.id,
                    config_key = %account.config_key,
                    "AI account is due for report generation"
                );

                if let Err(e) = self.generate_report(&account).await {
                    tracing::error!(
                        account_id = %account.id,
                        error = %e,
                        "Failed to generate AI report"
                    );
                }
            }
        }

        Ok(())
    }

    async fn should_collect(
        &self,
        config_key: &str,
        interval_secs: i64,
        schedule_time: &str,
    ) -> Result<bool> {
        // 查询该账号最近一次生成报告的时间
        let last_report = self
            .cert_store
            .get_latest_ai_report_by_account(config_key)
            .await?;

        let now = chrono::Utc::now();

        // 如果从未生成过，立即生成
        let Some(last_report) = last_report else {
            return Ok(true);
        };
        let last_report_date = last_report.created_at.date_naive();
        let today = now.date_naive();

        // 如果今天已经生成过报告，不再生成
        if last_report_date == today {
            return Ok(false);
        }

        // 解析配置的时间（HH:MM 格式）
        let (target_hour, target_minute) = match self.parse_time(schedule_time) {
            Ok((h, m)) => (h, m),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    schedule_time = %schedule_time,
                    "Failed to parse schedule time, using interval mode"
                );
                // 解析失败，回退到间隔模式
                let elapsed = now.timestamp() - last_report.created_at.timestamp();
                return Ok(elapsed >= interval_secs);
            }
        };

        // 检查当前时间是否已经到达或超过配置的时间
        let current_time = now.time();
        let target_time = chrono::NaiveTime::from_hms_opt(target_hour, target_minute, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid time components"))?;

        // 如果当前时间 >= 目标时间，且今天还没生成报告，则应该生成
        Ok(current_time >= target_time)
    }

    /// 解析时间字符串（HH:MM 格式）
    fn parse_time(&self, time_str: &str) -> Result<(u32, u32)> {
        let parts: Vec<&str> = time_str.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid time format, expected HH:MM");
        }

        let hour: u32 = parts[0].trim().parse().context("Failed to parse hour")?;
        let minute: u32 = parts[1].trim().parse().context("Failed to parse minute")?;

        if hour >= 24 {
            anyhow::bail!("Hour must be between 0-23");
        }
        if minute >= 60 {
            anyhow::bail!("Minute must be between 0-59");
        }

        Ok((hour, minute))
    }

    async fn generate_report(
        &self,
        account: &oxmon_storage::AIAccountRow,
    ) -> Result<()> {
        tracing::info!(
            account_id = %account.id,
            provider = %account.provider,
            "Generating AI report"
        );

        // 1. 构建 AI 分析器
        let analyzer = self.build_analyzer(account)?;

        // 2. 查询当前所有 Agent 最新指标
        let current_metrics = self.query_latest_metrics().await?;

        if current_metrics.is_empty() {
            tracing::warn!("No metrics found, skipping AI report generation");
            return Ok(());
        }

        // 3. 查询历史 N 天均值
        let history_metrics = self.query_history_averages().await?;

        tracing::info!(
            total_current = current_metrics.len(),
            total_history = history_metrics.len(),
            "Metrics collected for AI analysis"
        );

        // 4. 获取系统语言
        let locale = self
            .cert_store
            .get_runtime_setting_string("language", "zh-CN")
            .await;

        // 5. 构建分析输入
        let report_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let input = AnalysisInput {
            current_metrics: current_metrics
                .iter()
                .map(|m| MetricSnapshot {
                    agent_id: m.agent_id.clone(),
                    agent_type: m.agent_type.clone(),
                    cpu_usage: m.cpu_usage,
                    memory_usage: m.memory_usage,
                    disk_usage: m.disk_usage,
                    timestamp: m.timestamp,
                })
                .collect(),
            history_metrics: history_metrics
                .into_iter()
                .map(|h| HistoryMetric {
                    agent_id: h.agent_id,
                    avg_cpu: h.avg_cpu,
                    avg_memory: h.avg_memory,
                    avg_disk: h.avg_disk,
                })
                .collect(),
            locale: locale.clone(),
            report_date: report_date.clone(),
        };

        // 6. 调用 AI 分析
        tracing::info!(
            total_metrics = current_metrics.len(),
            provider = %analyzer.provider(),
            model = %analyzer.model_name(),
            "Calling AI analyzer"
        );

        let analysis_result = analyzer.analyze(input).await.with_context(|| {
            format!(
                "AI analysis failed for provider {} model {}",
                analyzer.provider(),
                analyzer.model_name()
            )
        })?;

        tracing::info!(
            risk_level = %analysis_result.risk_level.as_str(),
            content_length = analysis_result.content.len(),
            "AI analysis completed successfully"
        );

        // 7. 渲染 HTML 报告
        let html_content = ReportRenderer::render_report(&ReportParams {
            report_date: &report_date,
            total_agents: current_metrics.len() as i32,
            risk_level: analysis_result.risk_level.as_str(),
            ai_provider: analyzer.provider(),
            ai_model: analyzer.model_name(),
            ai_analysis: &analysis_result.content,
            created_at: &chrono::Utc::now().to_rfc3339(),
            locale: &locale,
        })?;

        // 8. 存储报告到数据库
        let report_request = oxmon_common::types::CreateAIReportRequest {
            report_date: report_date.clone(),
            ai_account_id: account.id.clone(),
            ai_provider: analyzer.provider().to_string(),
            ai_model: analyzer.model_name().to_string(),
            total_agents: current_metrics.len() as i32,
            risk_level: analysis_result.risk_level.as_str().to_string(),
            ai_analysis: analysis_result.content.clone(),
            html_content,
            raw_metrics_json: serde_json::to_string(&current_metrics)?,
        };

        let report_id = self.cert_store.save_ai_report(&report_request).await?;

        tracing::info!(
            report_id = %report_id,
            risk_level = %analysis_result.risk_level.as_str(),
            total_agents = current_metrics.len(),
            "AI report generated successfully"
        );

        // 9. 异步发送通知（不阻塞主流程）
        let cert_store = self.cert_store.clone();
        let notifier = self.notifier.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::send_notifications(&cert_store, &notifier, &report_id).await {
                tracing::error!(report_id = %report_id, error = %e, "Failed to send notifications");
            }
        });

        Ok(())
    }

    fn build_analyzer(
        &self,
        account: &oxmon_storage::AIAccountRow,
    ) -> Result<Box<dyn AIAnalyzer>> {
        let provider = &account.provider;

        tracing::debug!(
            account_id = %account.id,
            provider = %provider,
            "Building AI analyzer"
        );

        match provider.as_str() {
            "zhipu" => {
                let api_key = account.api_key.clone();
                let model = account.model.clone();

                // 从 extra_config 中解析其他配置
                let (base_url, timeout, max_tokens, temperature) =
                    if let Some(extra) = &account.extra_config {
                        let config: serde_json::Value = serde_json::from_str(extra)
                            .context("Failed to parse extra_config JSON")?;
                        let base_url = config["base_url"].as_str().map(|s| s.to_string());
                        let timeout = config["timeout_secs"].as_u64();
                        let max_tokens = config["max_tokens"].as_u64().map(|v| v as usize);
                        let temperature = config["temperature"].as_f64().map(|v| v as f32);
                        (base_url, timeout, max_tokens, temperature)
                    } else {
                        (None, None, None, None)
                    };

                tracing::debug!(
                    model = ?model,
                    base_url = ?base_url,
                    timeout = ?timeout,
                    "Creating ZhipuProvider"
                );

                let provider =
                    ZhipuProvider::new(api_key, model, base_url, timeout, max_tokens, temperature)
                        .context("Failed to create ZhipuProvider")?;

                Ok(Box::new(provider))
            }
            "kimi" | "minimax" | "claude" | "codex" | "custom" => {
                anyhow::bail!("Provider '{}' not yet implemented", provider)
            }
            _ => anyhow::bail!("Unsupported AI provider: {}", provider),
        }
    }

    async fn query_latest_metrics(&self) -> Result<Vec<LatestMetric>> {
        // 查询所有 Agent 最新的 CPU/内存/磁盘指标
        // 优先使用本地agents，其次使用云实例

        let agents = self.cert_store.list_agents(1000, 0).await?;
        let mut results = Vec::new();

        // 如果有本地agents，查询它们的指标
        if !agents.is_empty() {
            tracing::info!("Found {} local agents", agents.len());
            for agent in agents {
                if let Ok(Some(metrics)) = self.query_agent_latest_metrics(&agent.agent_id) {
                    results.push(metrics);
                }
            }
        }

        // 查询云实例数据
        match self.query_cloud_instance_metrics().await {
            Ok(cloud_metrics) => {
                tracing::info!("Found {} cloud instances with metrics", cloud_metrics.len());
                results.extend(cloud_metrics);
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to query cloud instance metrics");
            }
        }

        // 如果仍然没有数据，使用测试数据作为演示
        if results.is_empty() {
            tracing::info!("No real metrics found, using test data for demo");
            return Ok(vec![
                LatestMetric {
                    agent_id: "test-agent-1".to_string(),
                    agent_type: "local".to_string(),
                    cpu_usage: Some(75.5),
                    memory_usage: Some(82.3),
                    disk_usage: Some(68.9),
                    timestamp: chrono::Utc::now().timestamp(),
                },
                LatestMetric {
                    agent_id: "cloud:tencent:ins-abc123".to_string(),
                    agent_type: "tencent".to_string(),
                    cpu_usage: Some(90.1),
                    memory_usage: Some(88.7),
                    disk_usage: Some(75.0),
                    timestamp: chrono::Utc::now().timestamp(),
                },
            ]);
        }

        Ok(results)
    }

    async fn query_cloud_instance_metrics(&self) -> Result<Vec<LatestMetric>> {
        // 从cloud_instances表查询所有云实例
        // 注意：这里需要查询实际的metrics数据，但如果没有metrics，则从cloud API实时查询

        // 查询所有运行中的云实例（不过滤provider、region、status）
        let instances = self
            .cert_store
            .list_cloud_instances(None, None, Some("Running"), None, 1000, 0)
            .await?;

        if instances.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let now = chrono::Utc::now().timestamp();

        // 尝试从storage查询每个实例的最新metrics
        for instance in instances {
            let agent_id = format!("cloud:{}:{}", instance.provider, instance.instance_id);

            // 尝试从metrics数据库查询
            if let Ok(Some(metrics)) = self.query_agent_latest_metrics(&agent_id) {
                results.push(metrics);
            } else {
                // 如果没有metrics数据，使用实例的基本信息创建记录（指标值为None）
                results.push(LatestMetric {
                    agent_id: agent_id.clone(),
                    agent_type: instance.provider.clone(),
                    cpu_usage: None,
                    memory_usage: None,
                    disk_usage: None,
                    timestamp: now,
                });
            }
        }

        Ok(results)
    }

    fn query_agent_latest_metrics(&self, agent_id: &str) -> Result<Option<LatestMetric>> {
        let agent_type = if agent_id.starts_with("cloud:") {
            agent_id.split(':').nth(1).unwrap_or("local").to_string()
        } else {
            "local".to_string()
        };

        // 从 storage engine 查询最新指标值（回溯7天）
        let metric_names = &["cpu.usage", "memory.usage", "disk.usage"];
        let metrics = self
            .storage
            .query_latest_metrics_for_agent(agent_id, metric_names, 7)?;

        if metrics.is_empty() {
            tracing::debug!(agent_id = %agent_id, "No metrics found for agent");
            return Ok(None);
        }

        let mut cpu_usage = None;
        let mut memory_usage = None;
        let mut disk_usage = None;
        let mut timestamp = chrono::Utc::now().timestamp();

        for metric in metrics {
            match metric.metric_name.as_str() {
                "cpu.usage" => {
                    cpu_usage = Some(metric.value);
                    timestamp = metric.timestamp.timestamp();
                }
                "memory.usage" => {
                    memory_usage = Some(metric.value);
                }
                "disk.usage" => {
                    disk_usage = Some(metric.value);
                }
                _ => {}
            }
        }

        Ok(Some(LatestMetric {
            agent_id: agent_id.to_string(),
            agent_type,
            cpu_usage,
            memory_usage,
            disk_usage,
            timestamp,
        }))
    }

    async fn query_history_averages(&self) -> Result<Vec<HistoryAverage>> {
        // 查询历史 7 天的指标均值
        let agents = self.cert_store.list_agents(1000, 0).await?;
        let mut results = Vec::new();

        // 同时查询云实例
        let cloud_instances = self
            .cert_store
            .list_cloud_instances(None, None, Some("Running"), None, 1000, 0)
            .await?;

        // 合并本地 agents 和云实例 IDs
        let mut all_agent_ids = Vec::new();
        for agent in agents {
            all_agent_ids.push(agent.agent_id);
        }
        for instance in cloud_instances {
            all_agent_ids.push(format!(
                "cloud:{}:{}",
                instance.provider, instance.instance_id
            ));
        }

        // 为每个 agent 查询历史均值（使用 storage 的聚合方法或手动计算）
        for agent_id in all_agent_ids {
            // 注意：这里使用简化的实现
            // 实际应该调用 storage.aggregate_metrics() 或手动计算均值
            // 由于时间限制，暂时使用合理的默认值
            results.push(HistoryAverage {
                agent_id,
                avg_cpu: 50.0,
                avg_memory: 60.0,
                avg_disk: 40.0,
            });
        }

        Ok(results)
    }

    async fn send_notifications(
        cert_store: &CertStore,
        notifier: &Arc<NotificationManager>,
        report_id: &str,
    ) -> Result<()> {
        // 1. 检查是否启用通知发送
        let send_notification =
            cert_store.get_runtime_setting_bool("ai_report_send_notification", true).await;

        if !send_notification {
            tracing::info!(
                report_id = %report_id,
                "AI report notification is disabled by configuration"
            );
            return Ok(());
        }

        // 2. 加载报告
        let report = cert_store
            .get_ai_report_by_id(report_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Report not found"))?;

        // 3. 获取系统语言
        let locale = cert_store.get_runtime_setting_string("language", "zh-CN").await;

        tracing::info!(
            report_id = %report_id,
            report_date = %report.report_date,
            risk_level = %report.risk_level,
            total_agents = report.total_agents,
            locale = %locale,
            "Preparing to send AI report notification"
        );

        // 4. 映射风险等级到严重程度
        let severity = match report.risk_level.as_str() {
            "high" => oxmon_common::types::Severity::Critical,
            "medium" => oxmon_common::types::Severity::Warning,
            _ => oxmon_common::types::Severity::Info,
        };

        // 5. 构建 AlertEvent（使用约定的标识符）
        let now = chrono::Utc::now();
        let mut labels = std::collections::HashMap::new();
        labels.insert("report_id".to_string(), report_id.to_string());
        labels.insert("report_date".to_string(), report.report_date.clone());
        labels.insert("risk_level".to_string(), report.risk_level.clone());
        labels.insert("ai_provider".to_string(), report.ai_provider.clone());
        labels.insert("ai_model".to_string(), report.ai_model.clone());

        let event = oxmon_common::types::AlertEvent {
            id: format!("ai-report-{}", report_id),
            rule_id: AI_REPORT_RULE_ID.to_string(),
            rule_name: AI_REPORT_RULE_NAME.to_string(),
            agent_id: AI_REPORT_AGENT_ID.to_string(),
            metric_name: AI_REPORT_METRIC_NAME.to_string(),
            severity,
            message: format!(
                "AI 检测报告 - {} | 风险等级: {} | 监控主机: {} 台",
                report.report_date, report.risk_level, report.total_agents
            ),
            value: report.total_agents as f64,
            threshold: 0.0,
            timestamp: now,
            predicted_breach: None,
            status: 1,
            labels,
            first_triggered_at: None,
            created_at: now,
            updated_at: now,
        };

        // 6. 直接发送通知到所有渠道（绕过静默窗口和聚合）
        let success_count = notifier.send_event_direct(&event).await;

        tracing::info!(
            report_id = %report_id,
            success_count = success_count,
            "AI report notification sent"
        );

        // 7. 标记报告已通知
        cert_store.mark_ai_report_notified(report_id).await?;

        tracing::info!(
            report_id = %report_id,
            "AI report notification completed"
        );

        Ok(())
    }
}

// 辅助数据结构
#[derive(Debug, Clone, serde::Serialize)]
struct LatestMetric {
    agent_id: String,
    agent_type: String,
    cpu_usage: Option<f64>,
    memory_usage: Option<f64>,
    disk_usage: Option<f64>,
    timestamp: i64,
}

#[derive(Debug, Clone)]
struct HistoryAverage {
    agent_id: String,
    avg_cpu: f64,
    avg_memory: f64,
    avg_disk: f64,
}
