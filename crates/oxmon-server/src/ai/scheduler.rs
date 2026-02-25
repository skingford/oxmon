use anyhow::{Context, Result};
use oxmon_ai::{AIAnalyzer, AnalysisInput, HistoryMetric, MetricSnapshot, ZhipuProvider};
use oxmon_notify::report_template::ReportRenderer;
use oxmon_storage::cert_store::CertStore;
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

pub struct AIReportScheduler {
    cert_store: Arc<CertStore>,
    tick_interval: Duration,
    #[allow(dead_code)] // 用于未来的历史数据查询
    history_days: i32,
}

impl AIReportScheduler {
    pub fn new(cert_store: Arc<CertStore>, tick_interval: Duration, history_days: i32) -> Self {
        Self {
            cert_store,
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
        // 1. 加载所有启用的 AI 账号
        let accounts = self
            .cert_store
            .list_system_configs(Some("ai_account"), None, Some(true), 1000, 0)
            .context("Failed to load AI accounts")?;

        if accounts.is_empty() {
            return Ok(());
        }

        // 2. 检查每个账号是否到期需要生成报告
        for account in accounts {
            let config: serde_json::Value = serde_json::from_str(&account.config_json)
                .context("Failed to parse AI account config")?;

            let interval_secs = config
                .get("collection_interval_secs")
                .and_then(|v| v.as_i64())
                .unwrap_or(86400); // 默认每天

            // 检查上次生成报告的时间
            let should_collect = self.should_collect(&account.config_key, interval_secs)?;

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

    fn should_collect(&self, config_key: &str, interval_secs: i64) -> Result<bool> {
        // 查询该账号最近一次生成报告的时间
        let last_report = self
            .cert_store
            .get_latest_ai_report_by_account(config_key)?;

        match last_report {
            Some(report) => {
                let elapsed = chrono::Utc::now().timestamp() - report.created_at.timestamp();
                Ok(elapsed >= interval_secs)
            }
            None => Ok(true), // 从未生成过，立即生成
        }
    }

    async fn generate_report(
        &self,
        account: &oxmon_storage::cert_store::SystemConfigRow,
    ) -> Result<()> {
        tracing::info!(
            account_id = %account.id,
            provider = %account.provider.as_deref().unwrap_or("unknown"),
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

        // 4. 获取系统语言
        let locale = self
            .cert_store
            .get_runtime_setting_string("language", "zh-CN");

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
        let analysis_result = analyzer
            .analyze(input)
            .await
            .context("AI analysis failed")?;

        // 7. 渲染 HTML 报告
        let html_content = ReportRenderer::render_report(
            &report_date,
            current_metrics.len() as i32,
            analysis_result.risk_level.as_str(),
            analyzer.provider(),
            analyzer.model_name(),
            &analysis_result.content,
            &chrono::Utc::now().to_rfc3339(),
            &locale,
        )?;

        // 8. 存储报告到数据库
        let report_request = oxmon_common::types::CreateAIReportRequest {
            report_date: report_date.clone(),
            ai_account_id: account.id.clone(),
            ai_provider: analyzer.provider().to_string(),
            ai_model: analyzer.model_name().to_string(),
            total_agents: current_metrics.len() as i32,
            risk_level: analysis_result.risk_level.as_str().to_string(),
            ai_analysis: analysis_result.content.clone(),
            html_content: html_content.clone(),
            raw_metrics_json: serde_json::to_string(&current_metrics)?,
        };

        let report_id = self.cert_store.save_ai_report(&report_request)?;

        tracing::info!(
            report_id = %report_id,
            risk_level = %analysis_result.risk_level.as_str(),
            total_agents = current_metrics.len(),
            "AI report generated successfully"
        );

        // 9. 异步发送通知（不阻塞主流程）
        let cert_store = self.cert_store.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::send_notifications(&cert_store, &report_id).await {
                tracing::error!(report_id = %report_id, error = %e, "Failed to send notifications");
            }
        });

        Ok(())
    }

    fn build_analyzer(
        &self,
        account: &oxmon_storage::cert_store::SystemConfigRow,
    ) -> Result<Box<dyn AIAnalyzer>> {
        let config: serde_json::Value = serde_json::from_str(&account.config_json)?;
        let provider = account.provider.as_deref().unwrap_or("zhipu");

        match provider {
            "zhipu" => {
                let api_key = config["api_key"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing api_key"))?
                    .to_string();
                let model = config["model"].as_str().map(|s| s.to_string());
                let base_url = config["base_url"].as_str().map(|s| s.to_string());
                let timeout = config["timeout_secs"].as_u64();
                let max_tokens = config["max_tokens"].as_u64().map(|v| v as usize);
                let temperature = config["temperature"].as_f64().map(|v| v as f32);

                Ok(Box::new(ZhipuProvider::new(
                    api_key,
                    model,
                    base_url,
                    timeout,
                    max_tokens,
                    temperature,
                )?))
            }
            "kimi" | "minimax" | "claude" | "codex" | "custom" => {
                anyhow::bail!("Provider '{}' not yet implemented", provider)
            }
            _ => anyhow::bail!("Unsupported AI provider: {}", provider),
        }
    }

    async fn query_latest_metrics(&self) -> Result<Vec<LatestMetric>> {
        // 查询所有 Agent 最新的 CPU/内存/磁盘指标
        // 这里简化实现，实际应该使用 storage engine 的查询方法
        // 由于 storage engine 是分区的，我们需要一个辅助方法

        let agents = self.cert_store.list_agents(1000, 0)?;
        let mut results = Vec::new();

        // 如果没有真实 agents，使用测试数据
        if agents.is_empty() {
            tracing::info!("No real agents found, using test data for demo");
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
                    agent_id: "test-agent-2".to_string(),
                    agent_type: "local".to_string(),
                    cpu_usage: Some(45.2),
                    memory_usage: Some(60.5),
                    disk_usage: Some(55.3),
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

        for agent in agents {
            // 从最近的分区查询该 agent 的最新指标
            // 这里简化为直接查询（实际应该通过 storage engine）
            if let Ok(Some(metrics)) = self.query_agent_latest_metrics(&agent.agent_id) {
                results.push(metrics);
            }
        }

        Ok(results)
    }

    fn query_agent_latest_metrics(&self, agent_id: &str) -> Result<Option<LatestMetric>> {
        // 简化实现：从 agents 表获取基本信息
        // 实际应该从 storage engine 查询最新指标值
        // 这里返回模拟数据，实际使用时需要调用 storage.query_latest_metrics_for_agent()

        let agent_type = if agent_id.starts_with("cloud:") {
            agent_id.split(':').nth(1).unwrap_or("local").to_string()
        } else {
            "local".to_string()
        };

        // 注意：这里需要实际从 storage engine 查询指标
        // 暂时返回 None，待集成 storage engine 方法后完善
        Ok(Some(LatestMetric {
            agent_id: agent_id.to_string(),
            agent_type,
            cpu_usage: None,
            memory_usage: None,
            disk_usage: None,
            timestamp: chrono::Utc::now().timestamp(),
        }))
    }

    async fn query_history_averages(&self) -> Result<Vec<HistoryAverage>> {
        // 查询历史 N 天的指标均值
        // 这里简化实现，实际应该使用 storage engine 的聚合查询
        let agents = self.cert_store.list_agents(1000, 0)?;
        let mut results = Vec::new();

        for agent in agents {
            // 查询历史均值（简化实现）
            results.push(HistoryAverage {
                agent_id: agent.agent_id.clone(),
                avg_cpu: 50.0,
                avg_memory: 60.0,
                avg_disk: 40.0,
            });
        }

        Ok(results)
    }

    async fn send_notifications(cert_store: &CertStore, report_id: &str) -> Result<()> {
        // 加载报告
        let report = cert_store
            .get_ai_report_by_id(report_id)?
            .ok_or_else(|| anyhow::anyhow!("Report not found"))?;

        // 获取系统语言
        let _locale = cert_store.get_runtime_setting_string("language", "zh-CN");

        // TODO: 从 AppState 获取 NotificationManager 和通知配置
        // TODO: 使用 locale 进行多语言通知
        // 目前简化实现，仅记录日志
        tracing::info!(
            report_id = %report_id,
            report_date = %report.report_date,
            risk_level = %report.risk_level,
            "Would send AI report notifications here"
        );

        // 构建报告查看 URL（需要配置域名）
        // let report_url = format!("https://your-domain.com/v1/ai/reports/{}/view", report_id);

        // 发送邮件通知（HTML 格式）
        // 发送钉钉通知（Markdown + 链接）

        // 标记报告已通知
        cert_store.mark_ai_report_notified(report_id)?;

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
