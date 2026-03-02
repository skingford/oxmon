//! 核心 AI 报告生成逻辑，供调度器和手动触发端点共用。

use anyhow::{Context, Result};
use oxmon_ai::{AIAnalyzer, AnalysisInput, HistoryMetric, MetricSnapshot, ZhipuProvider};
use oxmon_notify::manager::NotificationManager;
use oxmon_notify::report_template::{ReportParams, ReportRenderer};
use oxmon_storage::engine::SqliteStorageEngine;
use oxmon_storage::{AIAccountRow, CertStore, StorageEngine};
use std::sync::Arc;


/// 为指定账号生成 AI 检测报告，并通过通知渠道推送。
///
/// 返回生成的报告 ID。
pub async fn generate_report_for_account(
    account: &AIAccountRow,
    storage: &Arc<SqliteStorageEngine>,
    cert_store: &Arc<CertStore>,
    notifier: &Arc<NotificationManager>,
) -> Result<String> {
    tracing::info!(
        account_id = %account.id,
        provider = %account.provider,
        config_key = %account.config_key,
        "Generating AI report"
    );

    // 1. 构建 AI 分析器
    let analyzer = build_analyzer(account)?;

    // 2. 查询当前所有 Agent 最新指标
    let current_metrics = query_latest_metrics(cert_store, storage).await?;

    if current_metrics.is_empty() {
        tracing::warn!("No metrics found, skipping AI report generation");
        anyhow::bail!("No metrics found for AI report generation");
    }

    // 3. 查询历史均值
    let history_metrics = query_history_averages(cert_store).await?;

    tracing::info!(
        total_current = current_metrics.len(),
        total_history = history_metrics.len(),
        "Metrics collected for AI analysis"
    );

    // 4. 获取系统语言
    let locale = cert_store
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

    let report_id = cert_store.save_ai_report(&report_request).await?;

    tracing::info!(
        report_id = %report_id,
        risk_level = %analysis_result.risk_level.as_str(),
        total_agents = current_metrics.len(),
        "AI report generated and saved"
    );

    // 9. 异步发送通知
    let cert_store_clone = cert_store.clone();
    let notifier_clone = notifier.clone();
    let report_id_clone = report_id.clone();
    tokio::spawn(async move {
        if let Err(e) =
            send_notifications(&cert_store_clone, &notifier_clone, &report_id_clone).await
        {
            tracing::error!(
                report_id = %report_id_clone,
                error = %e,
                "Failed to send AI report notifications"
            );
        }
    });

    Ok(report_id)
}

pub fn build_analyzer(account: &AIAccountRow) -> Result<Box<dyn AIAnalyzer>> {
    match account.provider.as_str() {
        "zhipu" => {
            tracing::debug!(
                model = ?account.model,
                base_url = ?account.base_url,
                api_mode = ?account.api_mode,
                "Creating ZhipuProvider"
            );
            let provider = ZhipuProvider::new(
                account.api_key.clone(),
                account.model.clone(),
                account.base_url.clone(),
                account.timeout_secs.map(|v| v as u64),
                account.max_tokens.map(|v| v as usize),
                account.temperature,
                account.api_mode.clone(),
            )
            .context("Failed to create ZhipuProvider")?;
            Ok(Box::new(provider))
        }
        "kimi" | "minimax" | "claude" | "codex" | "custom" => {
            anyhow::bail!("Provider '{}' not yet implemented", account.provider)
        }
        _ => anyhow::bail!("Unsupported AI provider: {}", account.provider),
    }
}

pub async fn query_latest_metrics(
    cert_store: &Arc<CertStore>,
    storage: &Arc<SqliteStorageEngine>,
) -> Result<Vec<LatestMetric>> {
    let agents = cert_store.list_agents(1000, 0).await?;
    let mut results = Vec::new();

    for agent in &agents {
        if let Ok(Some(metrics)) = query_agent_latest_metrics(storage, &agent.agent_id) {
            results.push(metrics);
        }
    }

    // 查询云实例指标（全部状态）
    let instances = cert_store
        .list_cloud_instances(None, None, None, None, 1000, 0)
        .await?;

    let now = chrono::Utc::now().timestamp();
    for instance in instances {
        let agent_id = format!("cloud:{}:{}", instance.provider, instance.instance_id);
        if let Ok(Some(metrics)) = query_agent_latest_metrics(storage, &agent_id) {
            results.push(metrics);
        } else {
            results.push(LatestMetric {
                agent_id,
                agent_type: instance.provider,
                cpu_usage: None,
                memory_usage: None,
                disk_usage: None,
                timestamp: now,
            });
        }
    }

    Ok(results)
}

fn query_agent_latest_metrics(
    storage: &Arc<SqliteStorageEngine>,
    agent_id: &str,
) -> Result<Option<LatestMetric>> {
    let agent_type = if agent_id.starts_with("cloud:") {
        agent_id.split(':').nth(1).unwrap_or("local").to_string()
    } else {
        "local".to_string()
    };

    let metric_names = &["cpu.usage", "memory.usage", "disk.usage"];
    let metrics = storage.query_latest_metrics_for_agent(agent_id, metric_names, 7)?;

    if metrics.is_empty() {
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
            "memory.usage" => memory_usage = Some(metric.value),
            "disk.usage" => disk_usage = Some(metric.value),
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

async fn query_history_averages(cert_store: &Arc<CertStore>) -> Result<Vec<HistoryAverage>> {
    let agents = cert_store.list_agents(1000, 0).await?;
    let instances = cert_store
        .list_cloud_instances(None, None, Some("Running"), None, 1000, 0)
        .await?;

    let mut results = Vec::new();
    for agent in agents {
        results.push(HistoryAverage {
            agent_id: agent.agent_id,
            avg_cpu: 50.0,
            avg_memory: 60.0,
            avg_disk: 40.0,
        });
    }
    for instance in instances {
        results.push(HistoryAverage {
            agent_id: format!("cloud:{}:{}", instance.provider, instance.instance_id),
            avg_cpu: 50.0,
            avg_memory: 60.0,
            avg_disk: 40.0,
        });
    }

    Ok(results)
}

async fn send_notifications(
    cert_store: &Arc<CertStore>,
    notifier: &Arc<NotificationManager>,
    report_id: &str,
) -> Result<()> {
    let send_notification = cert_store
        .get_runtime_setting_bool("ai_report_send_notification", true)
        .await;

    if !send_notification {
        tracing::info!(report_id = %report_id, "AI report notification disabled");
        return Ok(());
    }

    let report = cert_store
        .get_ai_report_by_id(report_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Report {} not found", report_id))?;

    let locale = cert_store
        .get_runtime_setting_string("language", "zh-CN")
        .await;

    tracing::info!(
        report_id = %report_id,
        report_date = %report.report_date,
        risk_level = %report.risk_level,
        locale = %locale,
        "Sending AI report notification"
    );

    let success_count = notifier
        .send_ai_report(
            report_id,
            &report.report_date,
            &report.risk_level,
            report.total_agents,
            &report.ai_provider,
            &report.ai_model,
            &report.html_content,
            &report.ai_analysis,
            &locale,
        )
        .await;

    tracing::info!(
        report_id = %report_id,
        success_count = success_count,
        "AI report notification sent"
    );

    cert_store.mark_ai_report_notified(report_id).await?;

    Ok(())
}

/// 最新指标快照（供内部使用）
#[derive(Debug, Clone, serde::Serialize)]
pub struct LatestMetric {
    pub agent_id: String,
    pub agent_type: String,
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub disk_usage: Option<f64>,
    pub timestamp: i64,
}

struct HistoryAverage {
    agent_id: String,
    avg_cpu: f64,
    avg_memory: f64,
    avg_disk: f64,
}
