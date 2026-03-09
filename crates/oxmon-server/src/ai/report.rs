//! 核心 AI 报告生成逻辑，供调度器和手动触发端点共用。

use anyhow::{Context, Result};

/// 返回 UTC+8 固定偏移时区。28800 秒始终在合法范围内。
#[allow(clippy::unwrap_used)]
fn utc8() -> chrono::FixedOffset {
    chrono::FixedOffset::east_opt(8 * 3600).unwrap()
}

use oxmon_ai::{AIAnalyzer, AnalysisInput, HistoryMetric, MetricSnapshot, ZhipuProvider};
use oxmon_common::types::MetricDataPoint;
use oxmon_notify::manager::NotificationManager;
use oxmon_notify::report_template::{ReportParams, ReportRenderer};
use oxmon_storage::engine::SeaOrmStorageEngine;
use oxmon_storage::{AIAccountRow, CertStore, StorageEngine};
use std::sync::Arc;

/// 为指定账号生成 AI 检测报告，并通过通知渠道推送。
///
/// 返回生成的报告 ID。
pub async fn generate_report_for_account(
    account: &AIAccountRow,
    storage: &Arc<SeaOrmStorageEngine>,
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

    // 3. 查询历史均值（真实 7 天均值）
    let history_metrics = query_history_averages(cert_store, storage).await?;

    tracing::info!(
        total_current = current_metrics.len(),
        total_history = history_metrics.len(),
        "Metrics collected for AI analysis"
    );

    // 4. 获取系统语言
    let locale = cert_store
        .get_runtime_setting_string("language", "zh-CN")
        .await;

    // 5. 按风险评分对实例排序（高风险排前面）
    let mut sorted_metrics = current_metrics.clone();
    sorted_metrics.sort_by(|a, b| {
        let score_a = instance_risk_score(a.cpu_usage, a.memory_usage, a.disk_usage);
        let score_b = instance_risk_score(b.cpu_usage, b.memory_usage, b.disk_usage);
        score_b.cmp(&score_a)
    });

    // 6. 构建分析输入
    let report_date = chrono::Utc::now()
        .with_timezone(&utc8())
        .format("%Y-%m-%d")
        .to_string();
    let history_map: std::collections::HashMap<&str, &HistoryAverage> = history_metrics
        .iter()
        .map(|h| (h.agent_id.as_str(), h))
        .collect();

    let input = AnalysisInput {
        current_metrics: sorted_metrics
            .iter()
            .map(|m| MetricSnapshot {
                agent_id: m.agent_id.clone(),
                instance_name: m.instance_name.clone(),
                agent_type: m.agent_type.clone(),
                cpu_usage: m.cpu_usage,
                memory_usage: m.memory_usage,
                disk_usage: m.disk_usage,
                timestamp: m.timestamp,
            })
            .collect(),
        history_metrics: history_metrics
            .iter()
            .map(|h| HistoryMetric {
                agent_id: h.agent_id.clone(),
                avg_cpu: h.avg_cpu,
                avg_memory: h.avg_memory,
                avg_disk: h.avg_disk,
            })
            .collect(),
        locale: locale.clone(),
        report_date: report_date.clone(),
    };

    // 7. 构建服务端确定性实例详情 HTML 表格
    let instance_table_html = build_instance_table_html(&sorted_metrics, &history_map, &locale);

    // 8. 调用 AI 分析
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
    let final_risk_level =
        merge_report_risk_level(analysis_result.risk_level.as_str(), &sorted_metrics);

    // 9. 渲染 HTML 报告
    let html_content = ReportRenderer::render_report(&ReportParams {
        report_date: &report_date,
        total_agents: current_metrics.len() as i32,
        risk_level: &final_risk_level,
        ai_provider: analyzer.provider(),
        ai_model: analyzer.model_name(),
        ai_analysis: &analysis_result.content,
        instance_table_html: &instance_table_html,
        created_at: &chrono::Utc::now().with_timezone(&utc8()).to_rfc3339(),
        locale: &locale,
    })?;

    // 10. 存储报告到数据库
    let report_request = oxmon_common::types::CreateAIReportRequest {
        report_date: report_date.clone(),
        ai_account_id: account.id.clone(),
        ai_provider: analyzer.provider().to_string(),
        ai_model: analyzer.model_name().to_string(),
        total_agents: current_metrics.len() as i32,
        risk_level: final_risk_level.clone(),
        ai_analysis: analysis_result.content.clone(),
        html_content,
        raw_metrics_json: serde_json::to_string(&current_metrics)?,
    };

    let report_id = cert_store.save_ai_report(&report_request).await?;

    tracing::info!(
        report_id = %report_id,
        risk_level = %final_risk_level,
        total_agents = current_metrics.len(),
        "AI report generated and saved"
    );

    // 11. 异步发送通知
    let cert_store_clone = cert_store.clone();
    let storage_clone = storage.clone();
    let notifier_clone = notifier.clone();
    let report_id_clone = report_id.clone();
    tokio::spawn(async move {
        if let Err(e) = send_notifications(
            &cert_store_clone,
            &storage_clone,
            &notifier_clone,
            &report_id_clone,
        )
        .await
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

/// 仅针对所有云实例生成 AI 检测报告，并通过通知渠道推送。
///
/// 与 `generate_report_for_account` 的区别在于：只分析云实例，不包含本地 Agent。
/// 返回生成的报告 ID。
pub async fn generate_report_for_cloud_instances(
    account: &AIAccountRow,
    storage: &Arc<SeaOrmStorageEngine>,
    cert_store: &Arc<CertStore>,
    notifier: &Arc<NotificationManager>,
) -> Result<String> {
    tracing::info!(
        account_id = %account.id,
        provider = %account.provider,
        "Generating AI report for all cloud instances"
    );

    let analyzer = build_analyzer(account)?;

    // 只查询云实例指标
    let current_metrics = query_cloud_instances_latest_metrics(cert_store, storage).await?;

    if current_metrics.is_empty() {
        anyhow::bail!("No cloud instance metrics found for AI report generation");
    }

    let history_metrics = query_cloud_instances_history_averages(cert_store, storage).await?;

    let locale = cert_store
        .get_runtime_setting_string("language", "zh-CN")
        .await;

    let mut sorted_metrics = current_metrics.clone();
    sorted_metrics.sort_by(|a, b| {
        let score_a = instance_risk_score(a.cpu_usage, a.memory_usage, a.disk_usage);
        let score_b = instance_risk_score(b.cpu_usage, b.memory_usage, b.disk_usage);
        score_b.cmp(&score_a)
    });

    let report_date = chrono::Utc::now()
        .with_timezone(&utc8())
        .format("%Y-%m-%d")
        .to_string();
    let history_map: std::collections::HashMap<&str, &HistoryAverage> = history_metrics
        .iter()
        .map(|h| (h.agent_id.as_str(), h))
        .collect();

    let input = AnalysisInput {
        current_metrics: sorted_metrics
            .iter()
            .map(|m| MetricSnapshot {
                agent_id: m.agent_id.clone(),
                instance_name: m.instance_name.clone(),
                agent_type: m.agent_type.clone(),
                cpu_usage: m.cpu_usage,
                memory_usage: m.memory_usage,
                disk_usage: m.disk_usage,
                timestamp: m.timestamp,
            })
            .collect(),
        history_metrics: history_metrics
            .iter()
            .map(|h| HistoryMetric {
                agent_id: h.agent_id.clone(),
                avg_cpu: h.avg_cpu,
                avg_memory: h.avg_memory,
                avg_disk: h.avg_disk,
            })
            .collect(),
        locale: locale.clone(),
        report_date: report_date.clone(),
    };

    let instance_table_html = build_instance_table_html(&sorted_metrics, &history_map, &locale);

    tracing::info!(
        total_metrics = current_metrics.len(),
        provider = %analyzer.provider(),
        model = %analyzer.model_name(),
        "Calling AI analyzer for cloud instances"
    );

    let analysis_result = analyzer.analyze(input).await.with_context(|| {
        format!(
            "AI analysis failed for provider {} model {}",
            analyzer.provider(),
            analyzer.model_name()
        )
    })?;
    let final_risk_level =
        merge_report_risk_level(analysis_result.risk_level.as_str(), &sorted_metrics);

    let html_content = ReportRenderer::render_report(&ReportParams {
        report_date: &report_date,
        total_agents: current_metrics.len() as i32,
        risk_level: &final_risk_level,
        ai_provider: analyzer.provider(),
        ai_model: analyzer.model_name(),
        ai_analysis: &analysis_result.content,
        instance_table_html: &instance_table_html,
        created_at: &chrono::Utc::now().with_timezone(&utc8()).to_rfc3339(),
        locale: &locale,
    })?;

    let report_request = oxmon_common::types::CreateAIReportRequest {
        report_date: report_date.clone(),
        ai_account_id: account.id.clone(),
        ai_provider: analyzer.provider().to_string(),
        ai_model: analyzer.model_name().to_string(),
        total_agents: current_metrics.len() as i32,
        risk_level: final_risk_level,
        ai_analysis: analysis_result.content.clone(),
        html_content,
        raw_metrics_json: serde_json::to_string(&current_metrics)?,
    };

    let report_id = cert_store.save_ai_report(&report_request).await?;

    tracing::info!(
        report_id = %report_id,
        total_cloud_instances = current_metrics.len(),
        "AI report for cloud instances generated and saved"
    );

    let cert_store_clone = cert_store.clone();
    let storage_clone = storage.clone();
    let notifier_clone = notifier.clone();
    let report_id_clone = report_id.clone();
    tokio::spawn(async move {
        if let Err(e) = send_notifications(
            &cert_store_clone,
            &storage_clone,
            &notifier_clone,
            &report_id_clone,
        )
        .await
        {
            tracing::error!(
                report_id = %report_id_clone,
                error = %e,
                "Failed to send cloud instances AI report notifications"
            );
        }
    });

    Ok(report_id)
}

/// 针对单个云实例生成 AI 检测报告，并通过通知渠道推送。
///
/// `cloud_instance_db_id` 为 cloud_instances 表的数据库主键（snowflake ID）。
/// 返回生成的报告 ID。
pub async fn generate_report_for_single_instance(
    account: &AIAccountRow,
    storage: &Arc<SeaOrmStorageEngine>,
    cert_store: &Arc<CertStore>,
    notifier: &Arc<NotificationManager>,
    cloud_instance_db_id: &str,
) -> Result<String> {
    // 查询云实例信息
    let instance = cert_store
        .get_cloud_instance_by_id(cloud_instance_db_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Cloud instance '{}' not found", cloud_instance_db_id))?;

    let agent_id = format!("cloud:{}:{}", instance.provider, instance.instance_id);

    tracing::info!(
        account_id = %account.id,
        instance_id = %instance.instance_id,
        agent_id = %agent_id,
        "Generating AI report for single cloud instance"
    );

    let analyzer = build_analyzer(account)?;

    // 查询该实例的最新指标
    let current_metric = if let Ok(Some(m)) = query_agent_latest_metrics(storage, &agent_id).await {
        m
    } else {
        // 无指标时也生成报告，指标全为 None
        LatestMetric {
            agent_id: agent_id.clone(),
            instance_name: instance
                .instance_name
                .clone()
                .filter(|s| !s.trim().is_empty()),
            agent_type: instance.provider.clone(),
            cpu_usage: None,
            memory_usage: None,
            disk_usage: None,
            timestamp: chrono::Utc::now().timestamp(),
        }
    };

    let current_metrics = vec![current_metric];

    // 查询该实例 7 天历史均值
    let locale = cert_store
        .get_runtime_setting_string("language", "zh-CN")
        .await;

    let now = chrono::Utc::now();
    let from = now - chrono::Duration::days(7);
    let history_metrics = [query_agent_history_average(storage, &from, &now, &agent_id).await];

    let history_map: std::collections::HashMap<&str, &HistoryAverage> = history_metrics
        .iter()
        .map(|h| (h.agent_id.as_str(), h))
        .collect();

    let report_date = chrono::Utc::now()
        .with_timezone(&utc8())
        .format("%Y-%m-%d")
        .to_string();

    let input = AnalysisInput {
        current_metrics: current_metrics
            .iter()
            .map(|m| MetricSnapshot {
                agent_id: m.agent_id.clone(),
                instance_name: m.instance_name.clone(),
                agent_type: m.agent_type.clone(),
                cpu_usage: m.cpu_usage,
                memory_usage: m.memory_usage,
                disk_usage: m.disk_usage,
                timestamp: m.timestamp,
            })
            .collect(),
        history_metrics: history_metrics
            .iter()
            .map(|h| HistoryMetric {
                agent_id: h.agent_id.clone(),
                avg_cpu: h.avg_cpu,
                avg_memory: h.avg_memory,
                avg_disk: h.avg_disk,
            })
            .collect(),
        locale: locale.clone(),
        report_date: report_date.clone(),
    };

    let instance_table_html = build_instance_table_html(&current_metrics, &history_map, &locale);

    tracing::info!(
        agent_id = %agent_id,
        provider = %analyzer.provider(),
        "Calling AI analyzer for single instance"
    );

    let analysis_result = analyzer.analyze(input).await.with_context(|| {
        format!(
            "AI analysis failed for instance '{}' provider {}",
            agent_id,
            analyzer.provider()
        )
    })?;
    let final_risk_level =
        merge_report_risk_level(analysis_result.risk_level.as_str(), &current_metrics);

    let html_content = ReportRenderer::render_report(&ReportParams {
        report_date: &report_date,
        total_agents: 1,
        risk_level: &final_risk_level,
        ai_provider: analyzer.provider(),
        ai_model: analyzer.model_name(),
        ai_analysis: &analysis_result.content,
        instance_table_html: &instance_table_html,
        created_at: &chrono::Utc::now().with_timezone(&utc8()).to_rfc3339(),
        locale: &locale,
    })?;

    let report_request = oxmon_common::types::CreateAIReportRequest {
        report_date: report_date.clone(),
        ai_account_id: account.id.clone(),
        ai_provider: analyzer.provider().to_string(),
        ai_model: analyzer.model_name().to_string(),
        total_agents: 1,
        risk_level: final_risk_level,
        ai_analysis: analysis_result.content.clone(),
        html_content,
        raw_metrics_json: serde_json::to_string(&current_metrics)?,
    };

    let report_id = cert_store.save_ai_report(&report_request).await?;

    tracing::info!(
        report_id = %report_id,
        agent_id = %agent_id,
        "AI report for single cloud instance generated and saved"
    );

    let cert_store_clone = cert_store.clone();
    let storage_clone = storage.clone();
    let notifier_clone = notifier.clone();
    let report_id_clone = report_id.clone();
    tokio::spawn(async move {
        if let Err(e) = send_notifications(
            &cert_store_clone,
            &storage_clone,
            &notifier_clone,
            &report_id_clone,
        )
        .await
        {
            tracing::error!(
                report_id = %report_id_clone,
                error = %e,
                "Failed to send single instance AI report notifications"
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
    storage: &Arc<SeaOrmStorageEngine>,
) -> Result<Vec<LatestMetric>> {
    let agents = cert_store.list_all_agents().await?;
    let mut results = Vec::new();

    for agent in &agents {
        if let Ok(Some(metrics)) = query_agent_latest_metrics(storage, &agent.agent_id).await {
            results.push(metrics);
        }
    }

    // 查询云实例指标（全部状态）
    let instances = cert_store.list_all_cloud_instances().await?;

    let now = chrono::Utc::now().timestamp();
    for instance in instances {
        let agent_id = format!("cloud:{}:{}", instance.provider, instance.instance_id);
        if let Ok(Some(metrics)) = query_agent_latest_metrics(storage, &agent_id).await {
            results.push(metrics);
        } else {
            results.push(LatestMetric {
                agent_id,
                instance_name: instance.instance_name.filter(|s| !s.trim().is_empty()),
                agent_type: instance.provider,
                cpu_usage: None,
                memory_usage: None,
                disk_usage: None,
                timestamp: now,
            });
        }
    }

    // 对 instance_name 仍为 None 的条目，批量查询 agents 表 hostname 或云实例名称补充。
    // 这覆盖了：普通 Agent（hostname）以及有指标但 labels 中无 instance_name 的云实例。
    let ids_needing_names: Vec<String> = results
        .iter()
        .filter(|m| m.instance_name.is_none())
        .map(|m| m.agent_id.clone())
        .collect();

    if !ids_needing_names.is_empty() {
        let name_map = cert_store
            .resolve_agent_display_names(&ids_needing_names)
            .await;
        for metric in &mut results {
            if metric.instance_name.is_none() {
                if let Some(name) = name_map.get(&metric.agent_id) {
                    // 仅当解析结果与 agent_id 本身不同时才设置，避免冗余显示
                    if name != &metric.agent_id {
                        metric.instance_name = Some(name.clone());
                    }
                }
            }
        }
    }

    Ok(results)
}

async fn query_agent_latest_metrics(
    storage: &Arc<SeaOrmStorageEngine>,
    agent_id: &str,
) -> Result<Option<LatestMetric>> {
    let agent_type = if agent_id.starts_with("cloud:") {
        agent_id.split(':').nth(1).unwrap_or("local").to_string()
    } else {
        "local".to_string()
    };

    let aliases = metric_aliases_for_agent(agent_id);
    let metric_names = metric_names_from_aliases(aliases);
    let metrics = storage
        .query_latest_metrics_for_agent(agent_id, &metric_names, 7)
        .await?;

    if metrics.is_empty() {
        return Ok(None);
    }

    let cpu_usage = pick_metric_value(&metrics, aliases.cpu).map(|(v, _)| v);
    let memory_usage = pick_metric_value(&metrics, aliases.memory).map(|(v, _)| v);
    let disk_usage = pick_metric_value(&metrics, aliases.disk).map(|(v, _)| v);
    let instance_name = metrics
        .iter()
        .find_map(|m| m.labels.get("instance_name"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if cpu_usage.is_none() && memory_usage.is_none() && disk_usage.is_none() {
        return Ok(None);
    }

    let mut timestamp = chrono::Utc::now().timestamp();

    if let Some((_, ts)) = pick_metric_value(&metrics, aliases.cpu) {
        timestamp = timestamp.max(ts);
    }
    if let Some((_, ts)) = pick_metric_value(&metrics, aliases.memory) {
        timestamp = timestamp.max(ts);
    }
    if let Some((_, ts)) = pick_metric_value(&metrics, aliases.disk) {
        timestamp = timestamp.max(ts);
    }

    Ok(Some(LatestMetric {
        agent_id: agent_id.to_string(),
        instance_name,
        agent_type,
        cpu_usage,
        memory_usage,
        disk_usage,
        timestamp,
    }))
}

async fn query_history_averages(
    cert_store: &Arc<CertStore>,
    storage: &Arc<SeaOrmStorageEngine>,
) -> Result<Vec<HistoryAverage>> {
    let agents = cert_store.list_all_agents().await?;
    let instances = cert_store.list_all_cloud_instances().await?;

    let now = chrono::Utc::now();
    let from = now - chrono::Duration::days(7);

    let mut agent_ids: Vec<String> = agents.into_iter().map(|a| a.agent_id).collect();
    for instance in instances {
        agent_ids.push(format!(
            "cloud:{}:{}",
            instance.provider, instance.instance_id
        ));
    }

    let mut results = Vec::new();
    for agent_id in agent_ids {
        results.push(query_agent_history_average(storage, &from, &now, &agent_id).await);
    }

    Ok(results)
}

async fn send_notifications(
    cert_store: &Arc<CertStore>,
    storage: &Arc<SeaOrmStorageEngine>,
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

    let mut latest_metrics: Vec<LatestMetric> = match serde_json::from_str(&report.raw_metrics_json)
    {
        Ok(metrics) => metrics,
        Err(e) => {
            tracing::warn!(
                report_id = %report_id,
                error = %e,
                "Failed to parse raw_metrics_json for AI report notification"
            );
            Vec::new()
        }
    };
    latest_metrics.sort_by(|a, b| {
        let score_a = instance_risk_score(a.cpu_usage, a.memory_usage, a.disk_usage);
        let score_b = instance_risk_score(b.cpu_usage, b.memory_usage, b.disk_usage);
        score_b.cmp(&score_a)
    });

    let history_metrics = query_history_averages_for_metrics(storage, &latest_metrics).await;
    let history_map: std::collections::HashMap<&str, &HistoryAverage> = history_metrics
        .iter()
        .map(|h| (h.agent_id.as_str(), h))
        .collect();

    let markdown_content = build_ai_notification_markdown(
        &report.report_date,
        &report.risk_level,
        report.total_agents,
        &report.ai_provider,
        &report.ai_model,
        &latest_metrics,
        &history_map,
        &report.ai_analysis,
        &locale,
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
            &markdown_content,
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

/// 只查询云实例的最新指标（不含本地 Agent）。
async fn query_cloud_instances_latest_metrics(
    cert_store: &Arc<CertStore>,
    storage: &Arc<SeaOrmStorageEngine>,
) -> Result<Vec<LatestMetric>> {
    let instances = cert_store.list_all_cloud_instances().await?;

    let now = chrono::Utc::now().timestamp();
    let mut results = Vec::new();

    for instance in instances {
        let agent_id = format!("cloud:{}:{}", instance.provider, instance.instance_id);
        if let Ok(Some(metrics)) = query_agent_latest_metrics(storage, &agent_id).await {
            results.push(metrics);
        } else {
            results.push(LatestMetric {
                agent_id,
                instance_name: instance.instance_name.filter(|s| !s.trim().is_empty()),
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

/// 只查询云实例的 7 天历史均值（不含本地 Agent）。
async fn query_cloud_instances_history_averages(
    cert_store: &Arc<CertStore>,
    storage: &Arc<SeaOrmStorageEngine>,
) -> Result<Vec<HistoryAverage>> {
    let instances = cert_store.list_all_cloud_instances().await?;

    let now = chrono::Utc::now();
    let from = now - chrono::Duration::days(7);

    let mut results = Vec::new();
    for instance in instances {
        let agent_id = format!("cloud:{}:{}", instance.provider, instance.instance_id);
        results.push(query_agent_history_average(storage, &from, &now, &agent_id).await);
    }

    Ok(results)
}

/// 最新指标快照（供内部使用）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LatestMetric {
    pub agent_id: String,
    pub instance_name: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InstanceRiskLevel {
    Normal,
    Low,
    Medium,
    High,
}

const INSTANCE_TABLE_MAX_ROWS: usize = 30;

fn instance_risk_level(cpu: Option<f64>, mem: Option<f64>, disk: Option<f64>) -> InstanceRiskLevel {
    let is_high = cpu.is_some_and(|v| v > 85.0)
        || mem.is_some_and(|v| v > 85.0)
        || disk.is_some_and(|v| v > 85.0);
    if is_high {
        return InstanceRiskLevel::High;
    }

    let is_medium = cpu.is_some_and(|v| v > 80.0)
        || mem.is_some_and(|v| v > 80.0)
        || disk.is_some_and(|v| v > 80.0);
    if is_medium {
        return InstanceRiskLevel::Medium;
    }

    let is_low = cpu.is_some_and(|v| v >= 60.0)
        || mem.is_some_and(|v| v >= 60.0)
        || disk.is_some_and(|v| v >= 60.0);
    if is_low {
        return InstanceRiskLevel::Low;
    }

    InstanceRiskLevel::Normal
}

/// 计算实例风险评分（越高越危险），用于排序。
fn instance_risk_score(cpu: Option<f64>, mem: Option<f64>, disk: Option<f64>) -> u32 {
    let mut score = 0u32;
    if let Some(v) = cpu {
        if v > 85.0 {
            score += 9;
        } else if v > 80.0 {
            score += 3;
        } else if v >= 60.0 {
            score += 1;
        }
    }
    if let Some(v) = mem {
        if v > 85.0 {
            score += 9;
        } else if v > 80.0 {
            score += 3;
        } else if v >= 60.0 {
            score += 1;
        }
    }
    if let Some(v) = disk {
        if v > 85.0 {
            score += 9;
        } else if v > 80.0 {
            score += 3;
        } else if v >= 60.0 {
            score += 1;
        }
    }
    score
}

fn instance_risk_label(level: InstanceRiskLevel, locale: &str) -> &'static str {
    if locale == "zh-CN" {
        match level {
            InstanceRiskLevel::High => "严重告警",
            InstanceRiskLevel::Medium => "告警",
            InstanceRiskLevel::Low => "关注",
            InstanceRiskLevel::Normal => "正常",
        }
    } else {
        match level {
            InstanceRiskLevel::High => "Critical",
            InstanceRiskLevel::Medium => "Alert",
            InstanceRiskLevel::Low => "Attention",
            InstanceRiskLevel::Normal => "Normal",
        }
    }
}

fn instance_risk_css_class(level: InstanceRiskLevel) -> &'static str {
    match level {
        InstanceRiskLevel::High => "row-high",
        InstanceRiskLevel::Medium => "row-medium",
        InstanceRiskLevel::Low => "row-low",
        InstanceRiskLevel::Normal => "row-normal",
    }
}

fn metric_css_class(value: Option<f64>, warn: f64, danger: f64, attention: f64) -> &'static str {
    match value {
        Some(v) if v >= danger => "val-danger",
        Some(v) if v >= warn => "val-warn",
        Some(v) if v >= attention => "val-attn",
        _ => "",
    }
}

/// 构建服务端确定性实例详情 HTML 表格（已按风险排序）。
fn build_instance_table_html(
    metrics: &[LatestMetric],
    history_map: &std::collections::HashMap<&str, &HistoryAverage>,
    locale: &str,
) -> String {
    let (
        title,
        th_id,
        th_type,
        th_cpu,
        th_mem,
        th_disk,
        th_avg_cpu,
        th_avg_mem,
        th_avg_disk,
        th_risk,
    ) = if locale == "zh-CN" {
        (
            "实例详情",
            "实例 ID（名称）",
            "类型",
            "CPU (%)",
            "内存 (%)",
            "磁盘 (%)",
            "CPU 均值",
            "内存均值",
            "磁盘均值",
            "风险",
        )
    } else {
        (
            "Instance Details",
            "Instance ID (Name)",
            "Type",
            "CPU (%)",
            "Memory (%)",
            "Disk (%)",
            "Avg CPU",
            "Avg Mem",
            "Avg Disk",
            "Risk",
        )
    };

    let selected = select_prioritized_metrics(metrics, INSTANCE_TABLE_MAX_ROWS);
    let omitted_count = metrics.len().saturating_sub(selected.len());
    let omitted_note = if omitted_count > 0 {
        if locale == "zh-CN" {
            format!(
                r#"<div class="instance-table-note">已展示前 {} 行（严重告警/告警优先），其余 {} 行已省略。</div>"#,
                selected.len(),
                omitted_count
            )
        } else {
            format!(
                r#"<div class="instance-table-note">Showing top {} rows (Critical/Alert first); {} row(s) omitted.</div>"#,
                selected.len(),
                omitted_count
            )
        }
    } else {
        String::new()
    };

    let mut html = format!(
        r#"<div class="instance-table-section">
<h2>{title}</h2>
{omitted_note}
<table class="instance-table">
<thead>
<tr>
  <th>{th_id}</th>
  <th>{th_type}</th>
  <th class="num">{th_cpu}</th>
  <th class="num">{th_mem}</th>
  <th class="num">{th_disk}</th>
  <th class="num">{th_avg_cpu}</th>
  <th class="num">{th_avg_mem}</th>
  <th class="num">{th_avg_disk}</th>
  <th class="center">{th_risk}</th>
</tr>
</thead>
<tbody>
"#
    );

    for m in selected {
        let level = instance_risk_level(m.cpu_usage, m.memory_usage, m.disk_usage);
        let row_class = instance_risk_css_class(level);
        let risk_label = instance_risk_label(level, locale);

        let hist = history_map.get(m.agent_id.as_str());
        let avg_cpu = hist.map(|h| h.avg_cpu);
        let avg_mem = hist.map(|h| h.avg_memory);
        let avg_disk = hist.map(|h| h.avg_disk);

        let fmt = |v: Option<f64>| {
            v.map(|x| format!("{:.1}", x))
                .unwrap_or_else(|| "N/A".to_string())
        };

        let cpu_class = metric_css_class(m.cpu_usage, 80.0, 85.0, 60.0);
        let mem_class = metric_css_class(m.memory_usage, 80.0, 85.0, 60.0);
        let disk_class = metric_css_class(m.disk_usage, 80.0, 85.0, 60.0);

        let risk_badge_class = match level {
            InstanceRiskLevel::High => "badge is-danger",
            InstanceRiskLevel::Medium => "badge is-warn",
            InstanceRiskLevel::Low => "badge is-ok",
            InstanceRiskLevel::Normal => "badge is-info",
        };
        let agent_identity_html = render_instance_identity_html(m);

        html.push_str(&format!(
            r#"<tr class="{row_class}">
  <td class="agent-id">{agent_identity_html}</td>
  <td>{agent_type}</td>
  <td class="num {cpu_class}">{cpu}</td>
  <td class="num {mem_class}">{mem}</td>
  <td class="num {disk_class}">{disk}</td>
  <td class="num">{a_cpu}</td>
  <td class="num">{a_mem}</td>
  <td class="num">{a_disk}</td>
  <td class="center"><span class="{risk_badge_class}">{risk_label}</span></td>
</tr>
"#,
            row_class = row_class,
            agent_identity_html = agent_identity_html,
            agent_type = m.agent_type,
            cpu = fmt(m.cpu_usage),
            mem = fmt(m.memory_usage),
            disk = fmt(m.disk_usage),
            a_cpu = fmt(avg_cpu),
            a_mem = fmt(avg_mem),
            a_disk = fmt(avg_disk),
            cpu_class = cpu_class,
            mem_class = mem_class,
            disk_class = disk_class,
            risk_badge_class = risk_badge_class,
            risk_label = risk_label,
        ));
    }

    html.push_str("</tbody>\n</table>\n</div>\n");
    html
}

#[derive(Clone, Copy)]
struct MetricAliasSet {
    cpu: &'static [&'static str],
    memory: &'static [&'static str],
    disk: &'static [&'static str],
}

const LOCAL_CPU_ALIASES: &[&str] = &["cpu.usage"];
const LOCAL_MEMORY_ALIASES: &[&str] = &["memory.used_percent", "memory.usage"];
const LOCAL_DISK_ALIASES: &[&str] = &["disk.used_percent", "disk.usage"];

const CLOUD_CPU_ALIASES: &[&str] = &["cloud.cpu.usage", "cpu.usage"];
const CLOUD_MEMORY_ALIASES: &[&str] =
    &["cloud.memory.usage", "memory.used_percent", "memory.usage"];
const CLOUD_DISK_ALIASES: &[&str] = &["cloud.disk.usage", "disk.used_percent", "disk.usage"];

fn metric_aliases_for_agent(agent_id: &str) -> MetricAliasSet {
    if agent_id.starts_with("cloud:") {
        MetricAliasSet {
            cpu: CLOUD_CPU_ALIASES,
            memory: CLOUD_MEMORY_ALIASES,
            disk: CLOUD_DISK_ALIASES,
        }
    } else {
        MetricAliasSet {
            cpu: LOCAL_CPU_ALIASES,
            memory: LOCAL_MEMORY_ALIASES,
            disk: LOCAL_DISK_ALIASES,
        }
    }
}

fn metric_names_from_aliases(aliases: MetricAliasSet) -> Vec<&'static str> {
    let mut metric_names = Vec::new();
    for name in aliases
        .cpu
        .iter()
        .chain(aliases.memory.iter())
        .chain(aliases.disk.iter())
    {
        if !metric_names.contains(name) {
            metric_names.push(*name);
        }
    }
    metric_names
}

fn pick_metric_value(metrics: &[MetricDataPoint], aliases: &[&str]) -> Option<(f64, i64)> {
    for alias in aliases {
        if let Some(dp) = metrics.iter().find(|m| m.metric_name == *alias) {
            return Some((dp.value, dp.timestamp.timestamp()));
        }
    }
    None
}

async fn query_avg_with_aliases(
    storage: &Arc<SeaOrmStorageEngine>,
    from: &chrono::DateTime<chrono::Utc>,
    to: &chrono::DateTime<chrono::Utc>,
    agent_id: &str,
    aliases: &[&str],
) -> f64 {
    for metric_name in aliases {
        match storage
            .query_metric_summary(from.to_owned(), to.to_owned(), agent_id, metric_name)
            .await
        {
            Ok(summary) if summary.count > 0 => return summary.avg,
            _ => {}
        }
    }
    0.0
}

async fn query_agent_history_average(
    storage: &Arc<SeaOrmStorageEngine>,
    from: &chrono::DateTime<chrono::Utc>,
    to: &chrono::DateTime<chrono::Utc>,
    agent_id: &str,
) -> HistoryAverage {
    let aliases = metric_aliases_for_agent(agent_id);
    let avg_cpu = query_avg_with_aliases(storage, from, to, agent_id, aliases.cpu).await;
    let avg_memory = query_avg_with_aliases(storage, from, to, agent_id, aliases.memory).await;
    let avg_disk = query_avg_with_aliases(storage, from, to, agent_id, aliases.disk).await;
    HistoryAverage {
        agent_id: agent_id.to_string(),
        avg_cpu,
        avg_memory,
        avg_disk,
    }
}

async fn query_history_averages_for_metrics(
    storage: &Arc<SeaOrmStorageEngine>,
    metrics: &[LatestMetric],
) -> Vec<HistoryAverage> {
    let now = chrono::Utc::now();
    let from = now - chrono::Duration::days(7);
    let mut seen = std::collections::HashSet::new();
    let mut history = Vec::new();

    for metric in metrics {
        if seen.insert(metric.agent_id.clone()) {
            history.push(query_agent_history_average(storage, &from, &now, &metric.agent_id).await);
        }
    }

    history
}

fn format_metric(value: Option<f64>) -> String {
    value
        .map(|v| format!("{:.1}", v))
        .unwrap_or_else(|| "N/A".to_string())
}

fn escape_markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn markdown_risk_label(level: InstanceRiskLevel, locale: &str) -> &'static str {
    if locale == "zh-CN" {
        match level {
            InstanceRiskLevel::High => "🔴 严重告警",
            InstanceRiskLevel::Medium => "🟠 告警",
            InstanceRiskLevel::Low => "🔵 关注",
            InstanceRiskLevel::Normal => "🟢 正常",
        }
    } else {
        match level {
            InstanceRiskLevel::High => "🔴 Critical",
            InstanceRiskLevel::Medium => "🟠 Alert",
            InstanceRiskLevel::Low => "🔵 Attention",
            InstanceRiskLevel::Normal => "🟢 Normal",
        }
    }
}

fn risk_level_display(risk_level: &str, locale: &str) -> &'static str {
    if locale == "zh-CN" {
        match risk_level {
            "high" => "🔴 严重告警",
            "medium" => "🟠 告警",
            "low" => "🔵 关注",
            _ => "🟢 正常",
        }
    } else {
        match risk_level {
            "high" => "🔴 Critical",
            "medium" => "🟠 Alert",
            "low" => "🔵 Attention",
            _ => "🟢 Normal",
        }
    }
}

fn canonical_risk_level(level: &str) -> &'static str {
    match level {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "normal",
    }
}

fn risk_level_rank(level: &str) -> u8 {
    match canonical_risk_level(level) {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn instance_level_to_report_level(level: InstanceRiskLevel) -> &'static str {
    match level {
        InstanceRiskLevel::High => "high",
        InstanceRiskLevel::Medium => "medium",
        InstanceRiskLevel::Low => "low",
        InstanceRiskLevel::Normal => "normal",
    }
}

fn merge_report_risk_level(ai_level: &str, metrics: &[LatestMetric]) -> String {
    let ai_level = canonical_risk_level(ai_level);
    let deterministic_level = metrics
        .iter()
        .map(|m| instance_risk_level(m.cpu_usage, m.memory_usage, m.disk_usage))
        .max()
        .unwrap_or(InstanceRiskLevel::Normal);
    let deterministic_level = instance_level_to_report_level(deterministic_level);

    if risk_level_rank(deterministic_level) > risk_level_rank(ai_level) {
        deterministic_level.to_string()
    } else {
        ai_level.to_string()
    }
}

fn build_instance_table_markdown(
    metrics: &[LatestMetric],
    history_map: &std::collections::HashMap<&str, &HistoryAverage>,
    locale: &str,
) -> String {
    let (th_id, th_type, th_cpu, th_mem, th_disk, th_avg_cpu, th_avg_mem, th_avg_disk, th_risk) =
        if locale == "zh-CN" {
            (
                "实例 ID（名称）",
                "类型",
                "CPU(%)",
                "内存(%)",
                "磁盘(%)",
                "CPU均值",
                "内存均值",
                "磁盘均值",
                "风险",
            )
        } else {
            (
                "Instance ID (Name)",
                "Type",
                "CPU(%)",
                "Memory(%)",
                "Disk(%)",
                "Avg CPU",
                "Avg Memory",
                "Avg Disk",
                "Risk",
            )
        };

    let selected = select_prioritized_metrics(metrics, INSTANCE_TABLE_MAX_ROWS);
    let omitted_count = metrics.len().saturating_sub(selected.len());
    let mut markdown = String::new();
    if omitted_count > 0 {
        if locale == "zh-CN" {
            markdown.push_str(&format!(
                "> 已展示前 {} 行（严重告警/告警优先），其余 {} 行已省略。\n\n",
                selected.len(),
                omitted_count
            ));
        } else {
            markdown.push_str(&format!(
                "> Showing top {} rows (Critical/Alert first); {} row(s) omitted.\n\n",
                selected.len(),
                omitted_count
            ));
        }
    }
    markdown.push_str(&format!(
        "| {th_id} | {th_type} | {th_cpu} | {th_mem} | {th_disk} | {th_avg_cpu} | {th_avg_mem} | {th_avg_disk} | {th_risk} |\n\
         |---|---|---:|---:|---:|---:|---:|---:|---|\n"
    ));

    for metric in selected {
        let level = instance_risk_level(metric.cpu_usage, metric.memory_usage, metric.disk_usage);
        let risk = markdown_risk_label(level, locale);
        let history = history_map.get(metric.agent_id.as_str());
        let avg_cpu = history.map(|h| h.avg_cpu);
        let avg_memory = history.map(|h| h.avg_memory);
        let avg_disk = history.map(|h| h.avg_disk);

        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            escape_markdown_cell(&render_instance_identity_markdown(metric)),
            escape_markdown_cell(&metric.agent_type),
            format_metric(metric.cpu_usage),
            format_metric(metric.memory_usage),
            format_metric(metric.disk_usage),
            format_metric(avg_cpu),
            format_metric(avg_memory),
            format_metric(avg_disk),
            risk
        ));
    }

    if metrics.is_empty() {
        let empty_label = if locale == "zh-CN" {
            "暂无实例数据"
        } else {
            "No instance data"
        };
        markdown.push_str(&format!(
            "| {empty_label} | - | - | - | - | - | - | - | - |\n"
        ));
    }

    markdown
}

#[allow(clippy::too_many_arguments)]
fn build_ai_notification_markdown(
    report_date: &str,
    risk_level: &str,
    total_agents: i32,
    ai_provider: &str,
    ai_model: &str,
    metrics: &[LatestMetric],
    history_map: &std::collections::HashMap<&str, &HistoryAverage>,
    ai_analysis: &str,
    locale: &str,
) -> String {
    let risk_label = risk_level_display(risk_level, locale);
    let table = build_instance_table_markdown(metrics, history_map, locale);
    let analysis = ai_analysis.trim();

    let mut markdown = if locale == "zh-CN" {
        format!(
            "### 🤖 AI 检测报告\n\n\
             - **日期**: {}\n\
             - **风险等级**: {}\n\
             - **实例总数**: {} 台\n\
             - **模型**: {} / {}\n\n\
             #### 实例汇总\n\n\
             {}\n",
            report_date, risk_label, total_agents, ai_provider, ai_model, table
        )
    } else {
        format!(
            "### 🤖 AI Inspection Report\n\n\
             - **Date**: {}\n\
             - **Risk Level**: {}\n\
             - **Total Instances**: {}\n\
             - **Model**: {} / {}\n\n\
             #### Instance Summary\n\n\
             {}\n",
            report_date, risk_label, total_agents, ai_provider, ai_model, table
        )
    };

    if !analysis.is_empty() {
        let analysis_title = if locale == "zh-CN" {
            "#### AI 分析"
        } else {
            "#### AI Analysis"
        };
        markdown.push('\n');
        markdown.push_str(analysis_title);
        markdown.push_str("\n\n");
        markdown.push_str(analysis);
    }

    markdown
}

fn select_prioritized_metrics(metrics: &[LatestMetric], max_rows: usize) -> Vec<&LatestMetric> {
    let mut priority = Vec::new();
    let mut others = Vec::new();

    for metric in metrics {
        let level = instance_risk_level(metric.cpu_usage, metric.memory_usage, metric.disk_usage);
        if matches!(level, InstanceRiskLevel::High | InstanceRiskLevel::Medium) {
            priority.push(metric);
        } else {
            others.push(metric);
        }
    }

    priority.extend(others);
    priority.into_iter().take(max_rows).collect()
}

fn render_instance_identity_markdown(metric: &LatestMetric) -> String {
    let instance_name = metric
        .instance_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(name) = instance_name {
        format!("{} ({})", metric.agent_id, name)
    } else {
        metric.agent_id.clone()
    }
}

fn render_instance_identity_html(metric: &LatestMetric) -> String {
    let instance_name = metric
        .instance_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(name) = instance_name {
        format!(
            r#"<span class="agent-id-main">{}</span><span class="agent-name">{}</span>"#,
            metric.agent_id, name
        )
    } else {
        format!(r#"<span class="agent-id-main">{}</span>"#, metric.agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_aliases_should_match_cloud_and_local() {
        let cloud = metric_aliases_for_agent("cloud:alibaba:i-xxx");
        assert_eq!(cloud.cpu[0], "cloud.cpu.usage");
        assert_eq!(cloud.memory[0], "cloud.memory.usage");
        assert_eq!(cloud.disk[0], "cloud.disk.usage");

        let local = metric_aliases_for_agent("agent-local-1");
        assert_eq!(local.cpu[0], "cpu.usage");
        assert_eq!(local.memory[0], "memory.used_percent");
        assert_eq!(local.disk[0], "disk.used_percent");
    }

    #[test]
    fn markdown_table_should_include_instance_rows() {
        let metrics = vec![LatestMetric {
            agent_id: "cloud:alibaba:i-test".to_string(),
            instance_name: Some("web-prod-01".to_string()),
            agent_type: "alibaba".to_string(),
            cpu_usage: Some(66.6),
            memory_usage: Some(77.7),
            disk_usage: Some(88.8),
            timestamp: 0,
        }];
        let history = vec![HistoryAverage {
            agent_id: "cloud:alibaba:i-test".to_string(),
            avg_cpu: 30.0,
            avg_memory: 40.0,
            avg_disk: 50.0,
        }];
        let history_map: std::collections::HashMap<&str, &HistoryAverage> =
            history.iter().map(|h| (h.agent_id.as_str(), h)).collect();

        let markdown = build_instance_table_markdown(&metrics, &history_map, "zh-CN");
        assert!(markdown.contains("| 实例 ID（名称） | 类型 | CPU(%) |"));
        assert!(markdown.contains("web-prod-01"));
        assert!(markdown.contains("cloud:alibaba:i-test (web-prod-01)"));
        assert!(markdown.contains("66.6"));
        assert!(markdown.contains("40.0"));
    }

    #[test]
    fn ai_notification_markdown_should_include_table_and_analysis() {
        let metrics = vec![LatestMetric {
            agent_id: "agent-1".to_string(),
            instance_name: Some("api-node-1".to_string()),
            agent_type: "local".to_string(),
            cpu_usage: Some(10.0),
            memory_usage: Some(20.0),
            disk_usage: Some(30.0),
            timestamp: 0,
        }];
        let history = vec![HistoryAverage {
            agent_id: "agent-1".to_string(),
            avg_cpu: 8.0,
            avg_memory: 18.0,
            avg_disk: 25.0,
        }];
        let history_map: std::collections::HashMap<&str, &HistoryAverage> =
            history.iter().map(|h| (h.agent_id.as_str(), h)).collect();

        let markdown = build_ai_notification_markdown(
            "2026-03-03",
            "low",
            1,
            "zhipu",
            "glm-5",
            &metrics,
            &history_map,
            "## 建议\n\n保持观察。",
            "zh-CN",
        );

        assert!(markdown.contains("#### 实例汇总"));
        assert!(markdown.contains("| 实例 ID（名称） | 类型 | CPU(%) |"));
        assert!(markdown.contains("api-node-1"));
        assert!(markdown.contains("#### AI 分析"));
        assert!(markdown.contains("保持观察"));
    }

    #[test]
    fn memory_ninety_should_be_high_risk() {
        let level = instance_risk_level(Some(10.0), Some(90.0), Some(20.0));
        assert_eq!(level, InstanceRiskLevel::High);
        assert_eq!(instance_risk_label(level, "zh-CN"), "严重告警");
    }

    #[test]
    fn deterministic_risk_should_override_lower_ai_risk() {
        let metrics = vec![LatestMetric {
            agent_id: "agent-1".to_string(),
            instance_name: None,
            agent_type: "local".to_string(),
            cpu_usage: Some(10.0),
            memory_usage: Some(90.0),
            disk_usage: Some(20.0),
            timestamp: 0,
        }];
        let merged = merge_report_risk_level("medium", &metrics);
        assert_eq!(merged, "high");
    }

    #[test]
    fn threshold_boundaries_should_match_spec() {
        assert_eq!(
            instance_risk_level(Some(59.9), Some(10.0), Some(10.0)),
            InstanceRiskLevel::Normal
        );
        assert_eq!(
            instance_risk_level(Some(60.0), Some(10.0), Some(10.0)),
            InstanceRiskLevel::Low
        );
        assert_eq!(
            instance_risk_level(Some(80.0), Some(10.0), Some(10.0)),
            InstanceRiskLevel::Low
        );
        assert_eq!(
            instance_risk_level(Some(80.1), Some(10.0), Some(10.0)),
            InstanceRiskLevel::Medium
        );
        assert_eq!(
            instance_risk_level(Some(85.0), Some(10.0), Some(10.0)),
            InstanceRiskLevel::Medium
        );
        assert_eq!(
            instance_risk_level(Some(85.1), Some(10.0), Some(10.0)),
            InstanceRiskLevel::High
        );
    }

    #[test]
    fn top_n_should_prioritize_critical_and_alert() {
        let mut metrics = Vec::new();
        for i in 0..40 {
            metrics.push(LatestMetric {
                agent_id: format!("agent-low-{i}"),
                instance_name: None,
                agent_type: "local".to_string(),
                cpu_usage: Some(65.0),
                memory_usage: Some(30.0),
                disk_usage: Some(20.0),
                timestamp: 0,
            });
        }
        metrics.push(LatestMetric {
            agent_id: "agent-alert-1".to_string(),
            instance_name: None,
            agent_type: "local".to_string(),
            cpu_usage: Some(81.0),
            memory_usage: Some(20.0),
            disk_usage: Some(20.0),
            timestamp: 0,
        });
        metrics.push(LatestMetric {
            agent_id: "agent-critical-1".to_string(),
            instance_name: None,
            agent_type: "local".to_string(),
            cpu_usage: Some(90.0),
            memory_usage: Some(20.0),
            disk_usage: Some(20.0),
            timestamp: 0,
        });

        let selected = select_prioritized_metrics(&metrics, INSTANCE_TABLE_MAX_ROWS);
        assert_eq!(selected.len(), INSTANCE_TABLE_MAX_ROWS);
        let selected_ids: Vec<&str> = selected.iter().map(|m| m.agent_id.as_str()).collect();
        assert!(selected_ids.contains(&"agent-alert-1"));
        assert!(selected_ids.contains(&"agent-critical-1"));
    }
}
