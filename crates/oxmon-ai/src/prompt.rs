use crate::analyzer::{AnalysisInput, HistoryMetric, MetricSnapshot};
use anyhow::Result;

/// 构建分析 prompt
pub fn build_analysis_prompt(input: &AnalysisInput) -> Result<String> {
    let metrics_text = format_metrics(&input.current_metrics, &input.history_metrics);

    let template = if input.locale == "zh-CN" {
        ANALYSIS_PROMPT_ZH
    } else {
        ANALYSIS_PROMPT_EN
    };

    Ok(template
        .replace("{{METRICS_DATA}}", &metrics_text)
        .replace("{{REPORT_DATE}}", &input.report_date))
}

/// 构建汇总 prompt（用于分批处理）
pub fn build_summary_prompt(batch_results: &[String], locale: &str) -> Result<String> {
    let combined = batch_results.join("\n\n---\n\n");

    let template = if locale == "zh-CN" {
        "以下是分批分析的结果，请汇总生成一份综合报告：\n\n{{BATCH_RESULTS}}\n\n请按照原有格式输出综合报告，最后一行标注 RISK_LEVEL:xxx"
    } else {
        "Below are batch analysis results. Please generate a comprehensive summary report:\n\n{{BATCH_RESULTS}}\n\nFollow the original format and add RISK_LEVEL:xxx in the last line."
    };

    Ok(template.replace("{{BATCH_RESULTS}}", &combined))
}

/// 格式化指标数据为表格形式（已按风险排序，包含风险标注列）
fn format_metrics(current: &[MetricSnapshot], history: &[HistoryMetric]) -> String {
    // 构建历史数据查找表
    let hist_map: std::collections::HashMap<&str, &HistoryMetric> =
        history.iter().map(|h| (h.agent_id.as_str(), h)).collect();

    let mut output = String::new();

    output.push_str("### 当前指标（已按风险排序，高风险排前）\n\n");
    output.push_str("| # | Agent ID | 类型 | CPU(%) | 内存(%) | 磁盘(%) | CPU均值 | 内存均值 | 磁盘均值 | 风险 |\n");
    output.push_str("|---|----------|------|--------|---------|---------|---------|----------|----------|------|\n");

    for (i, metric) in current.iter().enumerate() {
        let hist = hist_map.get(metric.agent_id.as_str());
        let risk = infer_risk_label(metric.cpu_usage, metric.memory_usage, metric.disk_usage);
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            i + 1,
            metric.agent_id,
            metric.agent_type,
            metric
                .cpu_usage
                .map_or("N/A".to_string(), |v| format!("{:.1}", v)),
            metric
                .memory_usage
                .map_or("N/A".to_string(), |v| format!("{:.1}", v)),
            metric
                .disk_usage
                .map_or("N/A".to_string(), |v| format!("{:.1}", v)),
            hist.map_or("N/A".to_string(), |h| format!("{:.1}", h.avg_cpu)),
            hist.map_or("N/A".to_string(), |h| format!("{:.1}", h.avg_memory)),
            hist.map_or("N/A".to_string(), |h| format!("{:.1}", h.avg_disk)),
            risk,
        ));
    }

    output
}

/// 根据指标值推断风险等级标签（用于 Prompt 中的表格注释）
fn infer_risk_label(cpu: Option<f64>, mem: Option<f64>, disk: Option<f64>) -> &'static str {
    let values = [cpu, mem, disk];
    if values.into_iter().flatten().any(|v| v > 85.0) {
        "🚨 严重告警"
    } else if values.into_iter().flatten().any(|v| v > 80.0) {
        "🔴 告警"
    } else if values.into_iter().flatten().any(|v| v >= 60.0) {
        "🟡 关注"
    } else {
        "✅ 正常"
    }
}

const ANALYSIS_PROMPT_ZH: &str = r#"你是一位资深运维专家，擅长分析服务器监控数据。请分析以下 {{REPORT_DATE}} 的监控数据，生成专业的巡检报告。

监控数据（已按风险从高到低排序）：
{{METRICS_DATA}}

请按照以下格式输出分析报告（使用 Markdown 格式）：

## 【整体概况】
- 服务器总数：X 台（本地 Agent X 台，腾讯云 A 台，阿里云 B 台）
- 高风险实例数：X 台，中风险：X 台，低风险：X 台，正常：X 台

## 【高风险实例详情】
**必须列出所有风险等级为"🔴 高"的实例，每条包含：**
- **实例 ID**：`agent-xxx`
  - CPU：当前值 / 7天均值（趋势：↑上升 / ↓下降 / →持平）
  - 内存：当前值 / 7天均值
  - 磁盘：当前值 / 7天均值
  - 告警原因：说明哪个指标超阈值

若无高风险实例，填写"无高风险实例"。

## 【中风险实例详情】
列出所有风险等级为"🟡 中"的实例（格式同上，可简略）。
若无，填写"无中风险实例"。

## 【趋势分析】
对比历史 7 天均值，分析异常趋势：
- 指标明显高于均值（超出 20% 以上）的实例
- 是否存在突发性峰值或持续恶化趋势

## 【处理建议】
针对高/中风险实例，给出具体操作建议（按优先级排序）：
1. 最紧急的问题及处理方法
2. 次要问题及建议

## 【总结】
- 是否需要立即人工介入：是 / 否
- 建议关注的关键指标

**最后一行请标注风险等级（必须，不要有任何其他内容在此行之后）：**
RISK_LEVEL:high/medium/low/normal

风险等级判断标准：
- high: 存在任一指标 >85%（严重告警）
- medium: 不满足 high，但存在任一指标 >80%（告警）
- low: 不满足 medium，但存在任一指标在 60%~80%（关注）
- normal: 所有指标正常
"#;

const ANALYSIS_PROMPT_EN: &str = r#"You are a senior DevOps expert skilled at analyzing server monitoring data. Please analyze the following monitoring data for {{REPORT_DATE}} and generate a professional inspection report.

Monitoring Data (sorted by risk level, highest risk first):
{{METRICS_DATA}}

Please output the analysis report in the following format (use Markdown):

## 【Overview】
- Total Servers: X (Local X, Tencent Cloud A, Alibaba Cloud B)
- High-risk: X, Medium-risk: X, Low-risk: X, Normal: X

## 【High-Risk Instance Details】
**Must list ALL instances with risk "🔴 High", each including:**
- **Instance ID**: `agent-xxx`
  - CPU: current / 7-day avg (trend: ↑rising / ↓falling / →stable)
  - Memory: current / 7-day avg
  - Disk: current / 7-day avg
  - Alert reason: which metric exceeded threshold

If none, write "No high-risk instances".

## 【Medium-Risk Instance Details】
List all instances with risk "🟡 Medium" (same format, can be brief).
If none, write "No medium-risk instances".

## 【Trend Analysis】
Compare with 7-day averages and identify anomalies:
- Instances with metrics significantly above average (>20%)
- Sudden spikes or continuously worsening trends

## 【Recommendations】
Provide specific suggestions for high/medium-risk instances (ordered by priority):
1. Most urgent issue and remediation
2. Secondary issues and suggestions

## 【Summary】
- Requires immediate manual intervention: Yes / No
- Key metrics to monitor

**Last line must indicate risk level (required, nothing after this line):**
RISK_LEVEL:high/medium/low/normal

Risk level criteria:
- high: Any metric >85% (critical)
- medium: Not high, but any metric >80% (alert)
- low: Not medium, but any metric in 60%-80% (attention)
- normal: All metrics normal
"#;
