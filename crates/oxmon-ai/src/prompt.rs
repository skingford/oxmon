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

/// 格式化指标数据为表格形式
fn format_metrics(current: &[MetricSnapshot], history: &[HistoryMetric]) -> String {
    let mut output = String::new();

    output.push_str("### 当前指标\n\n");
    output.push_str("| Agent ID | 类型 | CPU使用率(%) | 内存使用率(%) | 磁盘使用率(%) |\n");
    output.push_str("|----------|------|--------------|---------------|---------------|\n");

    for metric in current {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            metric.agent_id,
            metric.agent_type,
            metric
                .cpu_usage
                .map_or("N/A".to_string(), |v| format!("{:.2}", v)),
            metric
                .memory_usage
                .map_or("N/A".to_string(), |v| format!("{:.2}", v)),
            metric
                .disk_usage
                .map_or("N/A".to_string(), |v| format!("{:.2}", v)),
        ));
    }

    output.push_str("\n### 历史7天均值\n\n");
    output.push_str("| Agent ID | 平均CPU(%) | 平均内存(%) | 平均磁盘(%) |\n");
    output.push_str("|----------|------------|-------------|-------------|\n");

    for hist in history {
        output.push_str(&format!(
            "| {} | {:.2} | {:.2} | {:.2} |\n",
            hist.agent_id, hist.avg_cpu, hist.avg_memory, hist.avg_disk
        ));
    }

    output
}

const ANALYSIS_PROMPT_ZH: &str = r#"你是一位资深运维专家，擅长分析服务器监控数据。请分析以下 {{REPORT_DATE}} 的监控数据，生成专业的巡检报告。

监控数据：
{{METRICS_DATA}}

请按照以下格式输出分析报告（使用 Markdown 格式）：

## 【整体概况】
- 服务器总数：X 台
- Agent 类型分布：本地 Agent X 台，云主机 Y 台（腾讯云 A 台，阿里云 B 台）

## 【风险告警】
列出以下高风险项（如果存在）：
- CPU 使用率 > 80%
- 内存使用率 > 85%
- 磁盘使用率 > 90%

格式：
- **Agent ID**: cpu/memory/disk 当前值，历史7天均值

## 【趋势分析】
对比历史 7 天数据，分析异常趋势：
- 哪些 Agent 的指标出现明显上升趋势？
- 是否有突发性峰值？

## 【处理建议】
针对高风险项，给出具体操作建议：
1. 对于 CPU 高负载：排查进程、扩容等
2. 对于内存不足：清理缓存、增加内存等
3. 对于磁盘告警：清理日志、扩容磁盘等

## 【总结】
- 是否需要人工介入：是 / 否
- 风险优先级排序

**最后一行请标注风险等级（必须）：**
RISK_LEVEL:high/medium/low/normal

风险等级判断标准：
- high: 存在 CPU>80% 或 内存>85% 或 磁盘>90% 的 Agent，且趋势恶化
- medium: 存在接近阈值的 Agent（CPU>70%, 内存>75%, 磁盘>80%）
- low: 指标略有异常但未超过阈值
- normal: 所有指标正常
"#;

const ANALYSIS_PROMPT_EN: &str = r#"You are a senior DevOps expert skilled at analyzing server monitoring data. Please analyze the following monitoring data for {{REPORT_DATE}} and generate a professional inspection report.

Monitoring Data:
{{METRICS_DATA}}

Please output the analysis report in the following format (use Markdown):

## 【Overview】
- Total Servers: X
- Agent Type Distribution: Local Agents X, Cloud Instances Y (Tencent Cloud A, Alibaba Cloud B)

## 【Risk Alerts】
List high-risk items (if any):
- CPU usage > 80%
- Memory usage > 85%
- Disk usage > 90%

Format:
- **Agent ID**: cpu/memory/disk current value, 7-day historical average

## 【Trend Analysis】
Compare with 7-day historical data and analyze anomalies:
- Which agents show significant upward trends?
- Are there any sudden spikes?

## 【Recommendations】
Provide specific operational suggestions for high-risk items:
1. For high CPU load: Check processes, scale up, etc.
2. For low memory: Clear cache, add memory, etc.
3. For disk alerts: Clean logs, expand storage, etc.

## 【Summary】
- Requires manual intervention: Yes / No
- Risk priority ranking

**Last line must indicate risk level (required):**
RISK_LEVEL:high/medium/low/normal

Risk level criteria:
- high: Agents with CPU>80% or Memory>85% or Disk>90%, and worsening trend
- medium: Agents approaching thresholds (CPU>70%, Memory>75%, Disk>80%)
- low: Slight anomalies but below thresholds
- normal: All metrics normal
"#;
