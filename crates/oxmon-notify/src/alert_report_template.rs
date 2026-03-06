use anyhow::Result;
use chrono::{DateTime, Utc};

/// 单条告警明细（用于批量告警报告）
#[derive(Debug, Clone)]
pub struct AlertReportDetail {
    /// Agent ID（主机标识）
    pub agent_id: String,
    /// 规则名称
    pub rule_name: String,
    /// 指标名称
    pub metric_name: String,
    /// 严重程度: "critical" | "warning" | "info"
    pub severity: String,
    /// 当前指标值
    pub value: f64,
    /// 告警阈值
    pub threshold: f64,
    /// 告警消息
    pub message: String,
    /// 触发时间
    pub triggered_at: DateTime<Utc>,
}

/// 告警批量报告渲染参数
pub struct AlertReportParams<'a> {
    /// 报告时间范围描述（如 "2026-03-06 14:25 – 14:30"）
    pub report_date: &'a str,
    /// 触发告警的总条数
    pub total_alerts: usize,
    /// 严重级别数量
    pub critical_count: usize,
    /// 警告级别数量
    pub warning_count: usize,
    /// 告警明细列表
    pub items: &'a [AlertReportDetail],
    /// 语言环境
    pub locale: &'a str,
}

pub struct AlertReportRenderer;

impl AlertReportRenderer {
    /// 渲染 HTML 邮件报告
    pub fn render_html(params: &AlertReportParams<'_>) -> Result<String> {
        let template = include_str!("templates/alert_report.html");
        let locale = params.locale;
        let is_zh = locale == "zh-CN";

        let (
            title,
            time_label,
            total_label,
            critical_label,
            warning_label,
            section_title,
            agent_label,
            rule_label,
            metric_label,
            value_label,
            threshold_label,
            severity_label,
            time_col_label,
            message_label,
            footer_desc,
            generated_label,
        ) = if is_zh {
            (
                "告警通知汇总",
                "告警时段",
                "告警总数",
                "严重",
                "警告",
                "告警明细",
                "主机",
                "规则",
                "指标",
                "当前值",
                "阈值",
                "级别",
                "触发时间",
                "消息",
                "自动化告警监控系统",
                "生成时间",
            )
        } else {
            (
                "Alert Notification Summary",
                "Time Range",
                "Total Alerts",
                "Critical",
                "Warning",
                "Alert Details",
                "Host",
                "Rule",
                "Metric",
                "Value",
                "Threshold",
                "Severity",
                "Triggered At",
                "Message",
                "Automated Alert Monitoring",
                "Generated at",
            )
        };

        let (risk_level, risk_label) = if params.critical_count > 0 {
            (
                "high",
                if is_zh { "🔴 严重告警" } else { "🔴 Critical Alert" },
            )
        } else if params.warning_count > 0 {
            (
                "medium",
                if is_zh { "🟡 警告" } else { "🟡 Warning" },
            )
        } else {
            (
                "normal",
                if is_zh { "✅ 正常" } else { "✅ Normal" },
            )
        };

        let critical_value_class = if params.critical_count > 0 { "is-danger" } else { "" };
        let warning_value_class = if params.warning_count > 0 { "is-warn" } else { "" };

        let table_rows = Self::build_html_table_rows(params.items, locale);
        let created_at = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

        let html = template
            .replace("{{lang}}", if is_zh { "zh" } else { "en" })
            .replace("{{title}}", title)
            .replace("{{time_label}}", time_label)
            .replace("{{report_date}}", params.report_date)
            .replace("{{total_label}}", total_label)
            .replace("{{total_alerts}}", &params.total_alerts.to_string())
            .replace("{{critical_label}}", critical_label)
            .replace("{{critical_count}}", &params.critical_count.to_string())
            .replace("{{critical_value_class}}", critical_value_class)
            .replace("{{warning_label}}", warning_label)
            .replace("{{warning_count}}", &params.warning_count.to_string())
            .replace("{{warning_value_class}}", warning_value_class)
            .replace("{{risk_level}}", risk_level)
            .replace("{{risk_label}}", risk_label)
            .replace("{{section_title}}", section_title)
            .replace("{{agent_label}}", agent_label)
            .replace("{{rule_label}}", rule_label)
            .replace("{{metric_label}}", metric_label)
            .replace("{{value_label}}", value_label)
            .replace("{{threshold_label}}", threshold_label)
            .replace("{{severity_label}}", severity_label)
            .replace("{{time_col_label}}", time_col_label)
            .replace("{{message_label}}", message_label)
            .replace("{{table_rows}}", &table_rows)
            .replace("{{footer_desc}}", footer_desc)
            .replace("{{generated_label}}", generated_label)
            .replace("{{created_at}}", &created_at);

        Ok(html)
    }

    fn build_html_table_rows(items: &[AlertReportDetail], locale: &str) -> String {
        let is_zh = locale == "zh-CN";
        let mut sorted: Vec<&AlertReportDetail> = items.iter().collect();
        // critical 优先，同级按时间正序
        sorted.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "critical" => 0,
                "warning" => 1,
                _ => 2,
            };
            severity_order(&a.severity)
                .cmp(&severity_order(&b.severity))
                .then(a.triggered_at.cmp(&b.triggered_at))
        });

        let mut html = String::new();
        for item in sorted {
            let (row_class, badge_class, badge_text) = match item.severity.as_str() {
                "critical" => (
                    "row-critical",
                    "is-danger",
                    if is_zh { "严重" } else { "Critical" },
                ),
                "warning" => (
                    "row-warning",
                    "is-warn",
                    if is_zh { "警告" } else { "Warning" },
                ),
                _ => (
                    "row-info",
                    "is-info",
                    if is_zh { "提示" } else { "Info" },
                ),
            };

            let val_class = match item.severity.as_str() {
                "critical" => "num val-danger",
                "warning" => "num val-warn",
                _ => "num",
            };

            let time_str = item.triggered_at.format("%m-%d %H:%M:%S").to_string();
            // 截断过长的消息避免撑开表格
            let message_display = if item.message.len() > 80 {
                format!("{}…", &item.message[..80])
            } else {
                item.message.clone()
            };

            html.push_str(&format!(
                "<tr class=\"{row_class}\">\
                  <td class=\"agent-id\"><code>{agent}</code></td>\
                  <td>{rule}</td>\
                  <td><code>{metric}</code></td>\
                  <td class=\"{val_class}\">{value:.2}</td>\
                  <td class=\"num\">{threshold:.2}</td>\
                  <td><span class=\"badge {badge_class}\">{severity}</span></td>\
                  <td style=\"white-space:nowrap\">{time}</td>\
                  <td class=\"msg-cell\">{message}</td>\
                </tr>",
                row_class = row_class,
                agent = html_escape(&item.agent_id),
                rule = html_escape(&item.rule_name),
                metric = html_escape(&item.metric_name),
                val_class = val_class,
                value = item.value,
                threshold = item.threshold,
                badge_class = badge_class,
                severity = badge_text,
                time = time_str,
                message = html_escape(&message_display),
            ));
        }
        html
    }

    /// 渲染钉钉/企业微信 Markdown 报告
    pub fn render_markdown(params: &AlertReportParams<'_>) -> String {
        let is_zh = params.locale == "zh-CN";

        let (
            title,
            time_label,
            total_label,
            critical_label,
            warning_label,
            agent_label,
            rule_label,
            metric_label,
            severity_label,
            time_col_label,
        ) = if is_zh {
            (
                "🔔 告警通知汇总",
                "告警时段",
                "告警总数",
                "严重",
                "警告",
                "主机",
                "规则",
                "指标",
                "级别",
                "触发时间",
            )
        } else {
            (
                "🔔 Alert Notification Summary",
                "Time Range",
                "Total Alerts",
                "Critical",
                "Warning",
                "Host",
                "Rule",
                "Metric",
                "Severity",
                "Triggered At",
            )
        };

        let mut md = format!(
            "### {title}\n\n\
             - **{time_label}**: {date}\n\
             - **{total_label}**: {total} ({critical_label}: **{critical}**, {warning_label}: **{warning}**)\n\n",
            title = title,
            time_label = time_label,
            date = params.report_date,
            total_label = total_label,
            total = params.total_alerts,
            critical_label = critical_label,
            critical = params.critical_count,
            warning_label = warning_label,
            warning = params.warning_count,
        );

        let mut sorted: Vec<&AlertReportDetail> = params.items.iter().collect();
        sorted.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "critical" => 0,
                "warning" => 1,
                _ => 2,
            };
            severity_order(&a.severity)
                .cmp(&severity_order(&b.severity))
                .then(a.triggered_at.cmp(&b.triggered_at))
        });

        md.push_str(&format!(
            "| {agent_label} | {rule_label} | {metric_label} | {severity_label} | {time_col_label} |\n",
            agent_label = agent_label,
            rule_label = rule_label,
            metric_label = metric_label,
            severity_label = severity_label,
            time_col_label = time_col_label,
        ));
        md.push_str("|---|---|---|---|---|\n");

        for item in &sorted {
            let sev_display = match item.severity.as_str() {
                "critical" => if is_zh { "🔴 严重" } else { "🔴 Critical" },
                "warning" => if is_zh { "🟡 警告" } else { "🟡 Warning" },
                _ => if is_zh { "🔵 提示" } else { "🔵 Info" },
            };
            let time_str = item.triggered_at.format("%H:%M:%S").to_string();
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                item.agent_id, item.rule_name, item.metric_name, sev_display, time_str
            ));
        }

        md
    }

    /// 渲染纯文本报告（SMS/Webhook 降级）
    pub fn render_plain(params: &AlertReportParams<'_>) -> String {
        let is_zh = params.locale == "zh-CN";

        let header = if is_zh {
            format!(
                "[告警汇总] {date} | 共{total}条 严重:{critical} 警告:{warning}\n",
                date = params.report_date,
                total = params.total_alerts,
                critical = params.critical_count,
                warning = params.warning_count,
            )
        } else {
            format!(
                "[Alert Summary] {date} | Total:{total} Critical:{critical} Warning:{warning}\n",
                date = params.report_date,
                total = params.total_alerts,
                critical = params.critical_count,
                warning = params.warning_count,
            )
        };

        let mut text = header;

        let mut sorted: Vec<&AlertReportDetail> = params.items.iter().collect();
        sorted.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "critical" => 0,
                "warning" => 1,
                _ => 2,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        for item in sorted {
            let sev = match item.severity.as_str() {
                "critical" => if is_zh { "[严重]" } else { "[CRIT]" },
                "warning" => if is_zh { "[警告]" } else { "[WARN]" },
                _ => if is_zh { "[提示]" } else { "[INFO]" },
            };
            text.push_str(&format!(
                "- {} {} {} {:.2} ({:.2}): {}\n",
                sev, item.agent_id, item.metric_name, item.value, item.threshold, item.rule_name
            ));
        }

        text
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_items() -> Vec<AlertReportDetail> {
        vec![
            AlertReportDetail {
                agent_id: "server-01".to_string(),
                rule_name: "CPU 过高".to_string(),
                metric_name: "cpu.usage".to_string(),
                severity: "critical".to_string(),
                value: 95.3,
                threshold: 90.0,
                message: "CPU 使用率超过阈值".to_string(),
                triggered_at: Utc::now(),
            },
            AlertReportDetail {
                agent_id: "server-02".to_string(),
                rule_name: "内存告警".to_string(),
                metric_name: "memory.usage".to_string(),
                severity: "warning".to_string(),
                value: 82.1,
                threshold: 80.0,
                message: "内存使用率偏高".to_string(),
                triggered_at: Utc::now(),
            },
        ]
    }

    #[test]
    fn test_render_html_zh() {
        let items = make_items();
        let params = AlertReportParams {
            report_date: "2026-03-06 14:25",
            total_alerts: 2,
            critical_count: 1,
            warning_count: 1,
            items: &items,
            locale: "zh-CN",
        };
        let html = AlertReportRenderer::render_html(&params).unwrap();
        assert!(html.contains("告警通知汇总"));
        assert!(html.contains("server-01"));
        assert!(html.contains("严重"));
    }

    #[test]
    fn test_render_html_en() {
        let items = make_items();
        let params = AlertReportParams {
            report_date: "2026-03-06 14:25",
            total_alerts: 2,
            critical_count: 1,
            warning_count: 1,
            items: &items,
            locale: "en",
        };
        let html = AlertReportRenderer::render_html(&params).unwrap();
        assert!(html.contains("Alert Notification Summary"));
        assert!(html.contains("server-01"));
        assert!(html.contains("Critical"));
    }

    #[test]
    fn test_render_markdown() {
        let items = make_items();
        let params = AlertReportParams {
            report_date: "2026-03-06 14:25",
            total_alerts: 2,
            critical_count: 1,
            warning_count: 1,
            items: &items,
            locale: "zh-CN",
        };
        let md = AlertReportRenderer::render_markdown(&params);
        assert!(md.contains("告警通知汇总"));
        assert!(md.contains("server-01"));
    }

    #[test]
    fn test_render_plain() {
        let items = make_items();
        let params = AlertReportParams {
            report_date: "2026-03-06 14:25",
            total_alerts: 2,
            critical_count: 1,
            warning_count: 1,
            items: &items,
            locale: "zh-CN",
        };
        let plain = AlertReportRenderer::render_plain(&params);
        assert!(plain.contains("告警汇总"));
        assert!(plain.contains("server-01"));
    }
}
