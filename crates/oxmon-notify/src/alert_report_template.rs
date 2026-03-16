use anyhow::Result;
use chrono::{DateTime, FixedOffset, Utc};
use std::collections::HashMap;

/// 单条告警明细（用于批量告警报告）
#[derive(Debug, Clone)]
pub struct AlertReportDetail {
    /// Agent ID（主机标识）
    pub agent_id: String,
    /// 实例显示名称（hostname 或云实例名，解析失败时为 None）
    pub instance_name: Option<String>,
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
    /// 指标标签（如 mount=/data, interface=eth0）
    pub labels: HashMap<String, String>,
}

/// 格式化指标名称和值为可读形式（支持中英文）
pub fn format_metric_display(
    metric_name: &str,
    value: f64,
    labels: &HashMap<String, String>,
    locale: &str,
) -> String {
    let is_zh = locale == "zh-CN";

    // 附加标签信息（如挂载点、网络接口、域名）
    let label_suffix = if let Some(mount) = labels.get("mount") {
        format!(" [{}]", mount)
    } else if let Some(iface) = labels.get("interface") {
        format!(" [{}]", iface)
    } else if let Some(domain) = labels.get("domain") {
        format!(" [{}]", domain)
    } else {
        String::new()
    };

    match metric_name {
        "cpu.usage" => {
            if is_zh {
                format!("CPU使用率: {:.1}%{}", value, label_suffix)
            } else {
                format!("CPU Usage: {:.1}%{}", value, label_suffix)
            }
        }
        "memory.usage" => {
            if is_zh {
                format!("内存使用率: {:.1}%{}", value, label_suffix)
            } else {
                format!("Memory Usage: {:.1}%{}", value, label_suffix)
            }
        }
        "disk.usage" => {
            if is_zh {
                format!("磁盘使用率: {:.1}%{}", value, label_suffix)
            } else {
                format!("Disk Usage: {:.1}%{}", value, label_suffix)
            }
        }
        "load.1min" => {
            if is_zh {
                format!("1分钟负载: {:.2}{}", value, label_suffix)
            } else {
                format!("Load 1min: {:.2}{}", value, label_suffix)
            }
        }
        "load.5min" => {
            if is_zh {
                format!("5分钟负载: {:.2}{}", value, label_suffix)
            } else {
                format!("Load 5min: {:.2}{}", value, label_suffix)
            }
        }
        "load.15min" => {
            if is_zh {
                format!("15分钟负载: {:.2}{}", value, label_suffix)
            } else {
                format!("Load 15min: {:.2}{}", value, label_suffix)
            }
        }
        "network.rx_bytes" => {
            if is_zh {
                format!("网络接收: {:.1} KB/s{}", value, label_suffix)
            } else {
                format!("Net RX: {:.1} KB/s{}", value, label_suffix)
            }
        }
        "network.tx_bytes" => {
            if is_zh {
                format!("网络发送: {:.1} KB/s{}", value, label_suffix)
            } else {
                format!("Net TX: {:.1} KB/s{}", value, label_suffix)
            }
        }
        "cloud.cpu.usage" => {
            if is_zh {
                format!("云主机CPU: {:.1}%{}", value, label_suffix)
            } else {
                format!("Cloud CPU: {:.1}%{}", value, label_suffix)
            }
        }
        "cloud.memory.usage" => {
            if is_zh {
                format!("云主机内存: {:.1}%{}", value, label_suffix)
            } else {
                format!("Cloud Memory: {:.1}%{}", value, label_suffix)
            }
        }
        "cloud.disk.usage" => {
            if is_zh {
                format!("云主机磁盘: {:.1}%{}", value, label_suffix)
            } else {
                format!("Cloud Disk: {:.1}%{}", value, label_suffix)
            }
        }
        "certificate.days_until_expiry" | "certificate.days_remaining" => {
            if is_zh {
                format!("证书剩余天数: {:.0}天{}", value, label_suffix)
            } else {
                format!("Cert Days Left: {:.0}{}", value, label_suffix)
            }
        }
        _ => {
            // 未知指标：原样显示名称和值
            format!("{}: {:.2}{}", metric_name, value, label_suffix)
        }
    }
}

/// 获取实例显示名称：优先 instance_name，其次 agent_id
pub fn display_name(detail: &AlertReportDetail) -> &str {
    detail.instance_name.as_deref().unwrap_or(&detail.agent_id)
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
                if is_zh {
                    "🔴 严重告警"
                } else {
                    "🔴 Critical Alert"
                },
            )
        } else if params.warning_count > 0 {
            ("medium", if is_zh { "🟡 警告" } else { "🟡 Warning" })
        } else {
            ("normal", if is_zh { "✅ 正常" } else { "✅ Normal" })
        };

        let critical_value_class = if params.critical_count > 0 {
            "is-danger"
        } else {
            ""
        };
        let warning_value_class = if params.warning_count > 0 {
            "is-warn"
        } else {
            ""
        };

        let table_rows = Self::build_html_table_rows(params.items, locale);
        let beijing_tz = FixedOffset::east_opt(8 * 3600).unwrap();
        let created_at = Utc::now()
            .with_timezone(&beijing_tz)
            .format("%Y-%m-%d %H:%M:%S CST")
            .to_string();

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
                _ => ("row-info", "is-info", if is_zh { "提示" } else { "Info" }),
            };

            let val_class = match item.severity.as_str() {
                "critical" => "num val-danger",
                "warning" => "num val-warn",
                _ => "num",
            };

            let beijing_tz = FixedOffset::east_opt(8 * 3600).unwrap();
            let time_str = item
                .triggered_at
                .with_timezone(&beijing_tz)
                .format("%m-%d %H:%M:%S")
                .to_string();
            // 截断过长的消息避免撑开表格
            let message_display = if item.message.len() > 80 {
                format!("{}…", &item.message[..80])
            } else {
                item.message.clone()
            };

            // 主机列：证书告警显示域名+IP，其余显示实例名+agent_id
            let agent_cell = if item.agent_id == "cert-checker" {
                let domain = item.labels.get("domain").map(|s| s.as_str()).unwrap_or("cert-checker");
                let ip_line = item.labels.get("ip")
                    .map(|ip| format!("<br><small style=\"color:#888\">{}</small>", html_escape(ip)))
                    .unwrap_or_default();
                format!("<strong>{}</strong>{}", html_escape(domain), ip_line)
            } else if let Some(ref name) = item.instance_name {
                format!(
                    "<strong>{}</strong><br><small style=\"color:#888\">{}</small>",
                    html_escape(name),
                    html_escape(&item.agent_id)
                )
            } else {
                format!("<code>{}</code>", html_escape(&item.agent_id))
            };

            // 格式化指标值显示
            let metric_display =
                format_metric_display(&item.metric_name, item.value, &item.labels, locale);

            html.push_str(&format!(
                "<tr class=\"{row_class}\">\
                  <td class=\"agent-id\">{agent_cell}</td>\
                  <td>{rule}</td>\
                  <td><code>{metric}</code></td>\
                  <td class=\"{val_class}\">{metric_display}</td>\
                  <td class=\"num\">{threshold:.2}</td>\
                  <td><span class=\"badge {badge_class}\">{severity}</span></td>\
                  <td style=\"white-space:nowrap\">{time}</td>\
                  <td class=\"msg-cell\">{message}</td>\
                </tr>",
                row_class = row_class,
                agent_cell = agent_cell,
                rule = html_escape(&item.rule_name),
                metric = html_escape(&item.metric_name),
                val_class = val_class,
                metric_display = html_escape(&metric_display),
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

        let value_label = if is_zh { "当前值" } else { "Value" };
        md.push_str(&format!(
            "| {agent_label} | {rule_label} | {metric_label} | {value_label} | {severity_label} | {time_col_label} |\n",
            agent_label = agent_label,
            rule_label = rule_label,
            metric_label = metric_label,
            value_label = value_label,
            severity_label = severity_label,
            time_col_label = time_col_label,
        ));
        md.push_str("|---|---|---|---|---|---|\n");

        for item in &sorted {
            let sev_display = match item.severity.as_str() {
                "critical" => {
                    if is_zh {
                        "🔴 严重"
                    } else {
                        "🔴 Critical"
                    }
                }
                "warning" => {
                    if is_zh {
                        "🟡 警告"
                    } else {
                        "🟡 Warning"
                    }
                }
                _ => {
                    if is_zh {
                        "🔵 提示"
                    } else {
                        "🔵 Info"
                    }
                }
            };
            let beijing_tz = FixedOffset::east_opt(8 * 3600).unwrap();
            let time_str = item
                .triggered_at
                .with_timezone(&beijing_tz)
                .format("%H:%M:%S")
                .to_string();
            // 证书告警显示域名+IP，其余显示实例名+agent_id
            let agent_display = if item.agent_id == "cert-checker" {
                let domain = item.labels.get("domain").map(|s| s.as_str()).unwrap_or("cert-checker");
                if let Some(ip) = item.labels.get("ip") {
                    format!("{} ({})", domain, ip)
                } else {
                    domain.to_string()
                }
            } else if let Some(ref name) = item.instance_name {
                format!("{} ({})", name, item.agent_id)
            } else {
                item.agent_id.clone()
            };
            let metric_display =
                format_metric_display(&item.metric_name, item.value, &item.labels, params.locale);
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                agent_display,
                item.rule_name,
                item.metric_name,
                metric_display,
                sev_display,
                time_str
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
                "critical" => {
                    if is_zh {
                        "[严重]"
                    } else {
                        "[CRIT]"
                    }
                }
                "warning" => {
                    if is_zh {
                        "[警告]"
                    } else {
                        "[WARN]"
                    }
                }
                _ => {
                    if is_zh {
                        "[提示]"
                    } else {
                        "[INFO]"
                    }
                }
            };
            // 证书告警显示域名+IP，其余显示实例名+agent_id
            let host_display = if item.agent_id == "cert-checker" {
                let domain = item.labels.get("domain").map(|s| s.as_str()).unwrap_or("cert-checker");
                if let Some(ip) = item.labels.get("ip") {
                    format!("{}({})", domain, ip)
                } else {
                    domain.to_string()
                }
            } else if let Some(ref name) = item.instance_name {
                format!("{}({})", name, item.agent_id)
            } else {
                item.agent_id.clone()
            };
            let metric_display =
                format_metric_display(&item.metric_name, item.value, &item.labels, params.locale);
            text.push_str(&format!(
                "- {} {} {} (阈值:{:.2}): {}\n",
                sev, host_display, metric_display, item.threshold, item.rule_name
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
                instance_name: Some("prod-web-01".to_string()),
                rule_name: "CPU 过高".to_string(),
                metric_name: "cpu.usage".to_string(),
                severity: "critical".to_string(),
                value: 95.3,
                threshold: 90.0,
                message: "CPU 使用率超过阈值".to_string(),
                triggered_at: Utc::now(),
                labels: HashMap::new(),
            },
            AlertReportDetail {
                agent_id: "server-02".to_string(),
                instance_name: None,
                rule_name: "内存告警".to_string(),
                metric_name: "memory.usage".to_string(),
                severity: "warning".to_string(),
                value: 82.1,
                threshold: 80.0,
                message: "内存使用率偏高".to_string(),
                triggered_at: Utc::now(),
                labels: HashMap::new(),
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
        assert!(html.contains("prod-web-01"), "should contain instance name");
        assert!(html.contains("server-01"), "should contain agent_id");
        assert!(html.contains("严重"));
        assert!(
            html.contains("CPU使用率:"),
            "should contain formatted metric"
        );
        // server-02 无 instance_name，只显示 agent_id
        assert!(html.contains("server-02"));
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
        assert!(html.contains("prod-web-01"));
        assert!(html.contains("server-01"));
        assert!(html.contains("Critical"));
        assert!(
            html.contains("CPU Usage:"),
            "should contain formatted metric"
        );
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
        assert!(
            md.contains("prod-web-01 (server-01)"),
            "instance name with agent_id"
        );
        assert!(md.contains("CPU使用率:"), "formatted metric in markdown");
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
        assert!(
            plain.contains("prod-web-01(server-01)"),
            "instance name with agent_id in plain"
        );
        assert!(
            plain.contains("CPU使用率:"),
            "formatted metric in plain text"
        );
    }

    #[test]
    fn test_format_metric_display_zh() {
        let labels = HashMap::new();
        assert_eq!(
            format_metric_display("cpu.usage", 90.5, &labels, "zh-CN"),
            "CPU使用率: 90.5%"
        );
        assert_eq!(
            format_metric_display("memory.usage", 85.2, &labels, "zh-CN"),
            "内存使用率: 85.2%"
        );

        let mut disk_labels = HashMap::new();
        disk_labels.insert("mount".to_string(), "/data".to_string());
        assert_eq!(
            format_metric_display("disk.usage", 78.0, &disk_labels, "zh-CN"),
            "磁盘使用率: 78.0% [/data]"
        );
    }

    #[test]
    fn test_format_metric_display_en() {
        let labels = HashMap::new();
        assert_eq!(
            format_metric_display("cpu.usage", 90.5, &labels, "en"),
            "CPU Usage: 90.5%"
        );
        assert_eq!(
            format_metric_display("cloud.cpu.usage", 75.0, &labels, "en"),
            "Cloud CPU: 75.0%"
        );
    }

    #[test]
    fn test_format_metric_display_cert() {
        let mut labels = HashMap::new();
        labels.insert("domain".to_string(), "example.com".to_string());
        // certificate.days_until_expiry 应匹配证书剩余天数格式
        assert_eq!(
            format_metric_display("certificate.days_until_expiry", 354.0, &labels, "zh-CN"),
            "证书剩余天数: 354天 [example.com]"
        );
        assert_eq!(
            format_metric_display("certificate.days_until_expiry", 30.0, &labels, "en"),
            "Cert Days Left: 30 [example.com]"
        );
        // certificate.days_remaining 仍然匹配
        assert_eq!(
            format_metric_display("certificate.days_remaining", 10.0, &labels, "zh-CN"),
            "证书剩余天数: 10天 [example.com]"
        );
    }

    #[test]
    fn test_cert_checker_display() {
        let mut labels = HashMap::new();
        labels.insert("domain".to_string(), "example.com".to_string());
        labels.insert("ip".to_string(), "1.2.3.4".to_string());

        let items = vec![AlertReportDetail {
            agent_id: "cert-checker".to_string(),
            instance_name: None,
            rule_name: "SSL证书即将过期".to_string(),
            metric_name: "certificate.days_until_expiry".to_string(),
            severity: "warning".to_string(),
            value: 25.0,
            threshold: 30.0,
            message: "证书将在25天后过期".to_string(),
            triggered_at: Utc::now(),
            labels,
        }];

        let params = AlertReportParams {
            report_date: "2026-03-16 10:00",
            total_alerts: 1,
            critical_count: 0,
            warning_count: 1,
            items: &items,
            locale: "zh-CN",
        };

        // HTML: 域名加粗 + IP 灰字
        let html = AlertReportRenderer::render_html(&params).unwrap();
        assert!(html.contains("example.com"), "HTML should contain domain");
        assert!(html.contains("1.2.3.4"), "HTML should contain IP");
        assert!(!html.contains(">cert-checker<"), "HTML should not show raw cert-checker as primary");

        // Markdown: domain (ip)
        let md = AlertReportRenderer::render_markdown(&params);
        assert!(md.contains("example.com (1.2.3.4)"), "Markdown should show domain (ip), got: {}", md);

        // Plain: domain(ip)
        let plain = AlertReportRenderer::render_plain(&params);
        assert!(plain.contains("example.com(1.2.3.4)"), "Plain should show domain(ip), got: {}", plain);

        // 指标值格式化
        assert!(html.contains("证书剩余天数:"), "HTML should contain formatted cert metric");
    }
}
