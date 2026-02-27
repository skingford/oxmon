use anyhow::Result;
use chrono::Utc;

/// 证书告警明细条目（用于批量报告）
#[derive(Debug, Clone)]
pub struct CertAlertDetail {
    /// 域名
    pub domain: String,
    /// 距离过期天数（负数表示已过期）
    pub days_until_expiry: i64,
    /// 严重程度字符串: "critical" | "warning" | "info"
    pub severity: String,
    /// 证书过期时间（格式化后的字符串，如 "2026-03-01"）
    pub not_after: Option<String>,
    /// 颁发机构
    pub issuer: Option<String>,
    /// 告警消息
    pub message: String,
}

/// 证书告警报告渲染参数
pub struct CertReportParams<'a> {
    /// 报告日期，如 "2026-02-27"
    pub report_date: &'a str,
    /// 本次检查的域名总数
    pub total_checked: i32,
    /// 触发告警的域名列表
    pub alert_items: &'a [CertAlertDetail],
    /// 语言环境，如 "zh-CN" 或 "en"
    pub locale: &'a str,
}

pub struct CertReportRenderer;

impl CertReportRenderer {
    /// 渲染 HTML 邮件报告
    pub fn render_html(params: &CertReportParams<'_>) -> Result<String> {
        let template = include_str!("templates/cert_alert_report.html");
        let locale = params.locale;
        let alert_count = params.alert_items.len();

        let critical_count = params
            .alert_items
            .iter()
            .filter(|d| d.severity == "critical")
            .count();
        let warning_count = params
            .alert_items
            .iter()
            .filter(|d| d.severity == "warning")
            .count();

        let (title, date_label, total_label, alert_label, critical_label, warning_label,
             domain_label, days_label, expiry_label, severity_label, issuer_label,
             section_title, footer_desc, generated_label) = if locale == "zh-CN" {
            (
                "证书告警报告",
                "报告日期",
                "检查域名",
                "告警域名",
                "严重",
                "警告",
                "域名",
                "剩余天数",
                "过期日期",
                "级别",
                "颁发者",
                "证书告警明细",
                "自动化证书监控系统",
                "生成时间",
            )
        } else {
            (
                "Certificate Alert Report",
                "Report Date",
                "Checked",
                "Alerts",
                "Critical",
                "Warning",
                "Domain",
                "Days Left",
                "Expiry Date",
                "Severity",
                "Issuer",
                "Certificate Alert Details",
                "Automated Certificate Monitoring",
                "Generated at",
            )
        };

        let (risk_level, risk_label) = if critical_count > 0 {
            (
                "high",
                if locale == "zh-CN" {
                    "🔴 严重告警"
                } else {
                    "🔴 Critical Alert"
                },
            )
        } else if warning_count > 0 {
            (
                "medium",
                if locale == "zh-CN" {
                    "🟡 警告"
                } else {
                    "🟡 Warning"
                },
            )
        } else {
            (
                "normal",
                if locale == "zh-CN" {
                    "✅ 正常"
                } else {
                    "✅ Normal"
                },
            )
        };

        let alert_value_class = if critical_count > 0 {
            "is-danger"
        } else if warning_count > 0 {
            "is-warn"
        } else {
            ""
        };

        let table_rows = Self::build_html_table_rows(params.alert_items, locale);
        let created_at = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

        let html = template
            .replace("{{lang}}", if locale == "zh-CN" { "zh" } else { "en" })
            .replace("{{title}}", title)
            .replace("{{date_label}}", date_label)
            .replace("{{report_date}}", params.report_date)
            .replace("{{total_label}}", total_label)
            .replace("{{total_checked}}", &params.total_checked.to_string())
            .replace("{{alert_label}}", alert_label)
            .replace("{{alert_count}}", &alert_count.to_string())
            .replace("{{alert_value_class}}", alert_value_class)
            .replace("{{critical_label}}", critical_label)
            .replace("{{critical_count}}", &critical_count.to_string())
            .replace("{{warning_label}}", warning_label)
            .replace("{{warning_count}}", &warning_count.to_string())
            .replace("{{risk_level}}", risk_level)
            .replace("{{risk_label}}", risk_label)
            .replace("{{section_title}}", section_title)
            .replace("{{domain_label}}", domain_label)
            .replace("{{days_label}}", days_label)
            .replace("{{expiry_label}}", expiry_label)
            .replace("{{severity_label}}", severity_label)
            .replace("{{issuer_label}}", issuer_label)
            .replace("{{table_rows}}", &table_rows)
            .replace("{{footer_desc}}", footer_desc)
            .replace("{{generated_label}}", generated_label)
            .replace("{{created_at}}", &created_at);

        Ok(html)
    }

    fn build_html_table_rows(items: &[CertAlertDetail], locale: &str) -> String {
        let mut sorted: Vec<&CertAlertDetail> = items.iter().collect();
        sorted.sort_by(|a, b| {
            let a_pri = if a.severity == "critical" { 0 } else { 1 };
            let b_pri = if b.severity == "critical" { 0 } else { 1 };
            a_pri.cmp(&b_pri)
                .then(a.days_until_expiry.cmp(&b.days_until_expiry))
        });

        let mut html = String::new();
        for item in sorted {
            let (badge_class, badge_text) = match item.severity.as_str() {
                "critical" => (
                    "is-danger",
                    if locale == "zh-CN" { "严重" } else { "Critical" },
                ),
                "warning" => (
                    "is-warn",
                    if locale == "zh-CN" { "警告" } else { "Warning" },
                ),
                _ => (
                    "is-info",
                    if locale == "zh-CN" { "提示" } else { "Info" },
                ),
            };

            let days_display = if item.days_until_expiry < 0 {
                if locale == "zh-CN" {
                    format!(
                        "<span style='color:#b91c1c;font-weight:700'>已过期 {} 天</span>",
                        -item.days_until_expiry
                    )
                } else {
                    format!(
                        "<span style='color:#b91c1c;font-weight:700'>Expired {}d ago</span>",
                        -item.days_until_expiry
                    )
                }
            } else if item.days_until_expiry <= 7 {
                format!(
                    "<span style='color:#b91c1c;font-weight:700'>{}</span>",
                    item.days_until_expiry
                )
            } else if item.days_until_expiry <= 30 {
                format!(
                    "<span style='color:#8a6a00;font-weight:700'>{}</span>",
                    item.days_until_expiry
                )
            } else {
                item.days_until_expiry.to_string()
            };

            let not_after_str = item.not_after.as_deref().unwrap_or("-");
            let issuer_str = item.issuer.as_deref().unwrap_or("-");
            // Truncate long issuer strings
            let issuer_display = if issuer_str.len() > 50 {
                &issuer_str[..50]
            } else {
                issuer_str
            };

            html.push_str(&format!(
                "<tr>\
                  <td><code>{domain}</code></td>\
                  <td class=\"num\">{days}</td>\
                  <td>{expiry}</td>\
                  <td><span class=\"badge {badge_class}\">{severity}</span></td>\
                  <td style=\"font-family:'Inter',sans-serif;font-size:12px;color:var(--text-muted)\">{issuer}</td>\
                </tr>",
                domain = html_escape(&item.domain),
                days = days_display,
                expiry = html_escape(not_after_str),
                badge_class = badge_class,
                severity = badge_text,
                issuer = html_escape(issuer_display),
            ));
        }
        html
    }

    /// 渲染钉钉/企业微信 Markdown 报告
    pub fn render_markdown(params: &CertReportParams<'_>) -> String {
        let locale = params.locale;
        let alert_count = params.alert_items.len();
        let critical_count = params
            .alert_items
            .iter()
            .filter(|d| d.severity == "critical")
            .count();
        let warning_count = params
            .alert_items
            .iter()
            .filter(|d| d.severity == "warning")
            .count();

        let (title, date_label, total_label, alert_label, critical_label, warning_label,
             domain_label, days_label, expiry_label, expired_tag) = if locale == "zh-CN" {
            (
                "🔒 证书告警报告",
                "报告日期",
                "检查域名",
                "告警域名",
                "严重",
                "警告",
                "域名",
                "剩余天数",
                "过期日期",
                "已过期",
            )
        } else {
            (
                "🔒 Certificate Alert Report",
                "Report Date",
                "Checked Domains",
                "Alert Domains",
                "Critical",
                "Warning",
                "Domain",
                "Days Left",
                "Expiry Date",
                "Expired",
            )
        };

        let mut md = format!(
            "### {title}\n\n\
             - **{date_label}**: {date}\n\
             - **{total_label}**: {total}\n\
             - **{alert_label}**: {alerts} ({critical_label}: **{critical}**, {warning_label}: **{warning}**)\n\n",
            title = title,
            date_label = date_label,
            date = params.report_date,
            total_label = total_label,
            total = params.total_checked,
            alert_label = alert_label,
            alerts = alert_count,
            critical_label = critical_label,
            critical = critical_count,
            warning_label = warning_label,
            warning = warning_count,
        );

        let mut sorted: Vec<&CertAlertDetail> = params.alert_items.iter().collect();
        sorted.sort_by(|a, b| {
            let a_pri = if a.severity == "critical" { 0 } else { 1 };
            let b_pri = if b.severity == "critical" { 0 } else { 1 };
            a_pri.cmp(&b_pri)
                .then(a.days_until_expiry.cmp(&b.days_until_expiry))
        });

        md.push_str(&format!(
            "| {domain_label} | {days_label} | {expiry_label} |\n",
            domain_label = domain_label,
            days_label = days_label,
            expiry_label = expiry_label,
        ));
        md.push_str("|---|---|---|\n");

        for item in &sorted {
            let days_str = if item.days_until_expiry < 0 {
                format!("{} {}d", expired_tag, -item.days_until_expiry)
            } else {
                item.days_until_expiry.to_string()
            };
            let expiry = item.not_after.as_deref().unwrap_or("-");
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                item.domain, days_str, expiry
            ));
        }

        md
    }

    /// 渲染纯文本报告（SMS/Webhook 降级）
    pub fn render_plain(params: &CertReportParams<'_>) -> String {
        let locale = params.locale;
        let alert_count = params.alert_items.len();

        let header = if locale == "zh-CN" {
            format!(
                "[证书告警] {date} | 检查:{total} 告警:{alerts}\n",
                date = params.report_date,
                total = params.total_checked,
                alerts = alert_count,
            )
        } else {
            format!(
                "[Cert Alert] {date} | Checked:{total} Alerts:{alerts}\n",
                date = params.report_date,
                total = params.total_checked,
                alerts = alert_count,
            )
        };

        let mut text = header;

        let mut sorted: Vec<&CertAlertDetail> = params.alert_items.iter().collect();
        sorted.sort_by(|a, b| {
            let a_pri = if a.severity == "critical" { 0 } else { 1 };
            let b_pri = if b.severity == "critical" { 0 } else { 1 };
            a_pri.cmp(&b_pri)
                .then(a.days_until_expiry.cmp(&b.days_until_expiry))
        });

        for item in sorted {
            let days_str = if item.days_until_expiry < 0 {
                if locale == "zh-CN" {
                    format!("已过期{}天", -item.days_until_expiry)
                } else {
                    format!("expired {}d ago", -item.days_until_expiry)
                }
            } else if locale == "zh-CN" {
                format!("剩余{}天", item.days_until_expiry)
            } else {
                format!("{}d left", item.days_until_expiry)
            };
            text.push_str(&format!("- {} ({})\n", item.domain, days_str));
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

    fn make_params(locale: &'static str) -> (Vec<CertAlertDetail>, String) {
        let items = vec![
            CertAlertDetail {
                domain: "api.example.com".to_string(),
                days_until_expiry: -2,
                severity: "critical".to_string(),
                not_after: Some("2026-02-25".to_string()),
                issuer: Some("Let's Encrypt".to_string()),
                message: "Certificate expired".to_string(),
            },
            CertAlertDetail {
                domain: "web.example.com".to_string(),
                days_until_expiry: 12,
                severity: "warning".to_string(),
                not_after: Some("2026-03-11".to_string()),
                issuer: None,
                message: "Certificate expiring soon".to_string(),
            },
        ];
        let report_date = "2026-02-27".to_string();
        (items, report_date)
    }

    #[test]
    fn test_render_html_zh() {
        let (items, date) = make_params("zh-CN");
        let params = CertReportParams {
            report_date: &date,
            total_checked: 10,
            alert_items: &items,
            locale: "zh-CN",
        };
        let html = CertReportRenderer::render_html(&params).unwrap();
        assert!(html.contains("证书告警报告"));
        assert!(html.contains("api.example.com"));
        assert!(html.contains("已过期"));
        assert!(html.contains("严重"));
    }

    #[test]
    fn test_render_html_en() {
        let (items, date) = make_params("en");
        let params = CertReportParams {
            report_date: &date,
            total_checked: 10,
            alert_items: &items,
            locale: "en",
        };
        let html = CertReportRenderer::render_html(&params).unwrap();
        assert!(html.contains("Certificate Alert Report"));
        assert!(html.contains("api.example.com"));
        assert!(html.contains("Expired"));
        assert!(html.contains("Critical"));
    }

    #[test]
    fn test_render_markdown() {
        let (items, date) = make_params("zh-CN");
        let params = CertReportParams {
            report_date: &date,
            total_checked: 10,
            alert_items: &items,
            locale: "zh-CN",
        };
        let md = CertReportRenderer::render_markdown(&params);
        assert!(md.contains("证书告警报告"));
        assert!(md.contains("api.example.com"));
        assert!(md.contains("已过期"));
    }

    #[test]
    fn test_render_plain() {
        let (items, date) = make_params("zh-CN");
        let params = CertReportParams {
            report_date: &date,
            total_checked: 10,
            alert_items: &items,
            locale: "zh-CN",
        };
        let plain = CertReportRenderer::render_plain(&params);
        assert!(plain.contains("证书告警"));
        assert!(plain.contains("api.example.com"));
    }
}
