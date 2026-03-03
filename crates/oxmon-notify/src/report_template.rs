use anyhow::Result;

/// 报告渲染参数
pub struct ReportParams<'a> {
    pub report_date: &'a str,
    pub total_agents: i32,
    pub risk_level: &'a str,
    pub ai_provider: &'a str,
    pub ai_model: &'a str,
    pub ai_analysis: &'a str,
    /// 服务端预生成的实例详情 HTML 表格（已按风险排序）
    pub instance_table_html: &'a str,
    pub created_at: &'a str,
    pub locale: &'a str,
}

/// HTML 报告渲染器
pub struct ReportRenderer;

impl ReportRenderer {
    /// 将 Markdown 转换为 HTML
    pub fn markdown_to_html(markdown: &str) -> String {
        use pulldown_cmark::{html, Options, Parser};

        let mut options = Options::empty();
        options.insert(Options::ENABLE_TABLES);
        options.insert(Options::ENABLE_STRIKETHROUGH);
        options.insert(Options::ENABLE_TASKLISTS);

        let parser = Parser::new_ext(markdown, options);
        let mut html_output = String::new();
        html::push_html(&mut html_output, parser);

        html_output
    }

    /// 渲染完整的 HTML 报告
    pub fn render_report(params: &ReportParams<'_>) -> Result<String> {
        let report_date = params.report_date;
        let total_agents = params.total_agents;
        let risk_level = params.risk_level;
        let ai_provider = params.ai_provider;
        let ai_model = params.ai_model;
        let ai_analysis = params.ai_analysis;
        let created_at = params.created_at;
        let locale = params.locale;
        let template = include_str!("templates/ai_report.html");

        let risk_level_label = match risk_level {
            "high" => {
                if locale == "zh-CN" {
                    "🚨 严重告警"
                } else {
                    "🚨 Critical"
                }
            }
            "medium" => {
                if locale == "zh-CN" {
                    "🔴 告警"
                } else {
                    "🔴 Alert"
                }
            }
            "low" => {
                if locale == "zh-CN" {
                    "🟡 关注"
                } else {
                    "🟡 Attention"
                }
            }
            _ => {
                if locale == "zh-CN" {
                    "✅ 正常"
                } else {
                    "✅ Normal"
                }
            }
        };

        let title = if locale == "zh-CN" {
            "服务器监控 AI 分析报告"
        } else {
            "Server Monitoring AI Analysis Report"
        };

        let ai_analysis_html = Self::markdown_to_html(ai_analysis);

        let html = template
            .replace("{{lang}}", if locale == "zh-CN" { "zh" } else { "en" })
            .replace("{{title}}", title)
            .replace("{{report_date}}", report_date)
            .replace("{{total_agents}}", &total_agents.to_string())
            .replace("{{risk_level}}", risk_level)
            .replace("{{risk_level_label}}", risk_level_label)
            .replace("{{ai_provider}}", ai_provider)
            .replace("{{ai_model}}", ai_model)
            .replace("{{instance_table_html}}", params.instance_table_html)
            .replace("{{ai_analysis_html}}", &ai_analysis_html)
            .replace("{{created_at}}", created_at);

        Ok(html)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_to_html() {
        let markdown = "## 测试标题\n\n这是一段**加粗**的文本。";
        let html = ReportRenderer::markdown_to_html(markdown);
        assert!(html.contains("<h2>"));
        assert!(html.contains("<strong>"));
    }

    #[test]
    fn test_markdown_table() {
        let markdown = "| Name | Age |\n|------|-----|\n| Alice | 30 |";
        let html = ReportRenderer::markdown_to_html(markdown);
        assert!(html.contains("<table>"));
        assert!(html.contains("<th>"));
    }

    #[test]
    fn test_render_report() {
        let params = ReportParams {
            report_date: "2024-01-15",
            total_agents: 50,
            risk_level: "high",
            ai_provider: "zhipu",
            ai_model: "glm-5",
            ai_analysis: "## 测试报告\n\n这是测试内容。",
            instance_table_html: "",
            created_at: "2024-01-15T08:40:00Z",
            locale: "zh-CN",
        };
        let html = ReportRenderer::render_report(&params).unwrap();

        assert!(html.contains("服务器监控 AI 分析报告"));
        assert!(html.contains("2024-01-15"));
        assert!(html.contains(">50<"));
        assert!(html.contains("严重告警"));
        assert!(html.contains("glm-5"));
    }
}
