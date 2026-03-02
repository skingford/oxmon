/// AI 报告功能演示程序
///
/// 用途: 演示 AI 分析器、报告生成和 HTML 渲染的核心流程
///
/// 运行（模拟模式）:
///   cargo run --example test_ai_report
///
/// 运行（真实 API - Anthropic 兼容模式）:
///   ZHIPU_API_KEY=your-key cargo run --example test_ai_report
///
/// 运行（真实 API - OpenAI 兼容模式）:
///   ZHIPU_API_KEY=your-key ZHIPU_API_MODE=openai cargo run --example test_ai_report
use anyhow::Result;
use oxmon_ai::{AIAnalyzer, AnalysisInput, HistoryMetric, MetricSnapshot, ZhipuProvider};
use oxmon_notify::report_template::{ReportParams, ReportRenderer};

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("🤖 AI 检测报告功能演示\n");

    // 1. 模拟当前指标数据
    println!("📊 步骤 1: 准备指标数据");
    let current_metrics = vec![
        MetricSnapshot {
            agent_id: "agent-001".to_string(),
            agent_type: "local".to_string(),
            cpu_usage: Some(75.5),
            memory_usage: Some(82.3),
            disk_usage: Some(68.9),
            timestamp: chrono::Utc::now().timestamp(),
        },
        MetricSnapshot {
            agent_id: "agent-002".to_string(),
            agent_type: "local".to_string(),
            cpu_usage: Some(45.2),
            memory_usage: Some(60.5),
            disk_usage: Some(55.3),
            timestamp: chrono::Utc::now().timestamp(),
        },
        MetricSnapshot {
            agent_id: "cloud:tencent:ins-abc123".to_string(),
            agent_type: "tencent".to_string(),
            cpu_usage: Some(90.1),
            memory_usage: Some(88.7),
            disk_usage: Some(75.0),
            timestamp: chrono::Utc::now().timestamp(),
        },
    ];
    println!(
        "   ✅ 准备了 {} 个 agent 的当前指标\n",
        current_metrics.len()
    );

    // 2. 模拟历史均值数据
    println!("📈 步骤 2: 准备历史均值数据");
    let history_metrics = vec![
        HistoryMetric {
            agent_id: "agent-001".to_string(),
            avg_cpu: 60.0,
            avg_memory: 70.0,
            avg_disk: 65.0,
        },
        HistoryMetric {
            agent_id: "agent-002".to_string(),
            avg_cpu: 40.0,
            avg_memory: 55.0,
            avg_disk: 50.0,
        },
        HistoryMetric {
            agent_id: "cloud:tencent:ins-abc123".to_string(),
            avg_cpu: 75.0,
            avg_memory: 80.0,
            avg_disk: 70.0,
        },
    ];
    println!("   ✅ 准备了 7 天历史均值数据\n");

    // 3. 构建分析输入
    println!("🔧 步骤 3: 构建 AI 分析输入");
    let report_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let input = AnalysisInput {
        current_metrics: current_metrics.clone(),
        history_metrics,
        locale: "zh-CN".to_string(),
        report_date: report_date.clone(),
    };
    println!("   ✅ 报告日期: {}\n", report_date);

    // 4. 读取 API Key，决定使用真实 API 还是模拟数据
    let api_key = std::env::var("ZHIPU_API_KEY").unwrap_or_default();
    // 默认使用 Anthropic 模式（对应 seed_ai_glm_anthropic 账号），可通过环境变量覆盖
    let api_mode = std::env::var("ZHIPU_API_MODE").unwrap_or_else(|_| "anthropic".to_string());

    let (ai_analysis, risk_level, ai_provider, ai_model) = if api_key.is_empty() {
        println!("🤖 步骤 4: AI 分析（模拟模式）");
        println!("   ⚠️  未检测到 ZHIPU_API_KEY，使用模拟数据");
        println!("   💡 设置 ZHIPU_API_KEY=your-key 后重新运行以调用真实 API\n");

        let mock_analysis = r#"# 系统监控日常报告

## 整体评估
根据今日监控数据分析，系统整体运行状况为**中等风险**。

## 关键发现

### 高负载服务器
- **agent-001**: CPU 使用率 75.5%，内存使用率 82.3%，较历史均值上升明显
  - 风险: CPU 和内存使用率持续偏高，建议关注
  - 建议: 检查是否有异常进程，考虑扩容或优化

- **cloud:tencent:ins-abc123**: CPU 使用率 90.1%，内存使用率 88.7%
  - 风险: **高风险**，云服务器资源接近饱和
  - 建议: 立即检查负载来源，考虑升级实例配置

### 正常运行服务器
- **agent-002**: 各项指标正常，CPU 45.2%，内存 60.5%

## 总结
系统存在部分高负载节点，建议及时处理。

RISK_LEVEL:medium"#;
        (mock_analysis.to_string(), "medium".to_string(), "zhipu", "glm-5（模拟）")
    } else {
        // 根据 api_mode 选择端点
        let (base_url, mode_label) = if api_mode.eq_ignore_ascii_case("openai") {
            (
                "https://open.bigmodel.cn/api/paas/v4".to_string(),
                "OpenAI 兼容",
            )
        } else {
            (
                "https://open.bigmodel.cn/api/anthropic".to_string(),
                "Anthropic 兼容",
            )
        };

        println!("🤖 步骤 4: AI 分析（真实 API - {} 模式）", mode_label);
        println!("   端点: {}", base_url);
        println!("   api_mode: {}", api_mode);
        println!("   模型: glm-5\n");

        let provider = ZhipuProvider::new(
            api_key,
            Some("glm-5".to_string()),
            Some(base_url),
            Some(120),   // 超时 120 秒
            Some(4096),  // max_tokens
            None,        // temperature 默认
            Some(api_mode.clone()),
        )?;

        println!("   调用中，请稍候...");
        let result = provider.analyze(input).await?;
        println!(
            "   ✅ 风险等级: {}\n   ✅ 内容长度: {} 字符\n",
            result.risk_level.as_str(),
            result.content.len()
        );

        let level_str = result.risk_level.as_str().to_string();
        (result.content, level_str, "zhipu", "glm-5")
    };

    // 5. 渲染 HTML 报告
    println!("🎨 步骤 5: 渲染 HTML 报告");
    let html_content = ReportRenderer::render_report(&ReportParams {
        report_date: &report_date,
        total_agents: current_metrics.len() as i32,
        risk_level: &risk_level,
        ai_provider,
        ai_model,
        ai_analysis: &ai_analysis,
        created_at: &chrono::Utc::now().to_rfc3339(),
        locale: "zh-CN",
    })?;
    println!("   ✅ HTML 长度: {} 字节\n", html_content.len());

    // 6. 保存报告到文件
    let output_path = "ai_report_demo.html";
    std::fs::write(output_path, &html_content)?;
    println!("📄 步骤 6: 保存报告");
    println!("   ✅ 报告已保存到: {}\n", output_path);

    // 7. 展示摘要
    println!("📊 报告摘要:");
    println!("   - 监控主机数: {}", current_metrics.len());
    println!("   - 报告日期: {}", report_date);
    println!("   - 风险等级: {}", risk_level);
    println!("   - AI 提供商: {}", ai_provider);
    println!("   - 报告格式: HTML A4");
    println!();

    println!("💡 查看报告:");
    println!("   open {}", output_path);

    Ok(())
}
