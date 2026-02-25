/// AI 报告功能演示程序
///
/// 用途: 演示 AI 分析器、报告生成和 HTML 渲染的核心流程
///
/// 运行: cargo run --example test_ai_report
use anyhow::Result;
use oxmon_ai::{AIAnalyzer, AnalysisInput, HistoryMetric, MetricSnapshot, ZhipuProvider};
use oxmon_notify::report_template::ReportRenderer;

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
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
    println!("   ✅ 准备了 {} 天历史数据\n", 7);

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

    // 4. 模拟 AI 分析 (不调用真实 API)
    println!("🤖 步骤 4: AI 分析 (模拟)");
    println!("   ⚠️  注意: 需要配置真实的智谱 API Key 才能调用实际 API");
    println!("   当前演示使用模拟数据\n");

    // 模拟 AI 分析结果
    let ai_analysis = r#"# 系统监控日常报告

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

## 趋势分析
- agent-001 的 CPU 使用率相比历史均值上升 15.5%
- cloud:tencent:ins-abc123 持续高负载，需重点关注

## 行动建议
1. 优先处理 cloud:tencent:ins-abc123 的高负载问题
2. 对 agent-001 进行性能优化或资源扩容评估
3. 继续监控 agent-002 的运行状况
4. 建议设置更精细的告警规则

## 总结
系统存在部分高负载节点，建议及时处理以避免服务中断。
"#;

    let risk_level = "medium";
    println!("   ✅ 风险等级: {}", risk_level);
    println!("   ✅ 分析内容长度: {} 字符\n", ai_analysis.len());

    // 5. 渲染 HTML 报告
    println!("🎨 步骤 5: 渲染 HTML 报告");
    let html_content = ReportRenderer::render_report(
        &report_date,
        current_metrics.len() as i32,
        risk_level,
        "zhipu",
        "glm-4-flash",
        ai_analysis,
        &chrono::Utc::now().to_rfc3339(),
        "zh-CN",
    )?;
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
    println!("   - AI 提供商: zhipu (GLM-4)");
    println!("   - 报告格式: HTML A4");
    println!();

    // 8. 提示如何查看
    println!("💡 查看报告:");
    println!("   浏览器打开: open {}", output_path);
    println!("   或直接双击文件查看");
    println!();

    // 9. 真实 API 调用示例 (需要配置)
    println!("🔑 如需测试真实 AI API:");
    println!("   1. 获取智谱 API Key: https://open.bigmodel.cn");
    println!("   2. 设置环境变量: export ZHIPU_API_KEY=your-key");
    println!("   3. 修改代码取消注释真实 API 调用部分");
    println!();

    println!("✅ 演示完成!");

    Ok(())
}
