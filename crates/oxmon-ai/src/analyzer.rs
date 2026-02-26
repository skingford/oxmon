use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// AI 分析输入
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisInput {
    /// 当前指标快照
    pub current_metrics: Vec<MetricSnapshot>,
    /// 历史 7 天均值
    pub history_metrics: Vec<HistoryMetric>,
    /// 语言环境（zh-CN | en）
    pub locale: String,
    /// 分析日期
    pub report_date: String,
}

/// 指标快照
#[derive(Debug, Clone, Serialize)]
pub struct MetricSnapshot {
    pub agent_id: String,
    pub agent_type: String, // local / cloud:tencent / cloud:alibaba
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<f64>,
    pub disk_usage: Option<f64>,
    pub timestamp: i64,
}

/// 历史指标（均值）
#[derive(Debug, Clone, Serialize)]
pub struct HistoryMetric {
    pub agent_id: String,
    pub avg_cpu: f64,
    pub avg_memory: f64,
    pub avg_disk: f64,
}

/// AI 分析结果
#[derive(Debug, Clone, Deserialize)]
pub struct AnalysisResult {
    /// Markdown 格式分析内容
    pub content: String,
    /// 风险等级
    pub risk_level: RiskLevel,
}

/// 风险等级枚举
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    High,
    Medium,
    Low,
    Normal,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Normal => "normal",
        }
    }
}

impl FromStr for RiskLevel {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Normal,
        })
    }
}

/// AI 分析器 trait（支持多模型扩展）
#[async_trait]
pub trait AIAnalyzer: Send + Sync {
    /// 模型提供商名称
    fn provider(&self) -> &str;

    /// 模型名称
    fn model_name(&self) -> &str;

    /// 分析监控指标，生成报告
    async fn analyze(&self, input: AnalysisInput) -> Result<AnalysisResult>;

    /// 健康检查（可选）
    async fn health_check(&self) -> Result<()> {
        Ok(())
    }
}
