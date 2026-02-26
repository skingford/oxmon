use crate::analyzer::{AIAnalyzer, AnalysisInput, AnalysisResult, RiskLevel};
use crate::models::{ChatMessage, ChatRequest, ChatResponse};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;

/// 智谱 AI Provider（GLM-4/GLM-5）
#[derive(Clone)]
pub struct ZhipuProvider {
    api_key: String,
    model: String,
    base_url: String,
    client: Client,
    #[allow(dead_code)] // 用于构建时设置超时
    timeout_secs: u64,
    max_tokens: Option<usize>,
    temperature: Option<f32>,
}

impl ZhipuProvider {
    pub fn new(
        api_key: String,
        model: Option<String>,
        base_url: Option<String>,
        timeout_secs: Option<u64>,
        max_tokens: Option<usize>,
        temperature: Option<f32>,
    ) -> Result<Self> {
        let timeout = timeout_secs.unwrap_or(120);
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .build()?;

        Ok(Self {
            api_key,
            model: model.unwrap_or_else(|| "glm-5".to_string()),
            base_url: base_url
                .unwrap_or_else(|| "https://open.bigmodel.cn/api/paas/v4".to_string()),
            client,
            timeout_secs: timeout,
            max_tokens,
            temperature,
        })
    }
}

#[async_trait]
impl AIAnalyzer for ZhipuProvider {
    fn provider(&self) -> &str {
        "zhipu"
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    async fn analyze(&self, input: AnalysisInput) -> Result<AnalysisResult> {
        // 1. 判断是否需要分批处理
        if input.current_metrics.len() > 20 {
            return self.batch_analyze(input).await;
        }

        // 2. 构造 Prompt
        let prompt = crate::prompt::build_analysis_prompt(&input)?;

        // 3. 调用智谱 API
        let response = self.call_api(&prompt).await?;

        // 4. 解析风险等级
        let risk_level = extract_risk_level(&response);

        Ok(AnalysisResult {
            content: response,
            risk_level,
        })
    }
}

impl ZhipuProvider {
    /// 调用智谱 API
    async fn call_api(&self, prompt: &str) -> Result<String> {
        let req = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: "你是一位资深运维专家，擅长分析服务器监控数据并给出专业建议。"
                        .to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
            temperature: self.temperature,
            max_tokens: self.max_tokens,
            top_p: None,
        };

        tracing::debug!(
            model = %self.model,
            prompt_length = prompt.len(),
            "Calling Zhipu API"
        );

        let resp = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await
            .context("Failed to send request to Zhipu API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(
                status = %status,
                body = %body,
                "Zhipu API request failed"
            );
            anyhow::bail!("Zhipu API error {}: {}", status, body);
        }

        let chat_resp: ChatResponse = resp
            .json()
            .await
            .context("Failed to parse Zhipu API response")?;

        tracing::debug!(
            usage = ?chat_resp.usage,
            "Zhipu API response received"
        );

        chat_resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .ok_or_else(|| anyhow::anyhow!("Empty response from Zhipu API"))
    }

    /// 分批处理大量 Agent（每批 20 个）
    async fn batch_analyze(&self, input: AnalysisInput) -> Result<AnalysisResult> {
        const BATCH_SIZE: usize = 20;
        let mut batch_results = Vec::new();

        tracing::info!(
            total_agents = input.current_metrics.len(),
            batch_size = BATCH_SIZE,
            "Performing batch analysis"
        );

        for (idx, chunk) in input.current_metrics.chunks(BATCH_SIZE).enumerate() {
            tracing::info!(
                batch_index = idx,
                batch_size = chunk.len(),
                "Processing batch"
            );

            let batch_input = AnalysisInput {
                current_metrics: chunk.to_vec(),
                history_metrics: input.history_metrics.clone(),
                locale: input.locale.clone(),
                report_date: input.report_date.clone(),
            };

            tracing::info!("Building analysis prompt");
            let prompt = crate::prompt::build_analysis_prompt(&batch_input)
                .context("Failed to build analysis prompt")?;

            tracing::info!(prompt_length = prompt.len(), "Calling Zhipu API");
            let result = self
                .call_api(&prompt)
                .await
                .context(format!("Failed to call API for batch {}", idx))?;

            tracing::info!(result_length = result.len(), "Batch analysis completed");
            batch_results.push(result);
        }

        // 汇总所有批次结果
        tracing::debug!("Summarizing batch results");
        let summary_prompt = crate::prompt::build_summary_prompt(&batch_results, &input.locale)?;
        let final_result = self.call_api(&summary_prompt).await?;
        let risk_level = extract_risk_level(&final_result);

        Ok(AnalysisResult {
            content: final_result,
            risk_level,
        })
    }
}

/// 从 AI 响应中提取风险等级
fn extract_risk_level(content: &str) -> RiskLevel {
    // 1. 优先解析最后一行的 RISK_LEVEL 标签
    if let Some(last_line) = content.lines().last() {
        if let Some(level_str) = last_line.strip_prefix("RISK_LEVEL:") {
            let level = level_str.trim().to_lowercase();
            return match level.as_str() {
                "high" => RiskLevel::High,
                "medium" => RiskLevel::Medium,
                "low" => RiskLevel::Low,
                "normal" => RiskLevel::Normal,
                _ => RiskLevel::Normal,
            };
        }
    }

    // 2. 关键词匹配回退
    let content_lower = content.to_lowercase();
    if content_lower.contains("需要人工介入（是）")
        || content_lower.contains("需要人工介入：是")
        || content_lower.contains("高风险")
    {
        RiskLevel::High
    } else if content_lower.contains("中风险") {
        RiskLevel::Medium
    } else if content_lower.contains("低风险") {
        RiskLevel::Low
    } else {
        RiskLevel::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_risk_level_from_tag() {
        let content = "## 【总结】\n需要人工介入：否\n\nRISK_LEVEL:normal";
        assert_eq!(extract_risk_level(content), RiskLevel::Normal);

        let content2 = "Some analysis...\nRISK_LEVEL:high";
        assert_eq!(extract_risk_level(content2), RiskLevel::High);
    }

    #[test]
    fn test_extract_risk_level_from_keywords() {
        let content = "这是一个高风险的情况";
        assert_eq!(extract_risk_level(content), RiskLevel::High);

        let content2 = "需要人工介入（是）";
        assert_eq!(extract_risk_level(content2), RiskLevel::High);

        let content3 = "中风险提示";
        assert_eq!(extract_risk_level(content3), RiskLevel::Medium);
    }

    #[test]
    fn test_extract_risk_level_default() {
        let content = "All systems normal";
        assert_eq!(extract_risk_level(content), RiskLevel::Normal);
    }
}
