use crate::analyzer::{AIAnalyzer, AnalysisInput, AnalysisResult, RiskLevel};
use crate::models::{
    AnthropicMessage, AnthropicRequest, AnthropicResponse, ChatMessage, ChatRequest, ChatResponse,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;

/// 智谱 API 请求模式
#[derive(Debug, Clone, PartialEq)]
pub enum ApiMode {
    /// OpenAI 兼容模式（默认），端点：/chat/completions
    OpenAI,
    /// Anthropic 兼容模式，端点：/v1/messages
    Anthropic,
}

impl ApiMode {
    /// 根据 base_url 和显式配置自动推断请求模式：
    /// 1. 若 api_mode == "anthropic"，返回 Anthropic
    /// 2. 若 base_url 包含 "/api/anthropic"，返回 Anthropic
    /// 3. 默认返回 OpenAI
    pub fn detect(base_url: &str, explicit_mode: Option<&str>) -> Self {
        if let Some(mode) = explicit_mode {
            if mode.eq_ignore_ascii_case("anthropic") {
                return ApiMode::Anthropic;
            }
        }
        if base_url.contains("/api/anthropic") {
            return ApiMode::Anthropic;
        }
        ApiMode::OpenAI
    }
}

/// 智谱 AI Provider（GLM-5），支持 OpenAI 和 Anthropic 兼容两种请求模式
#[derive(Clone)]
pub struct ZhipuProvider {
    api_key: String,
    model: String,
    base_url: String,
    api_mode: ApiMode,
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
        api_mode: Option<String>,
    ) -> Result<Self> {
        let timeout = timeout_secs.unwrap_or(120);
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .build()?;

        let base_url =
            base_url.unwrap_or_else(|| "https://open.bigmodel.cn/api/paas/v4".to_string());

        let detected_mode = ApiMode::detect(&base_url, api_mode.as_deref());

        tracing::debug!(
            base_url = %base_url,
            api_mode = ?detected_mode,
            "ZhipuProvider initialized"
        );

        Ok(Self {
            api_key,
            model: model.unwrap_or_else(|| "glm-5".to_string()),
            base_url,
            api_mode: detected_mode,
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

        // 3. 调用 API（根据模式自动分发）
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
    /// 根据当前 api_mode 调用对应的 API
    async fn call_api(&self, prompt: &str) -> Result<String> {
        match self.api_mode {
            ApiMode::OpenAI => self.call_api_openai(prompt).await,
            ApiMode::Anthropic => self.call_api_anthropic(prompt).await,
        }
    }

    /// OpenAI 兼容模式：POST {base_url}/chat/completions
    async fn call_api_openai(&self, prompt: &str) -> Result<String> {
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
            "Calling Zhipu API (OpenAI mode)"
        );

        let resp = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await
            .context("Failed to send request to Zhipu API (OpenAI mode)")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(status = %status, body = %body, "Zhipu API (OpenAI) request failed");
            anyhow::bail!("Zhipu API error {}: {}", status, body);
        }

        let chat_resp: ChatResponse = resp
            .json()
            .await
            .context("Failed to parse Zhipu API response (OpenAI mode)")?;

        tracing::debug!(usage = ?chat_resp.usage, "Zhipu API (OpenAI) response received");

        chat_resp
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .ok_or_else(|| anyhow::anyhow!("Empty response from Zhipu API (OpenAI mode)"))
    }

    /// Anthropic 兼容模式：POST {base_url}/v1/messages
    ///
    /// 与 OpenAI 模式的主要区别：
    /// - 鉴权头：`x-api-key` + `anthropic-version`，而非 `Authorization: Bearer`
    /// - 请求结构：系统提示为顶层 `system` 字段，消息列表不含 system role
    /// - 响应结构：`content[].text`，而非 `choices[].message.content`
    async fn call_api_anthropic(&self, prompt: &str) -> Result<String> {
        let req = AnthropicRequest {
            model: self.model.clone(),
            system: Some(
                "你是一位资深运维专家，擅长分析服务器监控数据并给出专业建议。".to_string(),
            ),
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            // Anthropic 要求 max_tokens 必填，默认 4096
            max_tokens: self.max_tokens.unwrap_or(4096),
            temperature: self.temperature,
        };

        tracing::debug!(
            model = %self.model,
            prompt_length = prompt.len(),
            "Calling Zhipu API (Anthropic mode)"
        );

        let resp = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&req)
            .send()
            .await
            .context("Failed to send request to Zhipu API (Anthropic mode)")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(
                status = %status,
                body = %body,
                "Zhipu API (Anthropic) request failed"
            );
            anyhow::bail!("Zhipu API error {}: {}", status, body);
        }

        let anthropic_resp: AnthropicResponse = resp
            .json()
            .await
            .context("Failed to parse Zhipu API response (Anthropic mode)")?;

        tracing::debug!(
            usage = ?anthropic_resp.usage,
            stop_reason = ?anthropic_resp.stop_reason,
            "Zhipu API (Anthropic) response received"
        );

        anthropic_resp
            .content
            .iter()
            .find(|c| c.content_type == "text")
            .map(|c| c.text.clone())
            .ok_or_else(|| anyhow::anyhow!("Empty response from Zhipu API (Anthropic mode)"))
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

    // ─── ApiMode 检测测试 ──────────────────────────────────────────────────────

    #[test]
    fn test_api_mode_detect_default_openai() {
        let mode = ApiMode::detect("https://open.bigmodel.cn/api/paas/v4", None);
        assert_eq!(mode, ApiMode::OpenAI);
    }

    #[test]
    fn test_api_mode_detect_from_url() {
        let mode = ApiMode::detect("https://open.bigmodel.cn/api/anthropic", None);
        assert_eq!(mode, ApiMode::Anthropic);
    }

    #[test]
    fn test_api_mode_detect_from_explicit_config() {
        let mode = ApiMode::detect("https://open.bigmodel.cn/api/paas/v4", Some("anthropic"));
        assert_eq!(mode, ApiMode::Anthropic);
    }

    #[test]
    fn test_api_mode_detect_explicit_overrides_url() {
        // 即使 URL 看起来是 OpenAI，显式配置为 anthropic 时以显式为准
        let mode = ApiMode::detect("https://open.bigmodel.cn/api/paas/v4", Some("anthropic"));
        assert_eq!(mode, ApiMode::Anthropic);
    }

    #[test]
    fn test_api_mode_detect_case_insensitive() {
        let mode = ApiMode::detect("https://open.bigmodel.cn/api/paas/v4", Some("Anthropic"));
        assert_eq!(mode, ApiMode::Anthropic);
    }

    #[test]
    fn test_anthropic_request_serialization() {
        use crate::models::{AnthropicMessage, AnthropicRequest};

        let req = AnthropicRequest {
            model: "glm-5".to_string(),
            system: Some("系统提示".to_string()),
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: "用户消息".to_string(),
            }],
            max_tokens: 4096,
            temperature: Some(0.7),
        };

        let json = serde_json::to_value(&req).unwrap();
        // system 应在顶层
        assert_eq!(json["system"], "系统提示");
        // messages 不含 system role
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["max_tokens"], 4096);
        // temperature 存在时正常序列化
        assert!(json.get("temperature").is_some());
    }
}
