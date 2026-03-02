use serde::{Deserialize, Serialize};

// ─── Anthropic 兼容格式 ────────────────────────────────────────────────────────

/// Anthropic 兼容的聊天请求（用于智谱 /api/anthropic 端点）
#[derive(Debug, Clone, Serialize)]
pub struct AnthropicRequest {
    pub model: String,
    pub messages: Vec<AnthropicMessage>,
    /// 系统提示（Anthropic 将其作为顶层字段，区别于 OpenAI 的 role="system" 消息）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    /// Anthropic 必填字段
    pub max_tokens: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

/// Anthropic 消息（仅支持 "user" / "assistant"，不含 system role）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicMessage {
    pub role: String,
    pub content: String,
}

/// Anthropic 聊天响应
#[derive(Debug, Clone, Deserialize)]
pub struct AnthropicResponse {
    pub id: Option<String>,
    pub content: Vec<AnthropicContent>,
    pub model: Option<String>,
    pub stop_reason: Option<String>,
    pub usage: Option<AnthropicUsage>,
}

/// Anthropic 响应内容块
#[derive(Debug, Clone, Deserialize)]
pub struct AnthropicContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

/// Anthropic Token 使用统计
#[derive(Debug, Clone, Deserialize)]
pub struct AnthropicUsage {
    pub input_tokens: usize,
    pub output_tokens: usize,
}

// ─── OpenAI 兼容格式 ───────────────────────────────────────────────────────────

/// OpenAI 兼容的聊天请求格式（智谱、Kimi、MiniMax 等通用）
#[derive(Debug, Clone, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
}

/// 聊天消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// OpenAI 兼容的聊天响应格式
#[derive(Debug, Clone, Deserialize)]
pub struct ChatResponse {
    pub id: Option<String>,
    pub object: Option<String>,
    pub created: Option<i64>,
    pub model: Option<String>,
    pub choices: Vec<ChatChoice>,
    pub usage: Option<Usage>,
}

/// 聊天选择项
#[derive(Debug, Clone, Deserialize)]
pub struct ChatChoice {
    pub index: usize,
    pub message: ChatMessage,
    pub finish_reason: Option<String>,
}

/// Token 使用统计
#[derive(Debug, Clone, Deserialize)]
pub struct Usage {
    pub prompt_tokens: usize,
    pub completion_tokens: usize,
    pub total_tokens: usize,
}
