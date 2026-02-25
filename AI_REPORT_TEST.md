# AI 检测报告测试指南

## 概述

AI 检测报告功能已实现,包含以下核心组件:
- ✅ AI 分析器框架 (支持多模型)
- ✅ GLM-5/GLM-4 Provider 实现
- ✅ 自动调度器 (定期生成报告)
- ✅ HTML 报告模板
- ✅ REST API (AI 账号管理、报告查询)
- ✅ 数据库存储

## 当前状态

### 数据库状态
```bash
# Agents: 0 个真实 agent (有 1 个虚拟 cert-checker agent)
# Metrics: 351 条指标数据 (certificate.is_valid)
# AI Accounts: 0 个
# AI Reports: 0 个
```

## 测试步骤

### 方式 1: API 测试 (推荐)

#### 1. 启动服务器
```bash
cd /Users/kingford/workspace/github.com/oxmon
./target/release/oxmon-server config/server.test.toml
```

#### 2. 获取公钥并登录 (需要使用加密密码)
```bash
# 获取 RSA 公钥
curl http://localhost:8080/v1/auth/public-key

# 使用工具加密密码后登录
# (登录需要 RSA 加密,shell 测试较复杂,建议使用 Postman 或前端)
```

#### 3. 创建 AI 账号
```bash
# 准备请求 (需要真实的智谱 API Key)
cat > ai_account.json << 'EOF'
{
  "config_key": "ai_glm4_test",
  "provider": "zhipu",
  "display_name": "测试 GLM-4 账号",
  "description": "用于测试的 AI 账号",
  "enabled": true,
  "config": {
    "api_key": "YOUR_ZHIPU_API_KEY_HERE",
    "model": "glm-4-flash",
    "base_url": "https://open.bigmodel.cn/api/paas/v4",
    "timeout_secs": 60,
    "max_tokens": 4000,
    "temperature": 0.7,
    "collection_interval_secs": 60
  }
}
EOF

# 创建账号 (需要 JWT token)
curl -X POST http://localhost:8080/v1/ai/accounts \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d @ai_account.json
```

#### 4. 等待调度器执行

调度器配置 (config/server.test.toml):
- `tick_secs = 30` - 每 30 秒检查一次
- 账号的 `collection_interval_secs = 60` - 每 60 秒生成一次报告

查看日志:
```bash
tail -f server.log | grep -i "ai\|report"
```

#### 5. 查询报告
```bash
# 列出所有报告
curl -X GET http://localhost:8080/v1/ai/reports \
  -H "Authorization: Bearer YOUR_TOKEN" | jq

# 查看报告详情
curl -X GET http://localhost:8080/v1/ai/reports/{report_id} \
  -H "Authorization: Bearer YOUR_TOKEN" | jq

# 在浏览器查看 HTML 报告
open http://localhost:8080/v1/ai/reports/{report_id}/view
```

### 方式 2: CLI 初始化测试

#### 1. 准备种子数据文件
```bash
# 编辑 config/ai-accounts.test.json,填入真实的 API Key
nano config/ai-accounts.test.json
```

#### 2. 初始化 AI 账号
```bash
./target/release/oxmon-server init-ai-accounts \
  config/server.test.toml \
  config/ai-accounts.test.json
```

#### 3. 启动服务器
```bash
./target/release/oxmon-server config/server.test.toml
```

### 方式 3: 单元测试 (模拟)

创建测试程序验证核心逻辑:

```rust
// tests/ai_report_test.rs
#[tokio::test]
async fn test_ai_analyzer() {
    use oxmon_ai::{AIAnalyzer, AnalysisInput, MetricSnapshot, ZhipuProvider};

    let provider = ZhipuProvider::new(
        "test-key".to_string(),
        Some("glm-4-flash".to_string()),
        None, None, None, None
    ).unwrap();

    let input = AnalysisInput {
        current_metrics: vec![
            MetricSnapshot {
                agent_id: "agent1".to_string(),
                agent_type: "local".to_string(),
                cpu_usage: Some(75.5),
                memory_usage: Some(80.2),
                disk_usage: Some(60.0),
                timestamp: chrono::Utc::now().timestamp(),
            }
        ],
        history_metrics: vec![],
        locale: "zh-CN".to_string(),
        report_date: "2026-02-25".to_string(),
    };

    // 注意: 需要真实 API Key 才能调用
    // let result = provider.analyze(input).await.unwrap();
    // assert!(!result.content.is_empty());
}
```

## 测试数据准备

### 添加测试 Agent 和指标

如果需要更真实的测试数据,可以:

1. 启动 oxmon-agent:
```bash
./target/release/oxmon-agent config/agent.example.toml
```

2. 或手动插入测试数据:
```bash
sqlite3 data/cert.db << 'EOF'
INSERT INTO agents (agent_id, first_seen, last_seen)
VALUES ('test-agent-1', datetime('now'), datetime('now'));
EOF

# 指标会自动写入分区数据库
```

## API 端点

### AI 账号管理
- `GET /v1/ai/accounts` - 列出 AI 账号
- `POST /v1/ai/accounts` - 创建 AI 账号
- `GET /v1/ai/accounts/:id` - 获取账号详情
- `PUT /v1/ai/accounts/:id` - 更新账号
- `DELETE /v1/ai/accounts/:id` - 删除账号

### AI 报告查询
- `GET /v1/ai/reports` - 列出报告
- `GET /v1/ai/reports/:id` - 获取报告详情 (JSON)
- `GET /v1/ai/reports/:id/view` - 查看 HTML 报告

## 配置说明

### 服务器配置 (server.toml)
```toml
[ai_check]
enabled = true              # 启用 AI 调度器
tick_secs = 3600           # 调度器检查间隔 (秒)
history_days = 7           # 历史数据天数
batch_size = 20            # 批处理大小
```

### AI 账号配置
```json
{
  "api_key": "your-key",                    # 必填: API 密钥
  "model": "glm-4-flash",                   # 可选: 模型名称
  "base_url": "https://...",                # 可选: API 地址
  "timeout_secs": 60,                       # 可选: 超时时间
  "max_tokens": 4000,                       # 可选: 最大 token 数
  "temperature": 0.7,                       # 可选: 温度参数
  "collection_interval_secs": 86400         # 必填: 报告生成间隔
}
```

## 预期输出

### 成功的报告示例
```json
{
  "id": "1897234567890",
  "report_date": "2026-02-25",
  "ai_account_id": "ai_glm4_test",
  "ai_provider": "zhipu",
  "ai_model": "glm-4-flash",
  "total_agents": 1,
  "risk_level": "low",
  "ai_analysis": "根据今日监控数据分析...",
  "notified": false,
  "created_at": "2026-02-25T10:30:00Z"
}
```

### HTML 报告特性
- ✅ A4 格式专业排版
- ✅ 风险等级彩色标识
- ✅ Markdown 渲染支持
- ✅ 响应式设计
- ✅ 多语言支持 (中/英)

## 故障排查

### 1. 报告未生成
**可能原因:**
- AI 账号未启用 (`enabled = false`)
- API Key 无效或过期
- 没有 agent 数据
- `collection_interval_secs` 未到期
- 调度器未启动 (`enabled = false`)

**检查方法:**
```bash
# 查看调度器日志
tail -f server.log | grep "AI account is due"

# 查看数据库
sqlite3 data/cert.db "SELECT * FROM system_configs WHERE config_type='ai_account';"
sqlite3 data/cert.db "SELECT * FROM ai_reports ORDER BY created_at DESC LIMIT 1;"

# 查看 agents
sqlite3 data/cert.db "SELECT * FROM agents;"
```

### 2. API Key 错误
```
Error: AI analysis failed: Request failed with status 401
```
**解决:** 检查智谱 API Key 是否有效,更新账号配置。

### 3. 没有指标数据
```
No metrics found, skipping AI report generation
```
**解决:** 确保有 agent 上报数据,或启动 oxmon-agent。

### 4. 调度器不执行
**检查配置:**
- `[ai_check].enabled = true`
- `tick_secs` 设置合理 (测试建议 30-60 秒)
- 账号的 `collection_interval_secs` 不要太大

## 下一步优化

- [ ] 实现实际的指标查询 (目前使用占位符)
- [ ] 集成 NotificationManager 发送邮件/钉钉通知
- [ ] 添加更多 AI provider (Kimi, Claude, 等)
- [ ] 支持自定义提示词模板
- [ ] 添加报告对比和趋势分析
- [ ] 实现报告定期清理策略

## 相关文档

- API 文档: http://localhost:8080/docs
- 配置示例: config/ai-accounts.seed.example.json
- 代码位置: crates/oxmon-ai/, crates/oxmon-server/src/ai/

## 测试总结

✅ **已实现:**
- AI 分析器核心框架
- GLM-4/GLM-5 支持
- 自动调度器
- REST API 完整实现
- HTML 报告生成
- 数据库持久化

⚠️ **需要配置:**
- 真实的智谱 API Key
- agent 上报数据 (或使用现有测试数据)

🔧 **待完善:**
- 实际指标查询实现
- 通知渠道集成
- 更多测试覆盖
