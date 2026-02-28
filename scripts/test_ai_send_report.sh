#!/bin/bash

# AI 报告生成和发送测试脚本

set -e

echo "🚀 AI 报告生成和发送完整测试"
echo "================================"
echo ""

# 加载 .env 配置
if [ ! -f .env ]; then
  echo "❌ 未找到 .env 文件"
  exit 1
fi

source .env

echo "✅ 配置加载成功:"
echo "   - 智谱 API Key: ${ZHI_PU_API_KEY:0:10}***"
echo "   - 模型: $ZHI_PU_MODEL"
echo "   - 邮箱: $EMAIL_FROM_USERNAME"
echo "   - 钉钉 Webhook: ${DINGTALK_WEBHOOK_URL:0:50}..."
echo ""

# 变量定义
BASE_URL="http://localhost:8080/v1"
TOKEN=""
AI_ACCOUNT_ID=""
REPORT_ID=""

# 清理函数
cleanup() {
  echo ""
  echo "🧹 清理测试环境..."
  pkill -f "oxmon-server config/server.test.toml" 2>/dev/null || true
  sleep 1
}

# 设置退出时清理
trap cleanup EXIT

# 1. 启动服务器
echo "📡 步骤 1: 启动 oxmon-server"
./target/release/oxmon-server config/server.test.toml > server.log 2>&1 &
SERVER_PID=$!
echo "   服务器 PID: $SERVER_PID"
sleep 3

# 等待服务器就绪
echo "   等待服务器启动..."
for i in {1..30}; do
  if curl -s http://localhost:8080/v1/health > /dev/null 2>&1; then
    echo "   ✅ 服务器启动成功"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "   ❌ 服务器启动超时"
    exit 1
  fi
  sleep 1
done
echo ""

# 2. 登录获取 Token (使用简单的用户名密码，不加密)
echo "🔐 步骤 2: 登录系统"
echo "   提示: 当前 API 需要 RSA 加密密码，此脚本简化处理"
echo "   实际使用请先调用 GET /v1/auth/public-key 获取公钥"
echo ""

# 这里我们直接查询数据库获取 token (仅测试用)
echo "   ⚠️  跳过登录步骤，直接测试 AI 功能"
echo ""

# 3. 创建真实的 AI 账号
echo "🤖 步骤 3: 创建 AI 账号"

# 先检查是否已存在
EXISTING_ACCOUNT=$(sqlite3 data/oxmon.db "SELECT id FROM ai_accounts WHERE config_key='ai_test_glm5' LIMIT 1;" 2>/dev/null || echo "")

if [ ! -z "$EXISTING_ACCOUNT" ]; then
  echo "   ⚠️  AI 账号已存在，使用现有账号: $EXISTING_ACCOUNT"
  AI_ACCOUNT_ID=$EXISTING_ACCOUNT
else
  # 生成 ID
  AI_ACCOUNT_ID=$(date +%s)000

  # 构建额外配置 JSON (不包含 api_key, model)
  EXTRA_CONFIG=$(cat <<EOF
{
  "base_url": "https://open.bigmodel.cn/api/paas/v4",
  "timeout_secs": 60,
  "max_tokens": 4000,
  "temperature": 0.7,
  "collection_interval_secs": 5
}
EOF
)

  # 直接插入数据库到 ai_accounts 表
  sqlite3 data/oxmon.db <<EOF
INSERT INTO ai_accounts (
  id, config_key, provider, display_name, description,
  api_key, model, extra_config, enabled, created_at, updated_at
) VALUES (
  '$AI_ACCOUNT_ID',
  'ai_test_glm5',
  'zhipu',
  '测试 GLM-5 账号',
  '从 .env 加载的测试账号',
  '$ZHI_PU_API_KEY',
  '$ZHI_PU_MODEL',
  '$EXTRA_CONFIG',
  1,
  strftime('%s', 'now'),
  strftime('%s', 'now')
);
EOF

  echo "   ✅ AI 账号创建成功"
fi

echo "   账号 ID: $AI_ACCOUNT_ID"
echo "   模型: $ZHI_PU_MODEL"
echo "   间隔: 5 秒 (快速测试)"
echo ""

# 4. 检查 agents 和指标数据
echo "📊 步骤 4: 检查数据状态"
AGENT_COUNT=$(sqlite3 data/oxmon.db "SELECT COUNT(*) FROM agents;" 2>/dev/null || echo "0")
echo "   Agents 数量: $AGENT_COUNT"

if [ "$AGENT_COUNT" -eq 0 ]; then
  echo "   ⚠️  没有真实 agents，插入测试数据..."

  # 插入测试 agents
  sqlite3 data/oxmon.db <<EOF
INSERT OR IGNORE INTO agents (agent_id, first_seen, last_seen, created_at)
VALUES
  ('test-agent-1', datetime('now'), datetime('now'), datetime('now')),
  ('test-agent-2', datetime('now'), datetime('now'), datetime('now')),
  ('test-agent-3', datetime('now'), datetime('now'), datetime('now'));
EOF

  echo "   ✅ 已创建 3 个测试 agents"
fi

# 检查指标数据
PARTITION_DB="data/$(date +%Y-%m-%d).db"
METRIC_COUNT=$(sqlite3 "$PARTITION_DB" "SELECT COUNT(*) FROM metrics WHERE agent_id LIKE 'test-agent%';" 2>/dev/null || echo "0")
echo "   测试指标数量: $METRIC_COUNT"

if [ "$METRIC_COUNT" -lt 10 ]; then
  echo "   ⚠️  指标数据不足，生成测试数据..."

  # 这里可以运行 agent 或手动插入数据
  # 简化处理：使用调度器的模拟数据
  echo "   提示: 调度器会使用占位符数据"
fi
echo ""

# 5. 等待调度器触发
echo "⏰ 步骤 5: 等待 AI 调度器触发"
echo "   配置: tick_secs=30, collection_interval_secs=5"
echo "   预计等待: 5-35 秒"
echo ""

# 监控日志
echo "   监控服务器日志 (15 秒)..."
tail -f server.log &
TAIL_PID=$!
sleep 15
kill $TAIL_PID 2>/dev/null || true
echo ""

# 6. 查询生成的报告
echo "📄 步骤 6: 查询 AI 报告"
REPORT_COUNT=$(sqlite3 data/oxmon.db "SELECT COUNT(*) FROM ai_reports WHERE ai_account_id='$AI_ACCOUNT_ID';" 2>/dev/null || echo "0")
echo "   报告数量: $REPORT_COUNT"

if [ "$REPORT_COUNT" -eq 0 ]; then
  echo "   ⚠️  暂未生成报告，继续等待..."
  echo "   查看完整日志: tail -f server.log | grep -i 'ai\|report'"
  echo ""
  echo "   可能原因:"
  echo "   1. 调度器尚未触发 (每 30 秒检查一次)"
  echo "   2. API Key 无效"
  echo "   3. 网络问题"
  echo ""

  # 再等待 30 秒
  echo "   额外等待 30 秒..."
  sleep 30

  REPORT_COUNT=$(sqlite3 data/oxmon.db "SELECT COUNT(*) FROM ai_reports WHERE ai_account_id='$AI_ACCOUNT_ID';" 2>/dev/null || echo "0")
  echo "   报告数量: $REPORT_COUNT"
fi

if [ "$REPORT_COUNT" -gt 0 ]; then
  # 获取最新报告
  REPORT_ID=$(sqlite3 data/oxmon.db "SELECT id FROM ai_reports WHERE ai_account_id='$AI_ACCOUNT_ID' ORDER BY created_at DESC LIMIT 1;")

  echo "   ✅ 发现 AI 报告!"
  echo "   报告 ID: $REPORT_ID"
  echo ""

  # 查询报告详情
  echo "📊 报告详情:"
  sqlite3 data/oxmon.db <<EOF
.mode column
.headers on
SELECT
  report_date,
  risk_level,
  total_agents,
  ai_provider,
  ai_model,
  notified,
  datetime(created_at, 'localtime') as created_at
FROM ai_reports
WHERE id='$REPORT_ID';
EOF
  echo ""

  # 显示 AI 分析摘要
  echo "🤖 AI 分析 (前 500 字符):"
  sqlite3 data/oxmon.db "SELECT substr(ai_analysis, 1, 500) || '...' FROM ai_reports WHERE id='$REPORT_ID';"
  echo ""

  # 保存 HTML 报告
  HTML_FILE="ai_report_${REPORT_ID}.html"
  sqlite3 data/oxmon.db "SELECT html_content FROM ai_reports WHERE id='$REPORT_ID';" > "$HTML_FILE"
  echo "💾 HTML 报告已保存: $HTML_FILE"
  echo "   浏览器查看: open $HTML_FILE"
  echo ""

  # 7. 测试通知发送
  echo "📧 步骤 7: 测试通知发送"
  echo ""

  # 7.1 测试钉钉通知
  echo "   7.1 测试钉钉机器人通知"

  # 构建钉钉消息
  DINGTALK_MSG=$(cat <<EOF
{
  "msgtype": "markdown",
  "markdown": {
    "title": "🤖 AI 检测报告 - $REPORT_DATE",
    "text": "## 🤖 AI 系统监控报告\\n\\n**报告日期**: $(date +%Y-%m-%d)\\n\\n**风险等级**: 🔔 中等风险\\n\\n**监控主机**: 3 台\\n\\n**AI 分析**: 系统运行正常，部分节点需要关注\\n\\n---\\n\\n[📄 查看完整报告](http://localhost:8080/v1/ai/reports/$REPORT_ID/view)\\n\\n---\\n\\n*由 oxmon AI 自动生成*"
  }
}
EOF
)

  # 计算签名
  TIMESTAMP=$(date +%s)000
  SECRET="$DINGTALK_SECRET"
  STRING_TO_SIGN="${TIMESTAMP}\n${SECRET}"
  SIGN=$(echo -n "$STRING_TO_SIGN" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64 | python3 -c "import sys; import urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))")

  # 发送钉钉通知
  RESPONSE=$(curl -s -X POST "${DINGTALK_WEBHOOK_URL}&timestamp=${TIMESTAMP}&sign=${SIGN}" \
    -H "Content-Type: application/json" \
    -d "$DINGTALK_MSG")

  if echo "$RESPONSE" | grep -q '"errcode":0'; then
    echo "   ✅ 钉钉通知发送成功"
  else
    echo "   ❌ 钉钉通知发送失败: $RESPONSE"
  fi
  echo ""

  # 7.2 测试邮件通知
  echo "   7.2 测试邮件通知"
  echo "   提示: 邮件发送需要集成 SMTP 客户端"
  echo "   当前配置:"
  echo "   - SMTP: $EMAIL_FROM_HOST:$EMAIL_FROM_PORT"
  echo "   - 发件人: $EMAIL_FROM_USERNAME"
  echo "   ⚠️  邮件发送功能待集成到 NotificationManager"
  echo ""

else
  echo "   ❌ 未能生成 AI 报告"
  echo ""
  echo "   故障排查:"
  echo "   1. 查看日志: tail -50 server.log | grep -i 'ai\|error'"
  echo "   2. 检查 API Key 是否有效"
  echo "   3. 确认网络连接正常"
  echo "   4. 验证账号配置:"
  sqlite3 data/oxmon.db "SELECT * FROM ai_accounts WHERE id='$AI_ACCOUNT_ID';"
fi

echo ""
echo "✅ 测试完成"
echo ""
echo "📚 相关命令:"
echo "   - 查看日志: tail -f server.log"
echo "   - 查看报告: sqlite3 data/oxmon.db 'SELECT * FROM ai_reports;'"
echo "   - 查看账号: curl http://localhost:8080/v1/ai/accounts -H \"Authorization: Bearer \$TOKEN\""
echo "   - API 文档: open http://localhost:8080/docs"
echo ""
