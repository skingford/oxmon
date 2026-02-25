#!/bin/bash

# AI 报告测试脚本

set -e

BASE_URL="http://localhost:8080/v1"
DATA_DIR="./data"
TOKEN=""

echo "🚀 开始测试 AI 检测报告功能"
echo ""

# 1. 启动服务器（后台运行）
echo "📡 启动 oxmon-server..."
./target/release/oxmon-server config/server.test.toml > server.log 2>&1 &
SERVER_PID=$!
echo "服务器 PID: $SERVER_PID"
sleep 3

# 等待服务器启动
echo "⏳ 等待服务器启动..."
for i in {1..30}; do
  if curl -s http://localhost:8080/v1/health > /dev/null 2>&1; then
    echo "✅ 服务器启动成功"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "❌ 服务器启动超时"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
  fi
  sleep 1
done

# 2. 登录获取 token
echo ""
echo "🔐 登录获取 Token..."
LOGIN_RESP=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}')

TOKEN=$(echo $LOGIN_RESP | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
  echo "❌ 登录失败"
  echo "响应: $LOGIN_RESP"
  kill $SERVER_PID 2>/dev/null || true
  exit 1
fi

echo "✅ 登录成功，Token 获取成功"

# 3. 查看现有 agents
echo ""
echo "📊 查询现有 agents..."
AGENTS=$(curl -s -X GET "$BASE_URL/agents" \
  -H "Authorization: Bearer $TOKEN")

AGENT_COUNT=$(echo $AGENTS | grep -o '"agent_id"' | wc -l | tr -d ' ')
echo "发现 $AGENT_COUNT 个 agents"

if [ "$AGENT_COUNT" -eq 0 ]; then
  echo "⚠️  没有发现 agents，AI 报告需要至少一个 agent 的指标数据"
  echo "建议先运行 oxmon-agent 或手动插入测试数据"
fi

# 4. 创建 AI 账号配置（使用示例配置）
echo ""
echo "🤖 创建 AI 账号配置..."

AI_ACCOUNT=$(curl -s -X POST "$BASE_URL/ai/accounts" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config_key": "ai_account_test_glm4",
    "provider": "zhipu",
    "display_name": "测试 GLM-4 账号",
    "description": "用于测试的 GLM-4 AI 账号",
    "enabled": true,
    "config": {
      "api_key": "your-api-key-here",
      "model": "glm-4-flash",
      "base_url": "https://open.bigmodel.cn/api/paas/v4",
      "timeout_secs": 60,
      "max_tokens": 4000,
      "temperature": 0.7,
      "collection_interval_secs": 10
    }
  }')

AI_ACCOUNT_ID=$(echo $AI_ACCOUNT | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$AI_ACCOUNT_ID" ]; then
  echo "❌ AI 账号创建失败"
  echo "响应: $AI_ACCOUNT"
  kill $SERVER_PID 2>/dev/null || true
  exit 1
fi

echo "✅ AI 账号创建成功，ID: $AI_ACCOUNT_ID"

# 5. 查看 AI 账号列表
echo ""
echo "📋 查看 AI 账号列表..."
AI_ACCOUNTS=$(curl -s -X GET "$BASE_URL/ai/accounts" \
  -H "Authorization: Bearer $TOKEN")
echo $AI_ACCOUNTS | jq '.[0] | {id, config_key, provider, display_name, enabled}'

# 6. 等待调度器触发（collection_interval_secs=10）
echo ""
echo "⏰ 等待 AI 调度器触发报告生成..."
echo "   (调度器间隔: 1 小时，账号间隔: 10 秒)"
echo "   提示: AI 账号的 collection_interval_secs 设置为 10 秒用于测试"
echo ""
echo "📝 查看服务器日志："
echo "   tail -f server.log"
echo ""
echo "🔍 手动查询报告："
echo "   curl -X GET '$BASE_URL/ai/reports' -H 'Authorization: Bearer $TOKEN' | jq"
echo ""
echo "⚠️  注意: 需要配置真实的智谱 API Key 才能生成报告"
echo "   更新 API Key: PUT $BASE_URL/ai/accounts/$AI_ACCOUNT_ID"
echo ""

# 等待 15 秒，查看日志
sleep 15
echo ""
echo "📄 最近的服务器日志:"
tail -30 server.log | grep -i "ai\|report" || echo "未发现 AI 相关日志"

# 7. 查询生成的报告
echo ""
echo "📊 查询 AI 报告..."
REPORTS=$(curl -s -X GET "$BASE_URL/ai/reports" \
  -H "Authorization: Bearer $TOKEN")

REPORT_COUNT=$(echo $REPORTS | grep -o '"id"' | wc -l | tr -d ' ')
echo "发现 $REPORT_COUNT 个报告"

if [ "$REPORT_COUNT" -gt 0 ]; then
  echo ""
  echo "✅ 报告列表:"
  echo $REPORTS | jq '.[] | {id, report_date, risk_level, total_agents, ai_provider, ai_model}'

  # 获取第一个报告 ID
  FIRST_REPORT_ID=$(echo $REPORTS | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

  if [ ! -z "$FIRST_REPORT_ID" ]; then
    echo ""
    echo "📄 查看报告详情:"
    echo "   浏览器访问: http://localhost:8080/v1/ai/reports/$FIRST_REPORT_ID/view"
    echo "   或运行: curl -X GET '$BASE_URL/ai/reports/$FIRST_REPORT_ID' -H 'Authorization: Bearer $TOKEN' | jq '.ai_analysis'"
  fi
else
  echo "⚠️  暂无报告生成"
  echo ""
  echo "可能原因:"
  echo "1. AI 账号的 API Key 未配置或无效"
  echo "2. 没有 agent 指标数据"
  echo "3. 调度器尚未触发（默认 1 小时检查一次）"
  echo ""
  echo "手动触发测试建议:"
  echo "1. 配置真实的智谱 API Key"
  echo "2. 确保有 agent 上报数据"
  echo "3. 调整配置文件 ai_check.tick_secs = 60 (改为 1 分钟)"
  echo "4. 或者直接修改 collection_interval_secs = 5 (改为 5 秒立即触发)"
fi

echo ""
echo "🛑 停止服务器 (PID: $SERVER_PID)"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "✅ 测试完成"
echo ""
echo "📚 API 文档: http://localhost:8080/docs"
echo "📊 查看更多日志: cat server.log"
