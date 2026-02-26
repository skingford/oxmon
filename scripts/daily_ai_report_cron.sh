#!/bin/bash

# 每日AI报告发送脚本（简化版）
# 用于cron定时任务：每天8:00发送最新的AI报告

set -e

# 配置
PROJECT_DIR="/Users/kingford/workspace/github.com/oxmon"
DB_PATH="$PROJECT_DIR/data/cert.db"
LOG_FILE="$PROJECT_DIR/logs/ai_report_cron.log"
PYTHON_SCRIPT="$PROJECT_DIR/send_ai_report_clean.py"

# 确保日志目录存在
mkdir -p "$PROJECT_DIR/logs"

# 记录开始时间
echo "============================================================" >> "$LOG_FILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') - 开始每日AI报告发送任务" >> "$LOG_FILE"
echo "============================================================" >> "$LOG_FILE"

cd "$PROJECT_DIR"

# 1. 检查是否有报告
REPORT_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM ai_reports;")

if [ "$REPORT_COUNT" -eq 0 ]; then
    echo "$(date '+%H:%M:%S') ❌ 没有找到AI报告" >> "$LOG_FILE"
    echo "============================================================" >> "$LOG_FILE"
    exit 1
fi

# 2. 获取最新报告信息
LATEST_REPORT=$(sqlite3 "$DB_PATH" "
SELECT
    report_date || '|' ||
    risk_level || '|' ||
    total_agents || '|' ||
    datetime(created_at, 'unixepoch', 'localtime')
FROM ai_reports
ORDER BY created_at DESC
LIMIT 1;
")

REPORT_DATE=$(echo "$LATEST_REPORT" | cut -d'|' -f1)
RISK_LEVEL=$(echo "$LATEST_REPORT" | cut -d'|' -f2)
TOTAL_AGENTS=$(echo "$LATEST_REPORT" | cut -d'|' -f3)
CREATED_AT=$(echo "$LATEST_REPORT" | cut -d'|' -f4)

echo "$(date '+%H:%M:%S') 📊 最新报告信息:" >> "$LOG_FILE"
echo "  - 报告日期: $REPORT_DATE" >> "$LOG_FILE"
echo "  - 风险等级: $RISK_LEVEL" >> "$LOG_FILE"
echo "  - 监控节点: $TOTAL_AGENTS" >> "$LOG_FILE"
echo "  - 创建时间: $CREATED_AT" >> "$LOG_FILE"

# 3. 检查是否今天已经发送过
TODAY=$(date '+%Y-%m-%d')
LAST_NOTIF=$(sqlite3 "$DB_PATH" "
SELECT datetime(created_at, 'unixepoch', 'localtime')
FROM notification_logs
WHERE alert_event_id = (SELECT id FROM ai_reports ORDER BY created_at DESC LIMIT 1)
  AND status = 'success'
  AND date(created_at, 'unixepoch') = date('now')
ORDER BY created_at DESC
LIMIT 1;
")

if [ ! -z "$LAST_NOTIF" ]; then
    echo "$(date '+%H:%M:%S') ℹ️  今天已发送过通知（$LAST_NOTIF），跳过" >> "$LOG_FILE"
    echo "$(date '+%H:%M:%S') 💡 提示：如需重新发送，请删除今天的通知日志" >> "$LOG_FILE"
    echo "============================================================" >> "$LOG_FILE"
    exit 0
fi

# 4. 发送通知
echo "$(date '+%H:%M:%S') 📤 发送AI报告通知..." >> "$LOG_FILE"

if python3 "$PYTHON_SCRIPT" >> "$LOG_FILE" 2>&1; then
    echo "$(date '+%H:%M:%S') ✅ 通知发送成功" >> "$LOG_FILE"
    SEND_STATUS="成功"
else
    echo "$(date '+%H:%M:%S') ❌ 通知发送失败" >> "$LOG_FILE"
    SEND_STATUS="失败"
fi

echo "$(date '+%H:%M:%S') ✅ 每日AI报告任务完成 - 发送状态: $SEND_STATUS" >> "$LOG_FILE"
echo "============================================================" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

# 返回发送状态
if [ "$SEND_STATUS" = "失败" ]; then
    exit 1
fi
