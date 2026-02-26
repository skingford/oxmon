#!/bin/bash

# 安装每日AI报告定时任务
# 每天8:00自动生成并发送报告

PROJECT_DIR="/Users/kingford/workspace/github.com/oxmon"
CRON_SCRIPT="$PROJECT_DIR/daily_ai_report_cron.sh"

echo "============================================================"
echo "安装每日AI报告定时任务"
echo "============================================================"
echo ""

# 1. 给脚本添加执行权限
chmod +x "$CRON_SCRIPT"
echo "✅ 已添加执行权限"

# 2. 检查当前cron任务
echo ""
echo "当前的cron任务:"
crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "(无)"

# 3. 添加新的cron任务
CRON_LINE="0 8 * * * $CRON_SCRIPT"

# 检查是否已存在
if crontab -l 2>/dev/null | grep -F "$CRON_SCRIPT" > /dev/null; then
    echo ""
    echo "⚠️  定时任务已存在，跳过添加"
else
    # 添加新任务
    (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
    echo ""
    echo "✅ 已添加定时任务"
fi

echo ""
echo "============================================================"
echo "安装完成！"
echo "============================================================"
echo ""
echo "📋 定时任务详情:"
echo "  时间: 每天 8:00"
echo "  脚本: $CRON_SCRIPT"
echo "  日志: $PROJECT_DIR/logs/ai_report_cron.log"
echo ""
echo "🔍 查看所有cron任务:"
echo "  crontab -l"
echo ""
echo "📝 查看执行日志:"
echo "  tail -f $PROJECT_DIR/logs/ai_report_cron.log"
echo ""
echo "🗑️  删除定时任务:"
echo "  crontab -e"
echo "  (删除包含 '$CRON_SCRIPT' 的行)"
echo ""
echo "🧪 手动测试:"
echo "  $CRON_SCRIPT"
echo ""
echo "============================================================"
