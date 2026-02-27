#!/bin/bash

# 云账号数据验证脚本
# 验证 cloud_accounts 表的数据完整性

set -e

DB_PATH="${1:-data/cert.db}"

if [ ! -f "$DB_PATH" ]; then
  echo "❌ 数据库文件不存在: $DB_PATH"
  exit 1
fi

echo "✅ 云账号数据验证"
echo "================================"
echo "数据库: $DB_PATH"
echo ""

# 1. 检查表是否存在
if ! sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name='cloud_accounts';" | grep -q "cloud_accounts"; then
  echo "❌ cloud_accounts 表不存在"
  exit 1
fi

echo "✅ cloud_accounts 表存在"
echo ""

# 2. 统计账号数量
TOTAL=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM cloud_accounts;")
ENABLED=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM cloud_accounts WHERE enabled=1;")
DISABLED=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM cloud_accounts WHERE enabled=0;")

echo "📊 账号统计:"
echo "   总计: $TOTAL"
echo "   启用: $ENABLED"
echo "   禁用: $DISABLED"
echo ""

if [ "$TOTAL" -eq 0 ]; then
  echo "⚠️  没有云账号数据"
  echo ""
  echo "💡 提示:"
  echo "   - 如果有旧数据需要迁移，运行: ./scripts/migrate_cloud_accounts.sh"
  echo "   - 通过 REST API 创建账号: POST /v1/cloud/accounts"
  exit 0
fi

# 3. 按 provider 分组统计
echo "📈 按供应商统计:"
sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT
  provider,
  COUNT(*) as count,
  SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) as enabled
FROM cloud_accounts
GROUP BY provider;
EOF
echo ""

# 4. 数据完整性检查
echo "🔍 数据完整性检查:"

# 检查必填字段
MISSING_SECRET_ID=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM cloud_accounts WHERE secret_id IS NULL OR secret_id='';")
if [ "$MISSING_SECRET_ID" -gt 0 ]; then
  echo "   ❌ 发现 $MISSING_SECRET_ID 个账号缺少 secret_id"
else
  echo "   ✅ 所有账号都有 secret_id"
fi

MISSING_SECRET_KEY=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM cloud_accounts WHERE secret_key IS NULL OR secret_key='';")
if [ "$MISSING_SECRET_KEY" -gt 0 ]; then
  echo "   ❌ 发现 $MISSING_SECRET_KEY 个账号缺少 secret_key"
else
  echo "   ✅ 所有账号都有 secret_key"
fi

# 检查 config_key 唯一性
DUPLICATE_KEYS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM (SELECT config_key, COUNT(*) as cnt FROM cloud_accounts GROUP BY config_key HAVING cnt > 1);")
if [ "$DUPLICATE_KEYS" -gt 0 ]; then
  echo "   ❌ 发现 $DUPLICATE_KEYS 个重复的 config_key"
  sqlite3 "$DB_PATH" "SELECT config_key, COUNT(*) as cnt FROM cloud_accounts GROUP BY config_key HAVING cnt > 1;"
else
  echo "   ✅ config_key 唯一性正常"
fi

# 检查时间戳
INVALID_TIMESTAMPS=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM cloud_accounts WHERE created_at <= 0 OR updated_at <= 0;")
if [ "$INVALID_TIMESTAMPS" -gt 0 ]; then
  echo "   ❌ 发现 $INVALID_TIMESTAMPS 个账号的时间戳无效"
else
  echo "   ✅ 时间戳正常"
fi

echo ""

# 5. 显示账号列表（脱敏）
echo "📋 账号列表（脱敏）:"
sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT
  id,
  config_key,
  provider,
  display_name,
  CASE WHEN secret_id != '' THEN '***' ELSE 'MISSING' END as secret_id,
  CASE WHEN secret_key != '' THEN '***' ELSE 'MISSING' END as secret_key,
  region,
  collection_interval_secs,
  enabled,
  datetime(created_at, 'unixepoch', 'localtime') as created_at
FROM cloud_accounts
ORDER BY created_at DESC;
EOF
echo ""

# 6. 检查是否还有旧数据在 system_configs
OLD_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM system_configs WHERE config_type='cloud_account';" 2>/dev/null || echo "0")
if [ "$OLD_COUNT" -gt 0 ]; then
  echo "⚠️  发现 $OLD_COUNT 个旧的云账号数据在 system_configs 表中"
  echo "   如已完成迁移验证，可删除旧数据:"
  echo "   sqlite3 $DB_PATH \"DELETE FROM system_configs WHERE config_type='cloud_account';\""
else
  echo "✅ 没有旧的云账号数据在 system_configs 表中"
fi
echo ""

echo "✅ 验证完成"
