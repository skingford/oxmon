#!/bin/bash

# AI 账号数据迁移脚本
# 将 system_configs 表中的 ai_account 记录迁移到独立的 ai_accounts 表

set -e

DB_PATH="${1:-data/oxmon.db}"

if [ ! -f "$DB_PATH" ]; then
  echo "❌ 数据库文件不存在: $DB_PATH"
  echo "使用方法: $0 [数据库路径]"
  echo "示例: $0 data/oxmon.db"
  exit 1
fi

echo "🔄 AI 账号数据迁移工具"
echo "================================"
echo "数据库: $DB_PATH"
echo ""

# 1. 检查是否有需要迁移的数据
COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM system_configs WHERE config_type='ai_account';" 2>/dev/null || echo "0")

if [ "$COUNT" -eq 0 ]; then
  echo "✅ 没有需要迁移的 AI 账号数据"
  exit 0
fi

echo "📊 发现 $COUNT 个 AI 账号需要迁移"
echo ""

# 2. 显示待迁移的账号列表
echo "📋 待迁移账号列表:"
sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT
  id,
  config_key,
  provider,
  display_name,
  enabled,
  datetime(created_at, 'localtime') as created_at
FROM system_configs
WHERE config_type='ai_account'
ORDER BY created_at;
EOF
echo ""

# 3. 确认迁移
read -p "是否继续迁移? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "❌ 已取消迁移"
  exit 0
fi

# 4. 备份数据库
BACKUP_PATH="${DB_PATH}.backup_$(date +%Y%m%d_%H%M%S)"
echo "💾 创建备份: $BACKUP_PATH"
cp "$DB_PATH" "$BACKUP_PATH"
echo "✅ 备份成功"
echo ""

# 5. 执行迁移
echo "🔄 开始迁移..."

sqlite3 "$DB_PATH" <<'EOF'
-- 开启事务
BEGIN TRANSACTION;

-- 创建临时表用于数据转换
CREATE TEMP TABLE temp_ai_accounts AS
SELECT
  id,
  config_key,
  provider,
  display_name,
  description,
  json_extract(config_json, '$.api_key') as api_key,
  json_extract(config_json, '$.secret_key') as api_secret,
  json_extract(config_json, '$.model') as model,
  -- 提取除了 api_key, secret_key, model 之外的其他配置
  json_object(
    'base_url', json_extract(config_json, '$.base_url'),
    'timeout_secs', json_extract(config_json, '$.timeout_secs'),
    'max_tokens', json_extract(config_json, '$.max_tokens'),
    'temperature', json_extract(config_json, '$.temperature'),
    'collection_interval_secs', json_extract(config_json, '$.collection_interval_secs')
  ) as extra_config,
  enabled,
  strftime('%s', created_at) as created_at_unix,
  strftime('%s', updated_at) as updated_at_unix
FROM system_configs
WHERE config_type='ai_account';

-- 插入到 ai_accounts 表（跳过已存在的）
INSERT OR IGNORE INTO ai_accounts (
  id,
  config_key,
  provider,
  display_name,
  description,
  api_key,
  api_secret,
  model,
  extra_config,
  enabled,
  created_at,
  updated_at
)
SELECT
  id,
  config_key,
  COALESCE(provider, 'zhipu') as provider,
  display_name,
  description,
  COALESCE(api_key, '') as api_key,
  api_secret,
  model,
  extra_config,
  enabled,
  created_at_unix,
  updated_at_unix
FROM temp_ai_accounts;

-- 提交事务
COMMIT;

-- 显示迁移结果
.mode column
.headers on
SELECT '迁移完成' as status, COUNT(*) as migrated_count FROM ai_accounts;
EOF

MIGRATED=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM ai_accounts;")
echo ""
echo "✅ 迁移完成！已迁移 $MIGRATED 个账号"
echo ""

# 6. 验证迁移结果
echo "🔍 验证迁移结果:"
sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT
  id,
  config_key,
  provider,
  display_name,
  CASE WHEN api_key != '' THEN '***REDACTED***' ELSE 'MISSING' END as api_key,
  CASE WHEN api_secret IS NOT NULL THEN '***REDACTED***' ELSE NULL END as api_secret,
  model,
  enabled
FROM ai_accounts
ORDER BY created_at;
EOF
echo ""

# 7. 询问是否删除旧数据
echo "⚠️  迁移已完成，但 system_configs 中的旧数据仍然保留"
echo "   如需删除旧数据，请运行:"
echo "   sqlite3 $DB_PATH \"DELETE FROM system_configs WHERE config_type='ai_account';\""
echo ""
echo "📁 备份文件: $BACKUP_PATH"
echo "   如需回滚，请运行: cp $BACKUP_PATH $DB_PATH"
echo ""
echo "✅ 迁移完成！"
