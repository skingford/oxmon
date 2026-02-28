#!/bin/bash

# 云账号数据迁移脚本
# 将 system_configs 表中的 cloud_account 记录迁移到独立的 cloud_accounts 表

set -e

DB_PATH="${1:-data/oxmon.db}"

if [ ! -f "$DB_PATH" ]; then
  echo "❌ 数据库文件不存在: $DB_PATH"
  echo "使用方法: $0 [数据库路径]"
  echo "示例: $0 data/oxmon.db"
  exit 1
fi

echo "🔄 云账号数据迁移工具"
echo "================================"
echo "数据库: $DB_PATH"
echo ""

# 1. 检查是否有需要迁移的数据
COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM system_configs WHERE config_type='cloud_account';" 2>/dev/null || echo "0")

if [ "$COUNT" -eq 0 ]; then
  echo "✅ 没有需要迁移的云账号数据"
  exit 0
fi

echo "📊 发现 $COUNT 个云账号需要迁移"
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
WHERE config_type='cloud_account'
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

-- 插入到 cloud_accounts 表（跳过已存在的）
INSERT OR IGNORE INTO cloud_accounts (
  id,
  config_key,
  provider,
  display_name,
  description,
  secret_id,
  secret_key,
  region,
  extra_config,
  collection_interval_secs,
  enabled,
  created_at,
  updated_at
)
SELECT
  id,
  config_key,
  COALESCE(provider, 'tencent') as provider,
  display_name,
  description,
  COALESCE(json_extract(config_json, '$.secret_id'), '') as secret_id,
  COALESCE(json_extract(config_json, '$.secret_key'), '') as secret_key,
  json_extract(config_json, '$.region') as region,
  json_object(
    'base_url', json_extract(config_json, '$.base_url'),
    'timeout_secs', json_extract(config_json, '$.timeout_secs')
  ) as extra_config,
  COALESCE(json_extract(config_json, '$.collection_interval_secs'), 3600) as collection_interval_secs,
  enabled,
  created_at,
  updated_at
FROM system_configs
WHERE config_type='cloud_account';

-- 提交事务
COMMIT;

-- 显示迁移结果
.mode column
.headers on
SELECT '迁移完成' as status, COUNT(*) as migrated_count FROM cloud_accounts;
EOF

MIGRATED=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM cloud_accounts;")
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
  CASE WHEN secret_id != '' THEN '***REDACTED***' ELSE 'MISSING' END as secret_id,
  CASE WHEN secret_key != '' THEN '***REDACTED***' ELSE 'MISSING' END as secret_key,
  region,
  collection_interval_secs,
  enabled
FROM cloud_accounts
ORDER BY created_at;
EOF
echo ""

# 7. 询问是否删除旧数据
echo "⚠️  迁移已完成，但 system_configs 中的旧数据仍然保留"
echo "   如需删除旧数据，请运行:"
echo "   sqlite3 $DB_PATH \"DELETE FROM system_configs WHERE config_type='cloud_account';\""
echo ""
echo "📁 备份文件: $BACKUP_PATH"
echo "   如需回滚，请运行: cp $BACKUP_PATH $DB_PATH"
echo ""
echo "✅ 迁移完成！"
