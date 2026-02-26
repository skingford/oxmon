#!/bin/bash

# 同步云信息和域名信息从 data-test 到 data
# 作者: Claude Code
# 日期: 2026-02-26

set -e

SOURCE_DB="./data-test/cert.db"
TARGET_DB="./data/cert.db"

echo "========================================"
echo "数据库同步工具"
echo "源数据库: $SOURCE_DB"
echo "目标数据库: $TARGET_DB"
echo "========================================"
echo ""

# 检查数据库文件是否存在
if [ ! -f "$SOURCE_DB" ]; then
    echo "错误: 源数据库不存在: $SOURCE_DB"
    exit 1
fi

if [ ! -f "$TARGET_DB" ]; then
    echo "错误: 目标数据库不存在: $TARGET_DB"
    exit 1
fi

# 备份目标数据库
BACKUP_FILE="${TARGET_DB}.backup.$(date +%Y%m%d_%H%M%S)"
echo "正在备份目标数据库到: $BACKUP_FILE"
cp "$TARGET_DB" "$BACKUP_FILE"
echo "✓ 备份完成"
echo ""

# 显示同步前的数据统计
echo "同步前数据统计:"
echo "----------------------------------------"
echo "源数据库 (data-test):"
sqlite3 "$SOURCE_DB" "
SELECT 'cloud_instances: ' || COUNT(*) FROM cloud_instances UNION ALL
SELECT 'cloud_collection_state: ' || COUNT(*) FROM cloud_collection_state UNION ALL
SELECT 'system_configs(cloud): ' || COUNT(*) FROM system_configs WHERE config_type='cloud_account' UNION ALL
SELECT 'cert_domains: ' || COUNT(*) FROM cert_domains UNION ALL
SELECT 'certificate_details: ' || COUNT(*) FROM certificate_details;
"
echo ""
echo "目标数据库 (data):"
sqlite3 "$TARGET_DB" "
SELECT 'cloud_instances: ' || COUNT(*) FROM cloud_instances UNION ALL
SELECT 'cloud_collection_state: ' || COUNT(*) FROM cloud_collection_state UNION ALL
SELECT 'system_configs(cloud): ' || COUNT(*) FROM system_configs WHERE config_type='cloud_account' UNION ALL
SELECT 'cert_domains: ' || COUNT(*) FROM cert_domains UNION ALL
SELECT 'certificate_details: ' || COUNT(*) FROM certificate_details;
"
echo "----------------------------------------"
echo ""

# 询问用户确认
read -p "是否继续同步? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "同步已取消"
    exit 0
fi

echo ""
echo "开始同步数据..."
echo ""

# 1. 同步云账号配置（system_configs）
echo "[1/5] 同步云账号配置 (system_configs)..."
sqlite3 "$TARGET_DB" <<EOF
ATTACH DATABASE '$SOURCE_DB' AS source;

-- 删除目标库中的旧云账号配置
DELETE FROM system_configs WHERE config_type = 'cloud_account';

-- 插入源库的云账号配置（使用 * 匹配所有字段）
INSERT INTO system_configs
SELECT * FROM source.system_configs
WHERE config_type = 'cloud_account';

SELECT '✓ 同步了 ' || changes() || ' 条云账号配置';
DETACH DATABASE source;
EOF
echo ""

# 2. 同步云实例（cloud_instances）
echo "[2/5] 同步云实例 (cloud_instances)..."
sqlite3 "$TARGET_DB" <<EOF
ATTACH DATABASE '$SOURCE_DB' AS source;

-- 删除目标库中的旧云实例
DELETE FROM cloud_instances;

-- 插入源库的云实例
INSERT INTO cloud_instances
SELECT * FROM source.cloud_instances;

SELECT '✓ 同步了 ' || changes() || ' 条云实例';
DETACH DATABASE source;
EOF
echo ""

# 3. 同步云采集状态（cloud_collection_state）
echo "[3/5] 同步云采集状态 (cloud_collection_state)..."
sqlite3 "$TARGET_DB" <<EOF
ATTACH DATABASE '$SOURCE_DB' AS source;

-- 删除目标库中的旧云采集状态
DELETE FROM cloud_collection_state;

-- 插入源库的云采集状态
INSERT INTO cloud_collection_state
SELECT * FROM source.cloud_collection_state;

SELECT '✓ 同步了 ' || changes() || ' 条云采集状态';
DETACH DATABASE source;
EOF
echo ""

# 4. 同步证书域名（cert_domains）- 使用 REPLACE 策略合并
echo "[4/5] 同步证书域名 (cert_domains)..."
sqlite3 "$TARGET_DB" <<EOF
ATTACH DATABASE '$SOURCE_DB' AS source;

-- 使用 INSERT OR REPLACE 合并域名数据
INSERT OR REPLACE INTO cert_domains
SELECT * FROM source.cert_domains;

SELECT '✓ 合并了 ' || changes() || ' 条证书域名';
DETACH DATABASE source;
EOF
echo ""

# 5. 同步证书详情（certificate_details）- 使用 REPLACE 策略合并
echo "[5/5] 同步证书详情 (certificate_details)..."
sqlite3 "$TARGET_DB" <<EOF
ATTACH DATABASE '$SOURCE_DB' AS source;

-- 使用 INSERT OR REPLACE 合并证书详情
INSERT OR REPLACE INTO certificate_details
SELECT * FROM source.certificate_details;

SELECT '✓ 合并了 ' || changes() || ' 条证书详情';
DETACH DATABASE source;
EOF
echo ""

# 显示同步后的数据统计
echo "========================================"
echo "同步后数据统计:"
echo "----------------------------------------"
sqlite3 "$TARGET_DB" "
SELECT 'cloud_instances: ' || COUNT(*) FROM cloud_instances UNION ALL
SELECT 'cloud_collection_state: ' || COUNT(*) FROM cloud_collection_state UNION ALL
SELECT 'system_configs(cloud): ' || COUNT(*) FROM system_configs WHERE config_type='cloud_account' UNION ALL
SELECT 'cert_domains: ' || COUNT(*) FROM cert_domains UNION ALL
SELECT 'certificate_details: ' || COUNT(*) FROM certificate_details;
"
echo "----------------------------------------"
echo "✓ 数据同步完成！"
echo ""
echo "备份文件: $BACKUP_FILE"
echo "如需回滚，请执行: cp $BACKUP_FILE $TARGET_DB"
echo "========================================"
