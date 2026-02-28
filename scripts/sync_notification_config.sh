#!/bin/bash

# 同步通知配置从 data-test 到 data
# 包括：通知渠道、接收者

set -e

SOURCE_DB="./data-test/oxmon.db"
TARGET_DB="./data/oxmon.db"

echo "========================================"
echo "通知配置同步工具"
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
BACKUP_FILE="${TARGET_DB}.backup.notification_$(date +%Y%m%d_%H%M%S)"
echo "正在备份目标数据库到: $BACKUP_FILE"
cp "$TARGET_DB" "$BACKUP_FILE"
echo "✓ 备份完成"
echo ""

# 显示同步前的数据统计
echo "同步前数据统计:"
echo "----------------------------------------"
echo "源数据库 (data-test):"
sqlite3 "$SOURCE_DB" "
SELECT '启用的邮件渠道: ' || COUNT(*) FROM notification_channels WHERE channel_type='email' AND enabled=1 UNION ALL
SELECT '启用的钉钉渠道: ' || COUNT(*) FROM notification_channels WHERE channel_type='dingtalk' AND enabled=1 UNION ALL
SELECT '邮件接收者: ' || COUNT(*) FROM notification_recipients WHERE channel_id IN (SELECT id FROM notification_channels WHERE channel_type='email' AND enabled=1) UNION ALL
SELECT '钉钉接收者: ' || COUNT(*) FROM notification_recipients WHERE channel_id IN (SELECT id FROM notification_channels WHERE channel_type='dingtalk' AND enabled=1);
"
echo ""
echo "目标数据库 (data):"
sqlite3 "$TARGET_DB" "
SELECT '启用的邮件渠道: ' || COUNT(*) FROM notification_channels WHERE channel_type='email' AND enabled=1 UNION ALL
SELECT '启用的钉钉渠道: ' || COUNT(*) FROM notification_channels WHERE channel_type='dingtalk' AND enabled=1 UNION ALL
SELECT '邮件接收者: ' || COUNT(*) FROM notification_recipients WHERE channel_id IN (SELECT id FROM notification_channels WHERE channel_type='email' AND enabled=1) UNION ALL
SELECT '钉钉接收者: ' || COUNT(*) FROM notification_recipients WHERE channel_id IN (SELECT id FROM notification_channels WHERE channel_type='dingtalk' AND enabled=1);
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
echo "开始同步通知配置..."
echo ""

# 1. 同步邮件和钉钉通知渠道
echo "[1/2] 同步通知渠道 (email & dingtalk)..."
sqlite3 "$TARGET_DB" <<EOF
ATTACH DATABASE '$SOURCE_DB' AS source;

-- 删除目标库中的旧邮件和钉钉渠道
DELETE FROM notification_channels WHERE channel_type IN ('email', 'dingtalk');

-- 插入源库的邮件和钉钉渠道
INSERT INTO notification_channels
SELECT * FROM source.notification_channels
WHERE channel_type IN ('email', 'dingtalk') AND enabled = 1;

SELECT '✓ 同步了 ' || changes() || ' 个通知渠道';
DETACH DATABASE source;
EOF
echo ""

# 2. 同步接收者
echo "[2/2] 同步通知接收者..."
sqlite3 "$TARGET_DB" <<EOF
ATTACH DATABASE '$SOURCE_DB' AS source;

-- 删除目标库中的旧接收者（邮件和钉钉渠道）
DELETE FROM notification_recipients
WHERE channel_id IN (
    SELECT id FROM notification_channels
    WHERE channel_type IN ('email', 'dingtalk')
);

-- 插入源库的接收者（只同步已启用的邮件和钉钉渠道的接收者）
INSERT INTO notification_recipients
SELECT r.* FROM source.notification_recipients r
WHERE r.channel_id IN (
    SELECT id FROM source.notification_channels
    WHERE channel_type IN ('email', 'dingtalk') AND enabled = 1
);

SELECT '✓ 同步了 ' || changes() || ' 个接收者';
DETACH DATABASE source;
EOF
echo ""

# 显示同步后的数据统计
echo "========================================"
echo "同步后数据统计:"
echo "----------------------------------------"
sqlite3 "$TARGET_DB" "
SELECT '=== 邮件通知渠道 ===' as info;
SELECT id, name, enabled FROM notification_channels WHERE channel_type='email';

SELECT '' as blank, '=== 钉钉通知渠道 ===' as info;
SELECT id, name, enabled FROM notification_channels WHERE channel_type='dingtalk';

SELECT '' as blank, '=== 接收者统计 ===' as info;
SELECT
    nc.name as channel_name,
    nc.channel_type,
    COUNT(nr.id) as recipient_count
FROM notification_channels nc
LEFT JOIN notification_recipients nr ON nc.id = nr.channel_id
WHERE nc.channel_type IN ('email', 'dingtalk')
GROUP BY nc.id;
"
echo "----------------------------------------"
echo "✓ 通知配置同步完成！"
echo ""
echo "备份文件: $BACKUP_FILE"
echo "如需回滚，请执行: cp $BACKUP_FILE $TARGET_DB"
echo "========================================"
