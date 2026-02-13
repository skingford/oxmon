#!/usr/bin/env bash
# Migration script: Move system_config_id references to channel-level config_json
#
# This script helps migrate existing deployments that used system_configs
# for sender configurations (email/sms) to the new unified model where
# all sender configs are stored directly in notification_channels.config_json.
#
# Usage:
#   ./migrate_system_configs_to_channels.sh <data_dir>
#
# Example:
#   ./migrate_system_configs_to_channels.sh /var/lib/oxmon

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <data_dir>"
    echo "Example: $0 /var/lib/oxmon"
    exit 1
fi

DATA_DIR="$1"
CERT_DB="${DATA_DIR}/cert_store.db"

if [ ! -f "$CERT_DB" ]; then
    echo "Error: Database not found at ${CERT_DB}"
    exit 1
fi

echo "=== oxmon System Config Migration ==="
echo "Database: ${CERT_DB}"
echo

# Check if we need migration
CHANNELS_WITH_REF=$(sqlite3 "$CERT_DB" \
    "SELECT COUNT(*) FROM notification_channels WHERE system_config_id IS NOT NULL AND system_config_id != '';")

if [ "$CHANNELS_WITH_REF" -eq 0 ]; then
    echo "✓ No channels reference system_config_id. Migration not needed."
    exit 0
fi

echo "Found ${CHANNELS_WITH_REF} channel(s) with system_config_id references."
echo

# Create backup
BACKUP_FILE="${CERT_DB}.backup.$(date +%Y%m%d_%H%M%S)"
echo "Creating backup: ${BACKUP_FILE}"
cp "$CERT_DB" "$BACKUP_FILE"
echo "✓ Backup created"
echo

# Perform migration
echo "Starting migration..."

sqlite3 "$CERT_DB" <<'EOF'
BEGIN TRANSACTION;

-- Create temporary table to store merged configs
CREATE TEMP TABLE merged_configs AS
SELECT
    nc.id,
    nc.name,
    nc.config_json as channel_config,
    sc.config_json as system_config,
    sc.config_key
FROM notification_channels nc
JOIN system_configs sc ON nc.system_config_id = sc.id
WHERE nc.system_config_id IS NOT NULL AND nc.system_config_id != '';

-- Display channels to be migrated
.mode column
.headers on
SELECT
    name as "Channel Name",
    config_key as "System Config"
FROM merged_configs;

-- Update channels: merge system config into channel config_json
-- If channel has empty config ({}), use system config directly
-- Otherwise, keep channel config (assumes it's already complete)
UPDATE notification_channels
SET
    config_json = (
        SELECT CASE
            WHEN mc.channel_config = '{}' OR mc.channel_config = ''
            THEN mc.system_config
            ELSE mc.channel_config
        END
        FROM merged_configs mc
        WHERE mc.id = notification_channels.id
    ),
    system_config_id = NULL
WHERE id IN (SELECT id FROM merged_configs);

COMMIT;

-- Show migration result
SELECT
    '✓ Migration completed. ' || COUNT(*) || ' channel(s) updated.' as Result
FROM merged_configs;

EOF

echo
echo "=== Migration Summary ==="
echo "✓ Channels updated: system_config_id cleared, configs merged"
echo "✓ Backup available at: ${BACKUP_FILE}"
echo
echo "Notes:"
echo "  - system_configs table is unchanged (runtime settings still use it)"
echo "  - You can now delete old sender configs (config_type='email'/'sms') if desired:"
echo "    sqlite3 ${CERT_DB} \"DELETE FROM system_configs WHERE config_type IN ('email', 'sms');\""
echo
echo "To verify migration:"
echo "  sqlite3 ${CERT_DB} \"SELECT name, channel_type, system_config_id IS NULL as migrated FROM notification_channels;\""
