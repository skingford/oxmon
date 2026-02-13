# Migration Guide

This document describes migration procedures for upgrading existing oxmon deployments.

## v0.2.0: Unified Notification Configuration

**Date**: 2024-02
**Affects**: Deployments using `system_config_id` in notification channels

### Background

In earlier versions, notification channels could reference sender configurations (SMTP, SMS) via `system_config_id`. This created two ways to configure senders:
1. Channel-level: `notification_channels.config_json`
2. System-level: `system_configs` + `system_config_id` reference

Version 0.2.0 simplifies this by removing the system-level sender configuration. All sender configurations are now stored directly in each channel's `config_json`.

### Changes

- **Removed**: `notification_channels.system_config_id` column (no longer used)
- **Removed**: Ability to create `system_configs` with `config_type="email"` or `"sms"`
- **Changed**: `/v1/system/configs` API now only accepts `config_type="runtime"`
- **Unchanged**: `system_configs` table still exists for runtime settings (aggregation_window, log_retention)

### Migration Required?

Run this query to check if you need migration:

```sql
sqlite3 /var/lib/oxmon/cert_store.db \
  "SELECT COUNT(*) FROM notification_channels WHERE system_config_id IS NOT NULL;"
```

- **Result = 0**: No migration needed
- **Result > 0**: Follow migration steps below

### Migration Steps

#### Option 1: Automated Migration (Recommended)

Use the provided migration script:

```bash
cd /path/to/oxmon
./scripts/migrate_system_configs_to_channels.sh /var/lib/oxmon
```

This script will:
1. Create a timestamped backup of `cert_store.db`
2. Merge `system_configs` into channel `config_json` where needed
3. Clear `system_config_id` references
4. Show migration summary

#### Option 2: Manual Migration

1. **Backup your database**:
   ```bash
   cp /var/lib/oxmon/cert_store.db /var/lib/oxmon/cert_store.db.backup
   ```

2. **Identify affected channels**:
   ```sql
   SELECT id, name, channel_type, system_config_id
   FROM notification_channels
   WHERE system_config_id IS NOT NULL;
   ```

3. **For each channel, merge the system config**:
   ```sql
   -- Get system config
   SELECT config_json FROM system_configs WHERE id = '<system_config_id>';

   -- Update channel with merged config
   UPDATE notification_channels
   SET config_json = '<merged_json>', system_config_id = NULL
   WHERE id = '<channel_id>';
   ```

4. **Verify migration**:
   ```sql
   SELECT name, system_config_id IS NULL as migrated
   FROM notification_channels;
   ```

### Post-Migration

After successful migration:

1. **Test notifications**: Send test notifications to verify configs work:
   ```bash
   curl -X POST http://localhost:8080/v1/notifications/channels/<channel_id>/test \
     -H "Authorization: Bearer $TOKEN"
   ```

2. **Clean up old system configs** (optional):
   ```sql
   DELETE FROM system_configs WHERE config_type IN ('email', 'sms');
   ```

3. **Update your processes**: If you have scripts that create channels with `system_config_id`, update them to include full `config_json` instead.

### Example: Before and After

**Before (v0.1.x)**:
```json
{
  "name": "Email Alerts",
  "channel_type": "email",
  "system_config_id": "sys-smtp-1",
  "config_json": "{}",
  "recipients": ["admin@example.com"]
}
```

**After (v0.2.0)**:
```json
{
  "name": "Email Alerts",
  "channel_type": "email",
  "config_json": "{\"smtp_host\":\"smtp.example.com\",\"smtp_port\":587,\"smtp_username\":\"noreply\",\"smtp_password\":\"secret\",\"from\":\"alerts@example.com\"}",
  "recipients": ["admin@example.com"]
}
```

### Rollback

If you need to rollback after migration:

1. Stop oxmon-server
2. Restore the backup:
   ```bash
   cp /var/lib/oxmon/cert_store.db.backup.* /var/lib/oxmon/cert_store.db
   ```
3. Downgrade to previous version
4. Restart oxmon-server

### Troubleshooting

**Q: My channels show "no valid config_json" after upgrade**
A: Run the migration script to merge system configs into channels.

**Q: Can I still use system_configs for email/sms?**
A: No. In v0.2.0+, `system_configs` is limited to `config_type="runtime"` only. Sender configs must be in channel `config_json`.

**Q: What about new deployments?**
A: New deployments (starting from v0.2.0) don't need migration. Simply create channels with full `config_json`.

### Getting Help

- GitHub Issues: https://github.com/yourusername/oxmon/issues
- Check logs: `journalctl -u oxmon-server -n 100`
