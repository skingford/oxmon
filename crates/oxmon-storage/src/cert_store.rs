use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::{CertCheckResult, CertDomain, CreateDomainRequest};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::auth::TokenEncryptor;

const CERT_DOMAINS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS cert_domains (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    port INTEGER NOT NULL DEFAULT 443,
    enabled INTEGER NOT NULL DEFAULT 1,
    check_interval_secs INTEGER,
    note TEXT,
    last_checked_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_domains_domain ON cert_domains(domain);
CREATE INDEX IF NOT EXISTS idx_cert_domains_enabled ON cert_domains(enabled);
";

const CERT_CHECK_RESULTS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS cert_check_results (
    id TEXT PRIMARY KEY,
    domain_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    is_valid INTEGER NOT NULL DEFAULT 0,
    chain_valid INTEGER NOT NULL DEFAULT 0,
    not_before INTEGER,
    not_after INTEGER,
    days_until_expiry INTEGER,
    issuer TEXT,
    subject TEXT,
    san_list TEXT,
    resolved_ips TEXT,
    error TEXT,
    checked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_results_domain_id ON cert_check_results(domain_id);
CREATE INDEX IF NOT EXISTS idx_cert_results_checked_at ON cert_check_results(checked_at);
CREATE INDEX IF NOT EXISTS idx_cert_results_domain ON cert_check_results(domain);
";

const AGENT_WHITELIST_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS agent_whitelist (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    encrypted_token TEXT,
    description TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
";

const CERTIFICATE_DETAILS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS certificate_details (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    ip_addresses TEXT NOT NULL,
    issuer_cn TEXT,
    issuer_o TEXT,
    issuer_ou TEXT,
    issuer_c TEXT,
    subject_alt_names TEXT,
    chain_valid INTEGER NOT NULL,
    chain_error TEXT,
    last_checked INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_details_not_after ON certificate_details(not_after);
CREATE INDEX IF NOT EXISTS idx_cert_details_domain ON certificate_details(domain);
";

const ALERT_RULES_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    rule_type TEXT NOT NULL,
    metric TEXT NOT NULL,
    agent_pattern TEXT NOT NULL DEFAULT '*',
    severity TEXT NOT NULL DEFAULT 'info',
    enabled INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL DEFAULT '{}',
    silence_secs INTEGER NOT NULL DEFAULT 600,
    source TEXT NOT NULL DEFAULT 'api',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_name ON alert_rules(name);
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);
";

const NOTIFICATION_CHANNELS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS notification_channels (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    channel_type TEXT NOT NULL,
    description TEXT,
    min_severity TEXT NOT NULL DEFAULT 'info',
    enabled INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
";

const NOTIFICATION_RECIPIENTS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS notification_recipients (
    id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notif_recipients_channel ON notification_recipients(channel_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_recipients_uniq ON notification_recipients(channel_id, value);
";

const NOTIFICATION_SILENCE_WINDOWS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS notification_silence_windows (
    id TEXT PRIMARY KEY,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    recurrence TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
";

const USERS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
";

pub struct CertStore {
    conn: Mutex<Connection>,
    _db_path: PathBuf,
    token_encryptor: TokenEncryptor,
}

impl CertStore {
    pub fn new(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let db_path = data_dir.join("cert.db");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(CERT_DOMAINS_SCHEMA)?;
        conn.execute_batch(CERT_CHECK_RESULTS_SCHEMA)?;

        // 迁移 agent_whitelist：如果旧表缺少 id 列（以 agent_id 为主键），则重建
        Self::migrate_agent_whitelist(&conn)?;

        // 迁移 certificate_details：如果旧表缺少 id 列（以 domain 为主键），则重建
        Self::migrate_certificate_details(&conn)?;

        // 迁移：为已有的 cert_check_results 表添加 resolved_ips 列
        let _ = conn.execute_batch("ALTER TABLE cert_check_results ADD COLUMN resolved_ips TEXT;");
        // 迁移：为已有的 cert_check_results 表添加 created_at / updated_at 列
        let _ = conn.execute_batch("ALTER TABLE cert_check_results ADD COLUMN created_at INTEGER;");
        let _ = conn.execute_batch("ALTER TABLE cert_check_results ADD COLUMN updated_at INTEGER;");

        conn.execute_batch(USERS_SCHEMA)?;
        conn.execute_batch(ALERT_RULES_SCHEMA)?;
        conn.execute_batch(NOTIFICATION_CHANNELS_SCHEMA)?;
        conn.execute_batch(NOTIFICATION_RECIPIENTS_SCHEMA)?;
        conn.execute_batch(NOTIFICATION_SILENCE_WINDOWS_SCHEMA)?;

        // 迁移：为已有的 notification_channels 表添加 description 列
        let _ = conn.execute_batch("ALTER TABLE notification_channels ADD COLUMN description TEXT;");

        // 迁移：为已有的 users 表添加 token_version 列
        let _ = conn.execute_batch(
            "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;",
        );

        let token_encryptor = TokenEncryptor::load_or_create(data_dir)?;
        tracing::info!(path = %db_path.display(), "Initialized cert store");
        Ok(Self {
            conn: Mutex::new(conn),
            _db_path: db_path,
            token_encryptor,
        })
    }

    /// 迁移 agent_whitelist 表：从 agent_id 主键迁移到 UUID id 主键
    fn migrate_agent_whitelist(conn: &Connection) -> Result<()> {
        // 检查旧表是否存在
        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='agent_whitelist'",
            [],
            |row| row.get(0),
        )?;

        if !table_exists {
            // 新建表
            conn.execute_batch(AGENT_WHITELIST_SCHEMA)?;
            return Ok(());
        }

        // 检查是否已有 id 列（新 schema）
        let has_id_col = Self::table_has_column(conn, "agent_whitelist", "id")?;
        let has_updated_at_col = Self::table_has_column(conn, "agent_whitelist", "updated_at")?;

        if has_id_col && has_updated_at_col {
            // 已经是新 schema，无需迁移
            return Ok(());
        }

        tracing::info!("Migrating agent_whitelist table to new schema with Snowflake id");

        // 重建表
        conn.execute_batch(
            "
            CREATE TABLE agent_whitelist_new (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL UNIQUE,
                token_hash TEXT NOT NULL,
                encrypted_token TEXT,
                description TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
        ",
        )?;

        // 检查旧表是否有 encrypted_token 列
        let has_encrypted_token =
            Self::table_has_column(conn, "agent_whitelist", "encrypted_token")?;

        if has_encrypted_token {
            // 包含 encrypted_token 列的旧表
            conn.execute_batch("
                INSERT INTO agent_whitelist_new (id, agent_id, token_hash, encrypted_token, description, created_at, updated_at)
                SELECT CAST(abs(random()) AS TEXT),
                       agent_id, token_hash, encrypted_token, description, created_at, created_at
                FROM agent_whitelist;
            ")?;
        } else {
            // 没有 encrypted_token 列的旧表
            conn.execute_batch("
                INSERT INTO agent_whitelist_new (id, agent_id, token_hash, description, created_at, updated_at)
                SELECT CAST(abs(random()) AS TEXT),
                       agent_id, token_hash, description, created_at, created_at
                FROM agent_whitelist;
            ")?;
        }

        conn.execute_batch(
            "
            DROP TABLE agent_whitelist;
            ALTER TABLE agent_whitelist_new RENAME TO agent_whitelist;
        ",
        )?;

        tracing::info!("agent_whitelist migration completed");
        Ok(())
    }

    /// 迁移 certificate_details 表：从 domain 主键迁移到 UUID id 主键
    fn migrate_certificate_details(conn: &Connection) -> Result<()> {
        // 检查旧表是否存在
        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='certificate_details'",
            [],
            |row| row.get(0),
        )?;

        if !table_exists {
            // 新建表
            conn.execute_batch(CERTIFICATE_DETAILS_SCHEMA)?;
            return Ok(());
        }

        // 检查是否已有 id 列（新 schema）
        let has_id_col = Self::table_has_column(conn, "certificate_details", "id")?;
        let has_updated_at_col = Self::table_has_column(conn, "certificate_details", "updated_at")?;

        if has_id_col && has_updated_at_col {
            // 已经是新 schema，无需迁移
            return Ok(());
        }

        tracing::info!("Migrating certificate_details table to new schema with Snowflake id");

        conn.execute_batch(
            "
            CREATE TABLE certificate_details_new (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                not_before INTEGER NOT NULL,
                not_after INTEGER NOT NULL,
                ip_addresses TEXT NOT NULL,
                issuer_cn TEXT,
                issuer_o TEXT,
                issuer_ou TEXT,
                issuer_c TEXT,
                subject_alt_names TEXT,
                chain_valid INTEGER NOT NULL,
                chain_error TEXT,
                last_checked INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
        ",
        )?;

        conn.execute_batch("
            INSERT INTO certificate_details_new (id, domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c, subject_alt_names, chain_valid, chain_error, last_checked, created_at, updated_at)
            SELECT CAST(abs(random()) AS TEXT),
                   domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c, subject_alt_names, chain_valid, chain_error, last_checked, last_checked, last_checked
            FROM certificate_details;
        ")?;

        conn.execute_batch(
            "
            DROP TABLE certificate_details;
            ALTER TABLE certificate_details_new RENAME TO certificate_details;
            CREATE INDEX IF NOT EXISTS idx_cert_details_not_after ON certificate_details(not_after);
            CREATE INDEX IF NOT EXISTS idx_cert_details_domain ON certificate_details(domain);
        ",
        )?;

        tracing::info!("certificate_details migration completed");
        Ok(())
    }

    fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
        let sql = format!("PRAGMA table_info({})", table);
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            row.get::<_, String>(1) // column name is at index 1
        })?;
        for row in rows {
            if row? == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Lock the database connection, recovering from a poisoned Mutex if necessary.
    fn lock_conn(&self) -> MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // ---- cert_domains CRUD ----

    pub fn insert_domain(&self, req: &CreateDomainRequest) -> Result<CertDomain> {
        let conn = self.lock_conn();
        let id = oxmon_common::id::next_id();
        let now = Utc::now().timestamp();
        let port = req.port.unwrap_or(443);
        let check_interval_secs = req.check_interval_secs.map(|v| v as i64);
        conn.execute(
            "INSERT INTO cert_domains (id, domain, port, enabled, check_interval_secs, note, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7)",
            rusqlite::params![id, req.domain, port, check_interval_secs, req.note, now, now],
        )?;
        drop(conn);
        self.get_domain_by_id(&id)
            .and_then(|opt| opt.ok_or_else(|| anyhow::anyhow!("Failed to read inserted domain")))
    }

    pub fn insert_domains_batch(&self, reqs: &[CreateDomainRequest]) -> Result<Vec<CertDomain>> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;
        let now = Utc::now().timestamp();
        let mut ids = Vec::with_capacity(reqs.len());
        {
            let mut stmt = tx.prepare(
                "INSERT INTO cert_domains (id, domain, port, enabled, check_interval_secs, note, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7)",
            )?;
            for req in reqs {
                let id = oxmon_common::id::next_id();
                let port = req.port.unwrap_or(443);
                let check_interval_secs = req.check_interval_secs.map(|v| v as i64);
                stmt.execute(rusqlite::params![
                    id,
                    req.domain,
                    port,
                    check_interval_secs,
                    req.note,
                    now,
                    now,
                ])?;
                ids.push(id);
            }
        }
        tx.commit()?;
        drop(conn);

        let mut domains = Vec::with_capacity(ids.len());
        for id in &ids {
            if let Some(d) = self.get_domain_by_id(id)? {
                domains.push(d);
            }
        }
        Ok(domains)
    }

    pub fn query_domains(
        &self,
        enabled: Option<bool>,
        search: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CertDomain>> {
        let conn = self.lock_conn();
        let mut sql = String::from("SELECT id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, updated_at FROM cert_domains WHERE 1=1");
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(en) = enabled {
            sql.push_str(&format!(" AND enabled = ?{idx}"));
            params.push(Box::new(en as i32));
            idx += 1;
        }
        if let Some(s) = search {
            sql.push_str(&format!(" AND domain LIKE ?{idx}"));
            params.push(Box::new(format!("%{s}%")));
            idx += 1;
        }

        sql.push_str(" ORDER BY created_at DESC");
        sql.push_str(&format!(" LIMIT ?{idx} OFFSET ?{}", idx + 1));
        params.push(Box::new(limit as i64));
        params.push(Box::new(offset as i64));

        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(param_refs.as_slice(), |row| Ok(Self::row_to_domain(row)))?;

        let mut domains = Vec::new();
        for row in rows {
            domains.push(row??);
        }
        Ok(domains)
    }

    pub fn get_domain_by_id(&self, id: &str) -> Result<Option<CertDomain>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, updated_at FROM cert_domains WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], |row| Ok(Self::row_to_domain(row)))?;
        match rows.next() {
            Some(Ok(Ok(d))) => Ok(Some(d)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn get_domain_by_name(&self, domain: &str) -> Result<Option<CertDomain>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, updated_at FROM cert_domains WHERE domain = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![domain], |row| {
            Ok(Self::row_to_domain(row))
        })?;
        match rows.next() {
            Some(Ok(Ok(d))) => Ok(Some(d)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn update_domain(
        &self,
        id: &str,
        port: Option<i32>,
        enabled: Option<bool>,
        check_interval_secs: Option<Option<u64>>,
        note: Option<String>,
    ) -> Result<Option<CertDomain>> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        let mut sets = vec!["updated_at = ?1".to_string()];
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(now)];
        let mut idx = 2;

        if let Some(p) = port {
            sets.push(format!("port = ?{idx}"));
            params.push(Box::new(p));
            idx += 1;
        }
        if let Some(en) = enabled {
            sets.push(format!("enabled = ?{idx}"));
            params.push(Box::new(en as i32));
            idx += 1;
        }
        if let Some(interval) = check_interval_secs {
            sets.push(format!("check_interval_secs = ?{idx}"));
            match interval {
                Some(v) => params.push(Box::new(v as i64)),
                None => params.push(Box::new(rusqlite::types::Null)),
            }
            idx += 1;
        }
        if let Some(n) = note {
            sets.push(format!("note = ?{idx}"));
            params.push(Box::new(n));
            idx += 1;
        }

        let sql = format!(
            "UPDATE cert_domains SET {} WHERE id = ?{idx}",
            sets.join(", ")
        );
        params.push(Box::new(id.to_string()));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let updated = conn.execute(&sql, param_refs.as_slice())?;
        drop(conn);

        if updated == 0 {
            return Ok(None);
        }
        self.get_domain_by_id(id)
    }

    pub fn delete_domain(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        conn.execute(
            "DELETE FROM cert_check_results WHERE domain_id = ?1",
            rusqlite::params![id],
        )?;
        let deleted = conn.execute(
            "DELETE FROM cert_domains WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(deleted > 0)
    }

    // ---- Scheduler queries ----

    pub fn query_domains_due_for_check(
        &self,
        default_interval_secs: u64,
    ) -> Result<Vec<CertDomain>> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        let default_interval = default_interval_secs as i64;

        let mut stmt = conn.prepare(
            "SELECT id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, updated_at
             FROM cert_domains
             WHERE enabled = 1
               AND (last_checked_at IS NULL
                    OR (?1 - last_checked_at >= COALESCE(check_interval_secs, ?2)))",
        )?;
        let rows = stmt.query_map(rusqlite::params![now, default_interval], |row| {
            Ok(Self::row_to_domain(row))
        })?;

        let mut domains = Vec::new();
        for row in rows {
            domains.push(row??);
        }
        Ok(domains)
    }

    pub fn update_last_checked_at(&self, domain_id: &str, ts: DateTime<Utc>) -> Result<()> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE cert_domains SET last_checked_at = ?1 WHERE id = ?2",
            rusqlite::params![ts.timestamp(), domain_id],
        )?;
        Ok(())
    }

    // ---- cert_check_results ----

    pub fn insert_check_result(&self, result: &CertCheckResult) -> Result<()> {
        let conn = self.lock_conn();
        let san_json = result
            .san_list
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let ips_json = result
            .resolved_ips
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO cert_check_results (id, domain_id, domain, is_valid, chain_valid, not_before, not_after, days_until_expiry, issuer, subject, san_list, resolved_ips, error, checked_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            rusqlite::params![
                result.id,
                result.domain_id,
                result.domain,
                result.is_valid as i32,
                result.chain_valid as i32,
                result.not_before.map(|t| t.timestamp()),
                result.not_after.map(|t| t.timestamp()),
                result.days_until_expiry,
                result.issuer,
                result.subject,
                san_json,
                ips_json,
                result.error,
                result.checked_at.timestamp(),
                now,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn query_latest_results(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CertCheckResult>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT r.id, r.domain_id, r.domain, r.is_valid, r.chain_valid, r.not_before, r.not_after, r.days_until_expiry, r.issuer, r.subject, r.san_list, r.resolved_ips, r.error, r.checked_at, r.created_at, r.updated_at
             FROM cert_check_results r
             INNER JOIN (
                 SELECT domain_id, MAX(checked_at) AS max_checked
                 FROM cert_check_results
                 GROUP BY domain_id
             ) latest ON r.domain_id = latest.domain_id AND r.checked_at = latest.max_checked
             INNER JOIN cert_domains d ON d.id = r.domain_id AND d.enabled = 1
             ORDER BY r.checked_at DESC
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit as i64, offset as i64], |row| {
            Ok(Self::row_to_check_result(row))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    pub fn query_result_by_domain(&self, domain: &str) -> Result<Option<CertCheckResult>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, domain_id, domain, is_valid, chain_valid, not_before, not_after, days_until_expiry, issuer, subject, san_list, resolved_ips, error, checked_at, created_at, updated_at
             FROM cert_check_results
             WHERE domain = ?1
             ORDER BY checked_at DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![domain], |row| {
            Ok(Self::row_to_check_result(row))
        })?;
        match rows.next() {
            Some(Ok(Ok(r))) => Ok(Some(r)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    // ---- Row mappers ----

    fn row_to_domain(row: &rusqlite::Row) -> Result<CertDomain> {
        let enabled_int: i32 = row.get(3)?;
        let interval: Option<i64> = row.get(4)?;
        let last_checked: Option<i64> = row.get(6)?;
        let created: i64 = row.get(7)?;
        let updated: i64 = row.get(8)?;
        Ok(CertDomain {
            id: row.get(0)?,
            domain: row.get(1)?,
            port: row.get(2)?,
            enabled: enabled_int != 0,
            check_interval_secs: interval.map(|v| v as u64),
            note: row.get(5)?,
            last_checked_at: last_checked.and_then(|ts| DateTime::from_timestamp(ts, 0)),
            created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
            updated_at: DateTime::from_timestamp(updated, 0).unwrap_or_default(),
        })
    }

    fn row_to_check_result(row: &rusqlite::Row) -> Result<CertCheckResult> {
        let is_valid_int: i32 = row.get(3)?;
        let chain_valid_int: i32 = row.get(4)?;
        let not_before: Option<i64> = row.get(5)?;
        let not_after: Option<i64> = row.get(6)?;
        let days: Option<i64> = row.get(7)?;
        let san_str: Option<String> = row.get(10)?;
        let ips_str: Option<String> = row.get(11)?;
        let checked: i64 = row.get(13)?;
        let created: Option<i64> = row.get(14)?;
        let updated: Option<i64> = row.get(15)?;
        let now = Utc::now();
        Ok(CertCheckResult {
            id: row.get(0)?,
            domain_id: row.get(1)?,
            domain: row.get(2)?,
            is_valid: is_valid_int != 0,
            chain_valid: chain_valid_int != 0,
            not_before: not_before.and_then(|ts| DateTime::from_timestamp(ts, 0)),
            not_after: not_after.and_then(|ts| DateTime::from_timestamp(ts, 0)),
            days_until_expiry: days,
            issuer: row.get(8)?,
            subject: row.get(9)?,
            san_list: san_str.and_then(|s| serde_json::from_str(&s).ok()),
            resolved_ips: ips_str.and_then(|s| serde_json::from_str(&s).ok()),
            error: row.get(12)?,
            checked_at: DateTime::from_timestamp(checked, 0).unwrap_or_default(),
            created_at: created
                .and_then(|ts| DateTime::from_timestamp(ts, 0))
                .unwrap_or(now),
            updated_at: updated
                .and_then(|ts| DateTime::from_timestamp(ts, 0))
                .unwrap_or(now),
        })
    }

    // ---- Agent whitelist operations ----

    pub fn add_agent_to_whitelist(
        &self,
        agent_id: &str,
        token: &str,
        token_hash: &str,
        description: Option<&str>,
    ) -> Result<String> {
        let conn = self.lock_conn();
        let id = oxmon_common::id::next_id();
        let now = Utc::now().timestamp();
        let encrypted_token = self.token_encryptor.encrypt(token)?;
        conn.execute(
            "INSERT INTO agent_whitelist (id, agent_id, token_hash, created_at, updated_at, description, encrypted_token) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![id, agent_id, token_hash, now, now, description, encrypted_token],
        )?;
        Ok(id)
    }

    pub fn get_agent_token_hash(&self, agent_id: &str) -> Result<Option<String>> {
        let conn = self.lock_conn();
        let mut stmt =
            conn.prepare("SELECT token_hash FROM agent_whitelist WHERE agent_id = ?1")?;
        let mut rows = stmt.query_map(rusqlite::params![agent_id], |row| row.get(0))?;
        match rows.next() {
            Some(Ok(hash)) => Ok(Some(hash)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// 获取 agent 的加密 token 和 token_hash，用于认证验证
    pub fn get_agent_auth(&self, agent_id: &str) -> Result<Option<(Option<String>, String)>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT encrypted_token, token_hash FROM agent_whitelist WHERE agent_id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![agent_id], |row| {
            Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?))
        })?;
        match rows.next() {
            Some(Ok((encrypted, hash))) => {
                // 解密 token 用于直接比对
                let token = encrypted.and_then(|e| self.token_encryptor.decrypt(&e).ok());
                Ok(Some((token, hash)))
            }
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn list_agents(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<oxmon_common::types::AgentWhitelistEntry>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, created_at, updated_at, description, encrypted_token FROM agent_whitelist ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit as i64, offset as i64], |row| {
            let created: i64 = row.get(2)?;
            let updated: i64 = row.get(3)?;
            let encrypted_token: Option<String> = row.get(5)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                created,
                updated,
                row.get::<_, Option<String>>(4)?,
                encrypted_token,
            ))
        })?;
        let mut agents = Vec::new();
        for row in rows {
            let (id, agent_id, created, updated, description, encrypted_token) = row?;
            let token = encrypted_token.and_then(|e| self.token_encryptor.decrypt(&e).ok());
            agents.push(oxmon_common::types::AgentWhitelistEntry {
                id,
                agent_id,
                created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
                updated_at: DateTime::from_timestamp(updated, 0).unwrap_or_default(),
                description,
                token,
            });
        }
        Ok(agents)
    }

    pub fn delete_agent_from_whitelist(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        // 尝试按 id 删除，如果不匹配则按 agent_id 删除（向后兼容）
        let deleted = conn.execute(
            "DELETE FROM agent_whitelist WHERE id = ?1 OR agent_id = ?1",
            rusqlite::params![id],
        )?;
        Ok(deleted > 0)
    }

    /// 根据 agent_id 获取白名单条目的 UUID id
    pub fn get_agent_id_by_agent_id(&self, agent_id: &str) -> Result<Option<String>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare("SELECT id FROM agent_whitelist WHERE agent_id = ?1")?;
        let mut rows = stmt.query_map(rusqlite::params![agent_id], |row| row.get(0))?;
        match rows.next() {
            Some(Ok(id)) => Ok(Some(id)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// Check if an agent_id exists in the whitelist.
    pub fn agent_exists(&self, agent_id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM agent_whitelist WHERE agent_id = ?1",
            rusqlite::params![agent_id],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    pub fn update_agent_whitelist(&self, id: &str, description: Option<&str>) -> Result<bool> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        let updated = conn.execute(
            "UPDATE agent_whitelist SET description = ?2, updated_at = ?3 WHERE id = ?1",
            rusqlite::params![id, description, now],
        )?;
        Ok(updated > 0)
    }

    pub fn update_agent_token_hash(&self, id: &str, token: &str, token_hash: &str) -> Result<bool> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        let encrypted_token = self.token_encryptor.encrypt(token)?;
        let updated = conn.execute(
            "UPDATE agent_whitelist SET token_hash = ?2, encrypted_token = ?3, updated_at = ?4 WHERE id = ?1",
            rusqlite::params![id, token_hash, encrypted_token, now],
        )?;
        Ok(updated > 0)
    }

    /// 按 id 获取单个 agent 白名单条目
    pub fn get_agent_by_id(
        &self,
        id: &str,
    ) -> Result<Option<oxmon_common::types::AgentWhitelistEntry>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, agent_id, created_at, updated_at, description, encrypted_token FROM agent_whitelist WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], |row| {
            let created: i64 = row.get(2)?;
            let updated: i64 = row.get(3)?;
            let encrypted_token: Option<String> = row.get(5)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                created,
                updated,
                row.get::<_, Option<String>>(4)?,
                encrypted_token,
            ))
        })?;
        match rows.next() {
            Some(Ok((id, agent_id, created, updated, description, encrypted_token))) => {
                let token = encrypted_token.and_then(|e| self.token_encryptor.decrypt(&e).ok());
                Ok(Some(oxmon_common::types::AgentWhitelistEntry {
                    id,
                    agent_id,
                    created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
                    updated_at: DateTime::from_timestamp(updated, 0).unwrap_or_default(),
                    description,
                    token,
                }))
            }
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    // ---- cert_check_results history ----

    pub fn query_check_results_by_domain_id(
        &self,
        domain_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CertCheckResult>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, domain_id, domain, is_valid, chain_valid, not_before, not_after, days_until_expiry, issuer, subject, san_list, resolved_ips, error, checked_at, created_at, updated_at
             FROM cert_check_results
             WHERE domain_id = ?1
             ORDER BY checked_at DESC
             LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![domain_id, limit as i64, offset as i64],
            |row| Ok(Self::row_to_check_result(row)),
        )?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    pub fn count_check_results_by_domain_id(&self, domain_id: &str) -> Result<u64> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM cert_check_results WHERE domain_id = ?1",
            rusqlite::params![domain_id],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Returns a certificate health summary.
    pub fn cert_summary(&self) -> Result<CertHealthSummary> {
        let conn = self.lock_conn();
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM cert_domains WHERE enabled = 1",
            [],
            |row| row.get(0),
        )?;

        // Get latest result per domain, count valid/invalid/expiring
        let mut stmt = conn.prepare(
            "SELECT r.is_valid, r.days_until_expiry
             FROM cert_check_results r
             INNER JOIN (
                 SELECT domain_id, MAX(checked_at) AS max_checked
                 FROM cert_check_results
                 GROUP BY domain_id
             ) latest ON r.domain_id = latest.domain_id AND r.checked_at = latest.max_checked
             INNER JOIN cert_domains d ON d.id = r.domain_id AND d.enabled = 1",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i32>(0)?, row.get::<_, Option<i64>>(1)?))
        })?;

        let mut valid: u64 = 0;
        let mut invalid: u64 = 0;
        let mut expiring_soon: u64 = 0; // within 30 days

        for row in rows {
            let (is_valid, days) = row?;
            if is_valid != 0 {
                valid += 1;
                if let Some(d) = days {
                    if d <= 30 {
                        expiring_soon += 1;
                    }
                }
            } else {
                invalid += 1;
            }
        }

        Ok(CertHealthSummary {
            total_domains: total as u64,
            valid,
            invalid,
            expiring_soon,
        })
    }

    // ---- Alert rules CRUD ----

    pub fn insert_alert_rule(&self, rule: &AlertRuleRow) -> Result<AlertRuleRow> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO alert_rules (id, name, rule_type, metric, agent_pattern, severity, enabled, config_json, silence_secs, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                rule.id, rule.name, rule.rule_type, rule.metric, rule.agent_pattern,
                rule.severity, rule.enabled as i32, rule.config_json, rule.silence_secs as i64,
                rule.source, now, now,
            ],
        )?;
        drop(conn);
        self.get_alert_rule_by_id(&rule.id)
            .and_then(|opt| opt.ok_or_else(|| anyhow::anyhow!("Failed to read inserted rule")))
    }

    pub fn get_alert_rule_by_id(&self, id: &str) -> Result<Option<AlertRuleRow>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, name, rule_type, metric, agent_pattern, severity, enabled, config_json, silence_secs, source, created_at, updated_at
             FROM alert_rules WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], |row| Ok(Self::row_to_alert_rule(row)))?;
        match rows.next() {
            Some(Ok(Ok(r))) => Ok(Some(r)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn list_alert_rules(&self, limit: usize, offset: usize) -> Result<Vec<AlertRuleRow>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, name, rule_type, metric, agent_pattern, severity, enabled, config_json, silence_secs, source, created_at, updated_at
             FROM alert_rules ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit as i64, offset as i64], |row| {
            Ok(Self::row_to_alert_rule(row))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    pub fn count_alert_rules(&self) -> Result<u64> {
        let conn = self.lock_conn();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM alert_rules", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    pub fn update_alert_rule(&self, id: &str, update: &AlertRuleUpdate) -> Result<Option<AlertRuleRow>> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        let mut sets = vec!["updated_at = ?1".to_string()];
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(now)];
        let mut idx = 2;

        if let Some(ref name) = update.name {
            sets.push(format!("name = ?{idx}"));
            params.push(Box::new(name.clone()));
            idx += 1;
        }
        if let Some(ref metric) = update.metric {
            sets.push(format!("metric = ?{idx}"));
            params.push(Box::new(metric.clone()));
            idx += 1;
        }
        if let Some(ref agent_pattern) = update.agent_pattern {
            sets.push(format!("agent_pattern = ?{idx}"));
            params.push(Box::new(agent_pattern.clone()));
            idx += 1;
        }
        if let Some(ref severity) = update.severity {
            sets.push(format!("severity = ?{idx}"));
            params.push(Box::new(severity.clone()));
            idx += 1;
        }
        if let Some(enabled) = update.enabled {
            sets.push(format!("enabled = ?{idx}"));
            params.push(Box::new(enabled as i32));
            idx += 1;
        }
        if let Some(ref config_json) = update.config_json {
            sets.push(format!("config_json = ?{idx}"));
            params.push(Box::new(config_json.clone()));
            idx += 1;
        }
        if let Some(silence_secs) = update.silence_secs {
            sets.push(format!("silence_secs = ?{idx}"));
            params.push(Box::new(silence_secs as i64));
            idx += 1;
        }

        let sql = format!("UPDATE alert_rules SET {} WHERE id = ?{idx}", sets.join(", "));
        params.push(Box::new(id.to_string()));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let updated = conn.execute(&sql, param_refs.as_slice())?;
        drop(conn);

        if updated == 0 {
            return Ok(None);
        }
        self.get_alert_rule_by_id(id)
    }

    pub fn delete_alert_rule(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        let deleted = conn.execute(
            "DELETE FROM alert_rules WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(deleted > 0)
    }

    pub fn set_alert_rule_enabled(&self, id: &str, enabled: bool) -> Result<Option<AlertRuleRow>> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        let updated = conn.execute(
            "UPDATE alert_rules SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![enabled as i32, now, id],
        )?;
        drop(conn);
        if updated == 0 {
            return Ok(None);
        }
        self.get_alert_rule_by_id(id)
    }

    fn row_to_alert_rule(row: &rusqlite::Row) -> Result<AlertRuleRow> {
        let enabled_int: i32 = row.get(6)?;
        let silence: i64 = row.get(8)?;
        let created: i64 = row.get(10)?;
        let updated: i64 = row.get(11)?;
        Ok(AlertRuleRow {
            id: row.get(0)?,
            name: row.get(1)?,
            rule_type: row.get(2)?,
            metric: row.get(3)?,
            agent_pattern: row.get(4)?,
            severity: row.get(5)?,
            enabled: enabled_int != 0,
            config_json: row.get(7)?,
            silence_secs: silence as u64,
            source: row.get(9)?,
            created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
            updated_at: DateTime::from_timestamp(updated, 0).unwrap_or_default(),
        })
    }

    // ---- Notification channels CRUD ----

    pub fn insert_notification_channel(&self, ch: &NotificationChannelRow) -> Result<NotificationChannelRow> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO notification_channels (id, name, channel_type, description, min_severity, enabled, config_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                ch.id, ch.name, ch.channel_type, ch.description, ch.min_severity,
                ch.enabled as i32, ch.config_json, now, now,
            ],
        )?;
        drop(conn);
        self.get_notification_channel_by_id(&ch.id)
            .and_then(|opt| opt.ok_or_else(|| anyhow::anyhow!("Failed to read inserted channel")))
    }

    pub fn get_notification_channel_by_id(&self, id: &str) -> Result<Option<NotificationChannelRow>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, name, channel_type, description, min_severity, enabled, config_json, created_at, updated_at
             FROM notification_channels WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], |row| Ok(Self::row_to_notification_channel(row)))?;
        match rows.next() {
            Some(Ok(Ok(r))) => Ok(Some(r)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn list_notification_channels(&self, limit: usize, offset: usize) -> Result<Vec<NotificationChannelRow>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, name, channel_type, description, min_severity, enabled, config_json, created_at, updated_at
             FROM notification_channels ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit as i64, offset as i64], |row| {
            Ok(Self::row_to_notification_channel(row))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    pub fn count_notification_channels(&self) -> Result<u64> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM notification_channels", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    pub fn update_notification_channel(&self, id: &str, update: &NotificationChannelUpdate) -> Result<Option<NotificationChannelRow>> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        let mut sets = vec!["updated_at = ?1".to_string()];
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(now)];
        let mut idx = 2;

        if let Some(ref name) = update.name {
            sets.push(format!("name = ?{idx}"));
            params.push(Box::new(name.clone()));
            idx += 1;
        }
        if let Some(ref description) = update.description {
            sets.push(format!("description = ?{idx}"));
            params.push(Box::new(description.clone()));
            idx += 1;
        }
        if let Some(ref min_severity) = update.min_severity {
            sets.push(format!("min_severity = ?{idx}"));
            params.push(Box::new(min_severity.clone()));
            idx += 1;
        }
        if let Some(enabled) = update.enabled {
            sets.push(format!("enabled = ?{idx}"));
            params.push(Box::new(enabled as i32));
            idx += 1;
        }
        if let Some(ref config_json) = update.config_json {
            sets.push(format!("config_json = ?{idx}"));
            params.push(Box::new(config_json.clone()));
            idx += 1;
        }

        let sql = format!("UPDATE notification_channels SET {} WHERE id = ?{idx}", sets.join(", "));
        params.push(Box::new(id.to_string()));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let updated = conn.execute(&sql, param_refs.as_slice())?;
        drop(conn);

        if updated == 0 {
            return Ok(None);
        }
        self.get_notification_channel_by_id(id)
    }

    pub fn delete_notification_channel(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        // 级联删除关联的 recipients
        conn.execute(
            "DELETE FROM notification_recipients WHERE channel_id = ?1",
            rusqlite::params![id],
        )?;
        let deleted = conn.execute(
            "DELETE FROM notification_channels WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(deleted > 0)
    }

    fn row_to_notification_channel(row: &rusqlite::Row) -> Result<NotificationChannelRow> {
        let enabled_int: i32 = row.get(5)?;
        let created: i64 = row.get(7)?;
        let updated: i64 = row.get(8)?;
        Ok(NotificationChannelRow {
            id: row.get(0)?,
            name: row.get(1)?,
            channel_type: row.get(2)?,
            description: row.get(3)?,
            min_severity: row.get(4)?,
            enabled: enabled_int != 0,
            config_json: row.get(6)?,
            created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
            updated_at: DateTime::from_timestamp(updated, 0).unwrap_or_default(),
        })
    }

    // ---- Silence windows CRUD ----

    pub fn insert_silence_window(&self, sw: &SilenceWindowRow) -> Result<SilenceWindowRow> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO notification_silence_windows (id, start_time, end_time, recurrence, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![sw.id, sw.start_time, sw.end_time, sw.recurrence, now, now],
        )?;
        drop(conn);
        self.get_silence_window_by_id(&sw.id)
            .and_then(|opt| opt.ok_or_else(|| anyhow::anyhow!("Failed to read inserted silence window")))
    }

    pub fn get_silence_window_by_id(&self, id: &str) -> Result<Option<SilenceWindowRow>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, start_time, end_time, recurrence, created_at, updated_at
             FROM notification_silence_windows WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], |row| Ok(Self::row_to_silence_window(row)))?;
        match rows.next() {
            Some(Ok(Ok(r))) => Ok(Some(r)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn list_silence_windows(&self, limit: usize, offset: usize) -> Result<Vec<SilenceWindowRow>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, start_time, end_time, recurrence, created_at, updated_at
             FROM notification_silence_windows ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit as i64, offset as i64], |row| {
            Ok(Self::row_to_silence_window(row))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    pub fn delete_silence_window(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        let deleted = conn.execute(
            "DELETE FROM notification_silence_windows WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(deleted > 0)
    }

    fn row_to_silence_window(row: &rusqlite::Row) -> Result<SilenceWindowRow> {
        let created: i64 = row.get(4)?;
        let updated: i64 = row.get(5)?;
        Ok(SilenceWindowRow {
            id: row.get(0)?,
            start_time: row.get(1)?,
            end_time: row.get(2)?,
            recurrence: row.get(3)?,
            created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
            updated_at: DateTime::from_timestamp(updated, 0).unwrap_or_default(),
        })
    }

    // ---- Notification recipients CRUD ----

    pub fn insert_recipient(&self, channel_id: &str, value: &str) -> Result<NotificationRecipientRow> {
        let conn = self.lock_conn();
        let id = oxmon_common::id::next_id();
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO notification_recipients (id, channel_id, value, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, channel_id, value, now],
        )?;
        Ok(NotificationRecipientRow {
            id,
            channel_id: channel_id.to_string(),
            value: value.to_string(),
            created_at: DateTime::from_timestamp(now, 0).unwrap_or_default(),
        })
    }

    pub fn list_recipients_by_channel(&self, channel_id: &str) -> Result<Vec<NotificationRecipientRow>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, channel_id, value, created_at FROM notification_recipients WHERE channel_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(rusqlite::params![channel_id], |row| {
            let created: i64 = row.get(3)?;
            Ok(NotificationRecipientRow {
                id: row.get(0)?,
                channel_id: row.get(1)?,
                value: row.get(2)?,
                created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
            })
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn delete_recipient(&self, id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        let deleted = conn.execute(
            "DELETE FROM notification_recipients WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(deleted > 0)
    }

    /// 替换某渠道的全部收件人：先删后批量插入。
    pub fn set_channel_recipients(&self, channel_id: &str, values: &[String]) -> Result<Vec<NotificationRecipientRow>> {
        let conn = self.lock_conn();
        conn.execute(
            "DELETE FROM notification_recipients WHERE channel_id = ?1",
            rusqlite::params![channel_id],
        )?;
        let now = Utc::now().timestamp();
        let mut results = Vec::with_capacity(values.len());
        let mut stmt = conn.prepare(
            "INSERT INTO notification_recipients (id, channel_id, value, created_at)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for value in values {
            let id = oxmon_common::id::next_id();
            stmt.execute(rusqlite::params![id, channel_id, value, now])?;
            results.push(NotificationRecipientRow {
                id,
                channel_id: channel_id.to_string(),
                value: value.clone(),
                created_at: DateTime::from_timestamp(now, 0).unwrap_or_default(),
            });
        }
        Ok(results)
    }

    /// 列出所有已启用的通知渠道及其收件人。
    pub fn list_enabled_channels_with_recipients(&self) -> Result<Vec<(NotificationChannelRow, Vec<String>)>> {
        let channels = {
            let conn = self.lock_conn();
            let mut stmt = conn.prepare(
                "SELECT id, name, channel_type, description, min_severity, enabled, config_json, created_at, updated_at
                 FROM notification_channels WHERE enabled = 1 ORDER BY created_at ASC",
            )?;
            let rows = stmt.query_map([], |row| Ok(Self::row_to_notification_channel(row)))?;
            let mut results = Vec::new();
            for row in rows {
                results.push(row??);
            }
            results
        };

        let mut result = Vec::with_capacity(channels.len());
        for ch in channels {
            let recipients = self.list_recipients_by_channel(&ch.id)?
                .into_iter()
                .map(|r| r.value)
                .collect();
            result.push((ch, recipients));
        }
        Ok(result)
    }

    // ---- Agent count ----

    pub fn count_agents(&self) -> Result<u64> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM agent_whitelist", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    // ---- Certificate details operations ----

    // ---- User operations ----

    pub fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<oxmon_common::types::User>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, username, password_hash, token_version, created_at, updated_at FROM users WHERE username = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![username], |row| {
            let created: i64 = row.get(4)?;
            let updated: i64 = row.get(5)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                created,
                updated,
            ))
        })?;
        match rows.next() {
            Some(Ok((id, username, password_hash, token_version, created, updated))) => {
                Ok(Some(oxmon_common::types::User {
                    id,
                    username,
                    password_hash,
                    token_version,
                    created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
                    updated_at: DateTime::from_timestamp(updated, 0).unwrap_or_default(),
                }))
            }
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn create_user(&self, username: &str, password_hash: &str) -> Result<String> {
        let conn = self.lock_conn();
        let id = oxmon_common::id::next_id();
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, token_version, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?5)",
            rusqlite::params![id, username, password_hash, now, now],
        )?;
        Ok(id)
    }

    pub fn update_user_password_hash(&self, user_id: &str, password_hash: &str) -> Result<bool> {
        let conn = self.lock_conn();
        let now = Utc::now().timestamp();
        let updated = conn.execute(
            "UPDATE users SET password_hash = ?2, token_version = token_version + 1, updated_at = ?3 WHERE id = ?1",
            rusqlite::params![user_id, password_hash, now],
        )?;
        Ok(updated > 0)
    }

    pub fn count_users(&self) -> Result<i64> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        Ok(count)
    }

    // ---- Certificate details operations ----

    pub fn upsert_certificate_details(
        &self,
        details: &oxmon_common::types::CertificateDetails,
    ) -> Result<()> {
        let conn = self.lock_conn();
        let ip_json = serde_json::to_string(&details.ip_addresses)?;
        let san_json = serde_json::to_string(&details.subject_alt_names)?;
        let now = Utc::now().timestamp();

        // 尝试更新已有记录
        let updated = conn.execute(
            "UPDATE certificate_details SET
                not_before = ?2, not_after = ?3, ip_addresses = ?4,
                issuer_cn = ?5, issuer_o = ?6, issuer_ou = ?7, issuer_c = ?8,
                subject_alt_names = ?9, chain_valid = ?10, chain_error = ?11,
                last_checked = ?12, updated_at = ?13
             WHERE domain = ?1",
            rusqlite::params![
                details.domain,
                details.not_before.timestamp(),
                details.not_after.timestamp(),
                ip_json,
                details.issuer_cn,
                details.issuer_o,
                details.issuer_ou,
                details.issuer_c,
                san_json,
                details.chain_valid as i32,
                details.chain_error,
                details.last_checked.timestamp(),
                now,
            ],
        )?;

        if updated == 0 {
            // 不存在，插入新记录
            let id = oxmon_common::id::next_id();
            conn.execute(
                "INSERT INTO certificate_details
                 (id, domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c,
                  subject_alt_names, chain_valid, chain_error, last_checked, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                rusqlite::params![
                    id,
                    details.domain,
                    details.not_before.timestamp(),
                    details.not_after.timestamp(),
                    ip_json,
                    details.issuer_cn,
                    details.issuer_o,
                    details.issuer_ou,
                    details.issuer_c,
                    san_json,
                    details.chain_valid as i32,
                    details.chain_error,
                    details.last_checked.timestamp(),
                    now,
                    now,
                ],
            )?;
        }
        Ok(())
    }

    pub fn get_certificate_details(
        &self,
        domain: &str,
    ) -> Result<Option<oxmon_common::types::CertificateDetails>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c,
                    subject_alt_names, chain_valid, chain_error, last_checked, created_at, updated_at
             FROM certificate_details WHERE domain = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![domain], |row| {
            Ok(Self::row_to_cert_details(row))
        })?;
        match rows.next() {
            Some(Ok(Ok(details))) => Ok(Some(details)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    /// 按 id 获取证书详情
    pub fn get_certificate_details_by_id(
        &self,
        id: &str,
    ) -> Result<Option<oxmon_common::types::CertificateDetails>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT id, domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c,
                    subject_alt_names, chain_valid, chain_error, last_checked, created_at, updated_at
             FROM certificate_details WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], |row| {
            Ok(Self::row_to_cert_details(row))
        })?;
        match rows.next() {
            Some(Ok(Ok(details))) => Ok(Some(details)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn list_certificate_details(
        &self,
        filter: &oxmon_common::types::CertificateDetailsFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<oxmon_common::types::CertificateDetails>> {
        let conn = self.lock_conn();
        let mut sql = String::from(
            "SELECT id, domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c,
                    subject_alt_names, chain_valid, chain_error, last_checked, created_at, updated_at
             FROM certificate_details WHERE 1=1",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(not_after_lte) = filter.not_after_lte {
            sql.push_str(&format!(" AND not_after <= ?{idx}"));
            params.push(Box::new(not_after_lte));
            idx += 1;
        }
        if let Some(ip) = &filter.ip_address_contains {
            sql.push_str(&format!(" AND ip_addresses LIKE ?{idx}"));
            params.push(Box::new(format!("%{ip}%")));
            idx += 1;
        }
        if let Some(issuer) = &filter.issuer_contains {
            sql.push_str(&format!(
                " AND (issuer_cn LIKE ?{idx} OR issuer_o LIKE ?{idx})"
            ));
            params.push(Box::new(format!("%{issuer}%")));
            idx += 1;
        }

        sql.push_str(" ORDER BY not_after ASC");
        sql.push_str(&format!(" LIMIT ?{idx} OFFSET ?{}", idx + 1));
        params.push(Box::new(limit as i64));
        params.push(Box::new(offset as i64));

        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(Self::row_to_cert_details(row))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    fn row_to_cert_details(row: &rusqlite::Row) -> Result<oxmon_common::types::CertificateDetails> {
        let not_before: i64 = row.get(2)?;
        let not_after: i64 = row.get(3)?;
        let ip_json: String = row.get(4)?;
        let san_json: String = row.get(9)?;
        let chain_valid_int: i32 = row.get(10)?;
        let last_checked: i64 = row.get(12)?;
        let created: i64 = row.get(13)?;
        let updated: i64 = row.get(14)?;

        let ip_addresses: Vec<String> = serde_json::from_str(&ip_json).unwrap_or_default();
        let subject_alt_names: Vec<String> = serde_json::from_str(&san_json).unwrap_or_default();

        Ok(oxmon_common::types::CertificateDetails {
            id: row.get(0)?,
            domain: row.get(1)?,
            not_before: DateTime::from_timestamp(not_before, 0).unwrap_or_default(),
            not_after: DateTime::from_timestamp(not_after, 0).unwrap_or_default(),
            ip_addresses,
            issuer_cn: row.get(5)?,
            issuer_o: row.get(6)?,
            issuer_ou: row.get(7)?,
            issuer_c: row.get(8)?,
            subject_alt_names,
            chain_valid: chain_valid_int != 0,
            chain_error: row.get(11)?,
            last_checked: DateTime::from_timestamp(last_checked, 0).unwrap_or_default(),
            created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
            updated_at: DateTime::from_timestamp(updated, 0).unwrap_or_default(),
        })
    }
}

// ---- Data types for new tables ----

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertRuleRow {
    pub id: String,
    pub name: String,
    pub rule_type: String,
    pub metric: String,
    pub agent_pattern: String,
    pub severity: String,
    pub enabled: bool,
    pub config_json: String,
    pub silence_secs: u64,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AlertRuleUpdate {
    pub name: Option<String>,
    pub metric: Option<String>,
    pub agent_pattern: Option<String>,
    pub severity: Option<String>,
    pub enabled: Option<bool>,
    pub config_json: Option<String>,
    pub silence_secs: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NotificationChannelRow {
    pub id: String,
    pub name: String,
    pub channel_type: String,
    pub description: Option<String>,
    pub min_severity: String,
    pub enabled: bool,
    pub config_json: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct NotificationChannelUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub min_severity: Option<String>,
    pub enabled: Option<bool>,
    pub config_json: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NotificationRecipientRow {
    pub id: String,
    pub channel_id: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SilenceWindowRow {
    pub id: String,
    pub start_time: String,
    pub end_time: String,
    pub recurrence: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CertHealthSummary {
    pub total_domains: u64,
    pub valid: u64,
    pub invalid: u64,
    pub expiring_soon: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, CertStore) {
        oxmon_common::id::init(1, 1);
        let dir = TempDir::new().unwrap();
        let store = CertStore::new(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn test_insert_and_get_domain() {
        let (_dir, store) = setup();
        let req = CreateDomainRequest {
            domain: "example.com".to_string(),
            port: None,
            check_interval_secs: None,
            note: Some("test".to_string()),
        };
        let domain = store.insert_domain(&req).unwrap();
        assert_eq!(domain.domain, "example.com");
        assert_eq!(domain.port, 443);
        assert!(domain.enabled);
        assert_eq!(domain.note, Some("test".to_string()));

        let fetched = store.get_domain_by_id(&domain.id).unwrap().unwrap();
        assert_eq!(fetched.id, domain.id);
    }

    #[test]
    fn test_duplicate_domain_rejected() {
        let (_dir, store) = setup();
        let req = CreateDomainRequest {
            domain: "dup.com".to_string(),
            port: None,
            check_interval_secs: None,
            note: None,
        };
        store.insert_domain(&req).unwrap();
        assert!(store.insert_domain(&req).is_err());
    }

    #[test]
    fn test_batch_insert() {
        let (_dir, store) = setup();
        let reqs = vec![
            CreateDomainRequest {
                domain: "a.com".to_string(),
                port: None,
                check_interval_secs: None,
                note: None,
            },
            CreateDomainRequest {
                domain: "b.com".to_string(),
                port: Some(8443),
                check_interval_secs: Some(3600),
                note: None,
            },
        ];
        let domains = store.insert_domains_batch(&reqs).unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[1].port, 8443);
    }

    #[test]
    fn test_query_domains_filter() {
        let (_dir, store) = setup();
        for name in &["test.com", "example.com", "demo.org"] {
            store
                .insert_domain(&CreateDomainRequest {
                    domain: name.to_string(),
                    port: None,
                    check_interval_secs: None,
                    note: None,
                })
                .unwrap();
        }
        let all = store.query_domains(None, None, 100, 0).unwrap();
        assert_eq!(all.len(), 3);

        let searched = store.query_domains(None, Some("example"), 100, 0).unwrap();
        assert_eq!(searched.len(), 1);
        assert_eq!(searched[0].domain, "example.com");
    }

    #[test]
    fn test_update_domain() {
        let (_dir, store) = setup();
        let domain = store
            .insert_domain(&CreateDomainRequest {
                domain: "update.com".to_string(),
                port: None,
                check_interval_secs: None,
                note: None,
            })
            .unwrap();

        let updated = store
            .update_domain(
                &domain.id,
                Some(8443),
                Some(false),
                Some(Some(7200)),
                Some("updated".to_string()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.port, 8443);
        assert!(!updated.enabled);
        assert_eq!(updated.check_interval_secs, Some(7200));
        assert_eq!(updated.note, Some("updated".to_string()));
    }

    #[test]
    fn test_delete_domain_cascades() {
        let (_dir, store) = setup();
        let domain = store
            .insert_domain(&CreateDomainRequest {
                domain: "delete.com".to_string(),
                port: None,
                check_interval_secs: None,
                note: None,
            })
            .unwrap();

        let result = CertCheckResult {
            id: oxmon_common::id::next_id(),
            domain_id: domain.id.clone(),
            domain: "delete.com".to_string(),
            is_valid: true,
            chain_valid: true,
            not_before: None,
            not_after: None,
            days_until_expiry: Some(30),
            issuer: None,
            subject: None,
            san_list: None,
            resolved_ips: None,
            error: None,
            checked_at: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.insert_check_result(&result).unwrap();

        assert!(store.delete_domain(&domain.id).unwrap());
        assert!(store.get_domain_by_id(&domain.id).unwrap().is_none());
        assert!(store
            .query_result_by_domain("delete.com")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_query_domains_due_for_check() {
        let (_dir, store) = setup();
        // Domain with no last_checked_at should be due
        store
            .insert_domain(&CreateDomainRequest {
                domain: "new.com".to_string(),
                port: None,
                check_interval_secs: None,
                note: None,
            })
            .unwrap();

        let due = store.query_domains_due_for_check(86400).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].domain, "new.com");
    }

    #[test]
    fn test_check_result_crud() {
        let (_dir, store) = setup();
        let domain = store
            .insert_domain(&CreateDomainRequest {
                domain: "cert.com".to_string(),
                port: None,
                check_interval_secs: None,
                note: None,
            })
            .unwrap();

        let result = CertCheckResult {
            id: oxmon_common::id::next_id(),
            domain_id: domain.id,
            domain: "cert.com".to_string(),
            is_valid: true,
            chain_valid: true,
            not_before: Some(Utc::now()),
            not_after: Some(Utc::now() + chrono::Duration::days(90)),
            days_until_expiry: Some(90),
            issuer: Some("Let's Encrypt".to_string()),
            subject: Some("cert.com".to_string()),
            san_list: Some(vec!["cert.com".to_string(), "www.cert.com".to_string()]),
            resolved_ips: Some(vec!["1.2.3.4".to_string(), "2001:db8::1".to_string()]),
            error: None,
            checked_at: Utc::now(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.insert_check_result(&result).unwrap();

        let latest = store.query_latest_results(20, 0).unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].domain, "cert.com");
        assert!(latest[0].is_valid);
        assert_eq!(latest[0].san_list.as_ref().unwrap().len(), 2);
        assert_eq!(latest[0].resolved_ips.as_ref().unwrap().len(), 2);
        assert_eq!(latest[0].resolved_ips.as_ref().unwrap()[0], "1.2.3.4");

        let by_domain = store.query_result_by_domain("cert.com").unwrap().unwrap();
        assert_eq!(by_domain.issuer, Some("Let's Encrypt".to_string()));
        assert_eq!(by_domain.resolved_ips.as_ref().unwrap().len(), 2);
    }
}
