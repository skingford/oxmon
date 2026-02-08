use anyhow::Result;
use chrono::{DateTime, Utc};
use oxmon_common::types::{CertCheckResult, CertDomain, CreateDomainRequest};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
    agent_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    description TEXT
);
";

const CERTIFICATE_DETAILS_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS certificate_details (
    domain TEXT PRIMARY KEY,
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
    last_checked INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_details_not_after ON certificate_details(not_after);
";

pub struct CertStore {
    conn: Mutex<Connection>,
    _db_path: PathBuf,
}

impl CertStore {
    pub fn new(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let db_path = data_dir.join("cert.db");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(CERT_DOMAINS_SCHEMA)?;
        conn.execute_batch(CERT_CHECK_RESULTS_SCHEMA)?;
        conn.execute_batch(AGENT_WHITELIST_SCHEMA)?;
        conn.execute_batch(CERTIFICATE_DETAILS_SCHEMA)?;
        // 迁移：为已有的 cert_check_results 表添加 resolved_ips 列
        let _ = conn.execute_batch(
            "ALTER TABLE cert_check_results ADD COLUMN resolved_ips TEXT;",
        );
        tracing::info!(path = %db_path.display(), "Initialized cert store");
        Ok(Self {
            conn: Mutex::new(conn),
            _db_path: db_path,
        })
    }

    // ---- cert_domains CRUD ----

    pub fn insert_domain(&self, req: &CreateDomainRequest) -> Result<CertDomain> {
        let conn = self.conn.lock().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
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
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let now = Utc::now().timestamp();
        let mut ids = Vec::with_capacity(reqs.len());
        {
            let mut stmt = tx.prepare(
                "INSERT INTO cert_domains (id, domain, port, enabled, check_interval_secs, note, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7)",
            )?;
            for req in reqs {
                let id = uuid::Uuid::new_v4().to_string();
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
        let conn = self.conn.lock().unwrap();
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
        let rows = stmt.query_map(param_refs.as_slice(), |row| {
            Ok(Self::row_to_domain(row))
        })?;

        let mut domains = Vec::new();
        for row in rows {
            domains.push(row??);
        }
        Ok(domains)
    }

    pub fn get_domain_by_id(&self, id: &str) -> Result<Option<CertDomain>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, updated_at FROM cert_domains WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![id], |row| {
            Ok(Self::row_to_domain(row))
        })?;
        match rows.next() {
            Some(Ok(Ok(d))) => Ok(Some(d)),
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn get_domain_by_name(&self, domain: &str) -> Result<Option<CertDomain>> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
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

    pub fn query_domains_due_for_check(&self, default_interval_secs: u64) -> Result<Vec<CertDomain>> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE cert_domains SET last_checked_at = ?1 WHERE id = ?2",
            rusqlite::params![ts.timestamp(), domain_id],
        )?;
        Ok(())
    }

    // ---- cert_check_results ----

    pub fn insert_check_result(&self, result: &CertCheckResult) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let san_json = result
            .san_list
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let ips_json = result
            .resolved_ips
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        conn.execute(
            "INSERT INTO cert_check_results (id, domain_id, domain, is_valid, chain_valid, not_before, not_after, days_until_expiry, issuer, subject, san_list, resolved_ips, error, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
            ],
        )?;
        Ok(())
    }

    pub fn query_latest_results(&self) -> Result<Vec<CertCheckResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT r.id, r.domain_id, r.domain, r.is_valid, r.chain_valid, r.not_before, r.not_after, r.days_until_expiry, r.issuer, r.subject, r.san_list, r.resolved_ips, r.error, r.checked_at
             FROM cert_check_results r
             INNER JOIN (
                 SELECT domain_id, MAX(checked_at) AS max_checked
                 FROM cert_check_results
                 GROUP BY domain_id
             ) latest ON r.domain_id = latest.domain_id AND r.checked_at = latest.max_checked
             INNER JOIN cert_domains d ON d.id = r.domain_id AND d.enabled = 1
             ORDER BY r.checked_at DESC",
        )?;
        let rows = stmt.query_map([], |row| Ok(Self::row_to_check_result(row)))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    pub fn query_result_by_domain(&self, domain: &str) -> Result<Option<CertCheckResult>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, domain_id, domain, is_valid, chain_valid, not_before, not_after, days_until_expiry, issuer, subject, san_list, resolved_ips, error, checked_at
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
        })
    }

    // ---- Agent whitelist operations ----

    pub fn add_agent_to_whitelist(
        &self,
        agent_id: &str,
        token_hash: &str,
        description: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO agent_whitelist (agent_id, token_hash, created_at, description) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![agent_id, token_hash, now, description],
        )?;
        Ok(())
    }

    pub fn get_agent_token_hash(&self, agent_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT token_hash FROM agent_whitelist WHERE agent_id = ?1")?;
        let mut rows = stmt.query_map(rusqlite::params![agent_id], |row| row.get(0))?;
        match rows.next() {
            Some(Ok(hash)) => Ok(Some(hash)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    pub fn list_agents(&self) -> Result<Vec<oxmon_common::types::AgentWhitelistEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT agent_id, created_at, description FROM agent_whitelist ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let created: i64 = row.get(1)?;
            Ok(oxmon_common::types::AgentWhitelistEntry {
                agent_id: row.get(0)?,
                created_at: DateTime::from_timestamp(created, 0).unwrap_or_default(),
                description: row.get(2)?,
            })
        })?;
        let mut agents = Vec::new();
        for row in rows {
            agents.push(row?);
        }
        Ok(agents)
    }

    pub fn delete_agent_from_whitelist(&self, agent_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM agent_whitelist WHERE agent_id = ?1",
            rusqlite::params![agent_id],
        )?;
        Ok(deleted > 0)
    }

    pub fn update_agent_whitelist(
        &self,
        agent_id: &str,
        description: Option<&str>,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE agent_whitelist SET description = ?2 WHERE agent_id = ?1",
            rusqlite::params![agent_id, description],
        )?;
        Ok(updated > 0)
    }

    pub fn update_agent_token_hash(&self, agent_id: &str, token_hash: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE agent_whitelist SET token_hash = ?2 WHERE agent_id = ?1",
            rusqlite::params![agent_id, token_hash],
        )?;
        Ok(updated > 0)
    }

    // ---- Certificate details operations ----

    pub fn upsert_certificate_details(
        &self,
        details: &oxmon_common::types::CertificateDetails,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let ip_json = serde_json::to_string(&details.ip_addresses)?;
        let san_json = serde_json::to_string(&details.subject_alt_names)?;
        conn.execute(
            "INSERT OR REPLACE INTO certificate_details
             (domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c,
              subject_alt_names, chain_valid, chain_error, last_checked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
            ],
        )?;
        Ok(())
    }

    pub fn get_certificate_details(
        &self,
        domain: &str,
    ) -> Result<Option<oxmon_common::types::CertificateDetails>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c,
                    subject_alt_names, chain_valid, chain_error, last_checked
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

    pub fn list_certificate_details(
        &self,
        filter: &oxmon_common::types::CertificateDetailsFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<oxmon_common::types::CertificateDetails>> {
        let conn = self.conn.lock().unwrap();
        let mut sql = String::from(
            "SELECT domain, not_before, not_after, ip_addresses, issuer_cn, issuer_o, issuer_ou, issuer_c,
                    subject_alt_names, chain_valid, chain_error, last_checked
             FROM certificate_details WHERE 1=1",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(days) = filter.expiring_within_days {
            let threshold = (Utc::now() + chrono::Duration::days(days)).timestamp();
            sql.push_str(&format!(" AND not_after <= ?{idx}"));
            params.push(Box::new(threshold));
            idx += 1;
        }
        if let Some(ip) = &filter.ip_address {
            sql.push_str(&format!(" AND ip_addresses LIKE ?{idx}"));
            params.push(Box::new(format!("%{ip}%")));
            idx += 1;
        }
        if let Some(issuer) = &filter.issuer {
            sql.push_str(&format!(" AND (issuer_cn LIKE ?{idx} OR issuer_o LIKE ?{idx})"));
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
        let not_before: i64 = row.get(1)?;
        let not_after: i64 = row.get(2)?;
        let ip_json: String = row.get(3)?;
        let san_json: String = row.get(8)?;
        let chain_valid_int: i32 = row.get(9)?;
        let last_checked: i64 = row.get(11)?;

        let ip_addresses: Vec<String> = serde_json::from_str(&ip_json).unwrap_or_default();
        let subject_alt_names: Vec<String> = serde_json::from_str(&san_json).unwrap_or_default();

        Ok(oxmon_common::types::CertificateDetails {
            domain: row.get(0)?,
            not_before: DateTime::from_timestamp(not_before, 0).unwrap_or_default(),
            not_after: DateTime::from_timestamp(not_after, 0).unwrap_or_default(),
            ip_addresses,
            issuer_cn: row.get(4)?,
            issuer_o: row.get(5)?,
            issuer_ou: row.get(6)?,
            issuer_c: row.get(7)?,
            subject_alt_names,
            chain_valid: chain_valid_int != 0,
            chain_error: row.get(10)?,
            last_checked: DateTime::from_timestamp(last_checked, 0).unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, CertStore) {
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
            .update_domain(&domain.id, Some(8443), Some(false), Some(Some(7200)), Some("updated".to_string()))
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
            id: uuid::Uuid::new_v4().to_string(),
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
        };
        store.insert_check_result(&result).unwrap();

        assert!(store.delete_domain(&domain.id).unwrap());
        assert!(store.get_domain_by_id(&domain.id).unwrap().is_none());
        assert!(store.query_result_by_domain("delete.com").unwrap().is_none());
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
            id: uuid::Uuid::new_v4().to_string(),
            domain_id: domain.id.clone(),
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
        };
        store.insert_check_result(&result).unwrap();

        let latest = store.query_latest_results().unwrap();
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
