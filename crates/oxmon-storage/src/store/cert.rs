use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use oxmon_common::types::{
    CertCheckResult, CertDomain, CertificateDetails, CertificateDetailsFilter, CreateDomainRequest,
    UpdateDomainRequest,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};

use crate::entities::cert_check_result::{self, Column as CheckCol, Entity as CheckEntity};
use crate::entities::cert_domain::{self, Column as DomainCol, Entity as DomainEntity};
use crate::entities::certificate_detail::{self, Column as DetailCol, Entity as DetailEntity};
use crate::store::CertStore;

/// 证书健康摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertHealthSummary {
    pub total_domains: u64,
    pub valid: u64,
    pub invalid: u64,
    pub expiring_soon: u64,
}

/// 证书域名摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertDomainSummary {
    pub total: u64,
    pub enabled: u64,
    pub disabled: u64,
}

/// 证书状态摘要
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertStatusSummary {
    pub total: u64,
    pub healthy: u64,
    pub failed: u64,
    pub expiring_soon: u64,
}

/// 证书状态过滤器
#[derive(Debug, Clone, Default)]
pub struct CertStatusFilter {
    pub domain_contains: Option<String>,
    pub is_valid: Option<bool>,
    pub days_until_expiry_lte: Option<i64>,
}

fn model_to_domain(m: cert_domain::Model) -> CertDomain {
    CertDomain {
        id: m.id,
        domain: m.domain,
        port: m.port,
        enabled: m.enabled,
        check_interval_secs: m.check_interval_secs.map(|v| v as u64),
        note: m.note,
        last_checked_at: m.last_checked_at.map(|t| t.with_timezone(&Utc)),
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

fn model_to_check_result(m: cert_check_result::Model) -> CertCheckResult {
    let san_list = m
        .san_list
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let resolved_ips = m
        .resolved_ips
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    CertCheckResult {
        id: m.id,
        domain_id: m.domain_id,
        domain: m.domain,
        is_valid: m.is_valid,
        chain_valid: m.chain_valid,
        not_before: m.not_before.map(|t| t.with_timezone(&Utc)),
        not_after: m.not_after.map(|t| t.with_timezone(&Utc)),
        days_until_expiry: m.days_until_expiry.map(|v| v as i64),
        issuer: m.issuer,
        subject: m.subject,
        san_list,
        resolved_ips,
        error: m.error,
        checked_at: m.checked_at.with_timezone(&Utc),
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
    }
}

fn model_to_details(m: certificate_detail::Model) -> CertificateDetails {
    let ip_addresses: Vec<String> = serde_json::from_str(&m.ip_addresses).unwrap_or_default();
    let subject_alt_names: Vec<String> = m
        .subject_alt_names
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let key_usage: Option<Vec<String>> = m
        .key_usage
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let extended_key_usage: Option<Vec<String>> = m
        .extended_key_usage
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let ocsp_urls: Option<Vec<String>> = m
        .ocsp_urls
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let crl_urls: Option<Vec<String>> = m
        .crl_urls
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let ca_issuer_urls: Option<Vec<String>> = m
        .ca_issuer_urls
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());

    CertificateDetails {
        id: m.id,
        domain: m.domain,
        not_before: m.not_before.with_timezone(&Utc),
        not_after: m.not_after.with_timezone(&Utc),
        ip_addresses,
        issuer_cn: m.issuer_cn,
        issuer_o: m.issuer_o,
        issuer_ou: m.issuer_ou,
        issuer_c: m.issuer_c,
        subject_alt_names,
        chain_valid: m.chain_valid,
        chain_error: m.chain_error,
        last_checked: m.last_checked.with_timezone(&Utc),
        created_at: m.created_at.with_timezone(&Utc),
        updated_at: m.updated_at.with_timezone(&Utc),
        serial_number: m.serial_number,
        fingerprint_sha256: m.fingerprint_sha256,
        version: m.version,
        signature_algorithm: m.signature_algorithm,
        public_key_algorithm: m.public_key_algorithm,
        public_key_bits: m.public_key_bits,
        subject_cn: m.subject_cn,
        subject_o: m.subject_o,
        key_usage,
        extended_key_usage,
        is_ca: m.is_ca,
        is_wildcard: m.is_wildcard,
        ocsp_urls,
        crl_urls,
        ca_issuer_urls,
        sct_count: m.sct_count,
        tls_version: m.tls_version,
        cipher_suite: m.cipher_suite,
        chain_depth: m.chain_depth,
    }
}

impl CertStore {
    // ---- cert_domains CRUD ----

    pub async fn insert_domain(&self, req: &CreateDomainRequest) -> Result<CertDomain> {
        let id = oxmon_common::id::next_id();
        let now = Utc::now().fixed_offset();
        let port = req.port.unwrap_or(443);
        let am = cert_domain::ActiveModel {
            id: Set(id.clone()),
            domain: Set(req.domain.clone()),
            port: Set(port),
            enabled: Set(true),
            check_interval_secs: Set(req.check_interval_secs.map(|v| v as i64)),
            note: Set(req.note.clone()),
            last_checked_at: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        };
        am.insert(self.db()).await?;
        self.get_domain_by_id(&id)
            .await?
            .ok_or_else(|| anyhow!("Failed to read inserted domain"))
    }

    pub async fn insert_domains_batch(
        &self,
        reqs: &[CreateDomainRequest],
    ) -> Result<Vec<CertDomain>> {
        let now = Utc::now().fixed_offset();
        let mut ids = Vec::with_capacity(reqs.len());
        for req in reqs {
            let id = oxmon_common::id::next_id();
            let port = req.port.unwrap_or(443);
            let am = cert_domain::ActiveModel {
                id: Set(id.clone()),
                domain: Set(req.domain.clone()),
                port: Set(port),
                enabled: Set(true),
                check_interval_secs: Set(req.check_interval_secs.map(|v| v as i64)),
                note: Set(req.note.clone()),
                last_checked_at: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            am.insert(self.db()).await?;
            ids.push(id);
        }
        let mut domains = Vec::with_capacity(ids.len());
        for id in &ids {
            if let Some(d) = self.get_domain_by_id(id).await? {
                domains.push(d);
            }
        }
        Ok(domains)
    }

    pub async fn get_domain_by_id(&self, id: &str) -> Result<Option<CertDomain>> {
        let model = DomainEntity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(model_to_domain))
    }

    pub async fn get_domain_by_name(&self, domain: &str) -> Result<Option<CertDomain>> {
        let model = DomainEntity::find()
            .filter(DomainCol::Domain.eq(domain))
            .one(self.db())
            .await?;
        Ok(model.map(model_to_domain))
    }

    pub async fn query_domains(
        &self,
        enabled: Option<bool>,
        search: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CertDomain>> {
        let mut q = DomainEntity::find();
        if let Some(en) = enabled {
            q = q.filter(DomainCol::Enabled.eq(en));
        }
        if let Some(s) = search {
            q = q.filter(DomainCol::Domain.contains(s));
        }
        let rows = q
            .order_by(DomainCol::CreatedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_domain).collect())
    }

    pub async fn count_domains(&self, enabled: Option<bool>, search: Option<&str>) -> Result<u64> {
        let mut q = DomainEntity::find();
        if let Some(en) = enabled {
            q = q.filter(DomainCol::Enabled.eq(en));
        }
        if let Some(s) = search {
            q = q.filter(DomainCol::Domain.contains(s));
        }
        Ok(q.count(self.db()).await?)
    }

    pub async fn update_domain(
        &self,
        id: &str,
        req: &UpdateDomainRequest,
    ) -> Result<Option<CertDomain>> {
        let model = DomainEntity::find_by_id(id).one(self.db()).await?;
        if let Some(m) = model {
            let now = Utc::now().fixed_offset();
            let mut am: cert_domain::ActiveModel = m.into();
            if let Some(port) = req.port {
                am.port = Set(port);
            }
            if let Some(enabled) = req.enabled {
                am.enabled = Set(enabled);
            }
            if let Some(interval) = req.check_interval_secs {
                am.check_interval_secs = Set(interval.map(|v| v as i64));
            }
            if let Some(ref note) = req.note {
                am.note = Set(Some(note.clone()));
            }
            am.updated_at = Set(now);
            let updated = am.update(self.db()).await?;
            Ok(Some(model_to_domain(updated)))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_domain(&self, id: &str) -> Result<bool> {
        let res = DomainEntity::delete_by_id(id).exec(self.db()).await?;
        Ok(res.rows_affected > 0)
    }

    pub async fn query_domains_due_for_check(
        &self,
        default_interval_secs: i64,
        limit: usize,
    ) -> Result<Vec<CertDomain>> {
        use sea_orm::ConnectionTrait;
        use sea_orm::Statement;
        let sql = format!(
            "SELECT id, domain, port, enabled, check_interval_secs, note, last_checked_at, created_at, updated_at
             FROM cert_domains
             WHERE enabled = 1
               AND (
                   last_checked_at IS NULL
                   OR (strftime('%s', 'now') - strftime('%s', last_checked_at)) >= COALESCE(check_interval_secs, {default})
               )
             ORDER BY last_checked_at ASC NULLS FIRST
             LIMIT {limit}",
            default = default_interval_secs,
            limit = limit,
        );
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.try_get("", "id")?;
            let domain: String = row.try_get("", "domain")?;
            let port: i32 = row.try_get("", "port")?;
            let enabled: bool = row.try_get("", "enabled")?;
            let check_interval_secs: Option<i64> = row.try_get("", "check_interval_secs")?;
            let note: Option<String> = row.try_get("", "note")?;
            let last_checked_at: Option<chrono::DateTime<chrono::FixedOffset>> =
                row.try_get("", "last_checked_at")?;
            let created_at: chrono::DateTime<chrono::FixedOffset> =
                row.try_get("", "created_at")?;
            let updated_at: chrono::DateTime<chrono::FixedOffset> =
                row.try_get("", "updated_at")?;
            result.push(CertDomain {
                id,
                domain,
                port,
                enabled,
                check_interval_secs: check_interval_secs.map(|v| v as u64),
                note,
                last_checked_at: last_checked_at.map(|t| t.with_timezone(&Utc)),
                created_at: created_at.with_timezone(&Utc),
                updated_at: updated_at.with_timezone(&Utc),
            });
        }
        Ok(result)
    }

    pub async fn update_last_checked_at(&self, domain_id: &str, ts: DateTime<Utc>) -> Result<()> {
        let model = DomainEntity::find_by_id(domain_id).one(self.db()).await?;
        if let Some(m) = model {
            let mut am: cert_domain::ActiveModel = m.into();
            am.last_checked_at = Set(Some(ts.fixed_offset()));
            am.updated_at = Set(Utc::now().fixed_offset());
            am.update(self.db()).await?;
        }
        Ok(())
    }

    // ---- cert_check_results CRUD ----

    pub async fn insert_check_result(&self, result: &CertCheckResult) -> Result<()> {
        let san_json = result
            .san_list
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let ip_json = result
            .resolved_ips
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let now = Utc::now().fixed_offset();
        let am = cert_check_result::ActiveModel {
            id: Set(result.id.clone()),
            domain_id: Set(result.domain_id.clone()),
            domain: Set(result.domain.clone()),
            is_valid: Set(result.is_valid),
            chain_valid: Set(result.chain_valid),
            not_before: Set(result.not_before.map(|t| t.fixed_offset())),
            not_after: Set(result.not_after.map(|t| t.fixed_offset())),
            days_until_expiry: Set(result.days_until_expiry.map(|v| v as i32)),
            issuer: Set(result.issuer.clone()),
            subject: Set(result.subject.clone()),
            san_list: Set(san_json),
            resolved_ips: Set(ip_json),
            error: Set(result.error.clone()),
            checked_at: Set(result.checked_at.fixed_offset()),
            created_at: Set(now),
            updated_at: Set(now),
        };
        am.insert(self.db()).await?;
        Ok(())
    }

    pub async fn query_latest_results(
        &self,
        filter: &CertStatusFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CertCheckResult>> {
        use sea_orm::{ConnectionTrait, Statement};
        let mut where_parts = vec!["1=1".to_string()];
        let params_sql = String::new();
        let mut bind_vals: Vec<String> = Vec::new();

        if let Some(ref s) = filter.domain_contains {
            bind_vals.push(format!("%{}%", s.replace('%', "\\%").replace('_', "\\_")));
            where_parts.push(format!("r.domain LIKE ${} ESCAPE '\\'", bind_vals.len()));
        }
        if let Some(v) = filter.is_valid {
            bind_vals.push(if v { "1".to_string() } else { "0".to_string() });
            where_parts.push(format!("r.is_valid = ${}", bind_vals.len()));
        }
        if let Some(v) = filter.days_until_expiry_lte {
            bind_vals.push(v.to_string());
            where_parts.push(format!("r.days_until_expiry <= ${}", bind_vals.len()));
        }

        let _ = params_sql; // consumed by format

        let where_clause = where_parts.join(" AND ");
        let sql = format!(
            "SELECT r.id, r.domain_id, r.domain, r.is_valid, r.chain_valid,
                    r.not_before, r.not_after, r.days_until_expiry,
                    r.issuer, r.subject, r.san_list, r.resolved_ips,
                    r.error, r.checked_at, r.created_at, r.updated_at
             FROM cert_check_results r
             INNER JOIN (
                 SELECT domain_id, MAX(checked_at) AS max_checked
                 FROM cert_check_results
                 GROUP BY domain_id
             ) latest ON r.domain_id = latest.domain_id AND r.checked_at = latest.max_checked
             INNER JOIN cert_domains d ON d.id = r.domain_id AND d.enabled = 1
             WHERE {where_clause}
             ORDER BY r.domain ASC
             LIMIT {limit} OFFSET {offset}"
        );

        let mut stmt = Statement::from_string(sea_orm::DatabaseBackend::Sqlite, sql);
        for v in &bind_vals {
            stmt = Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                stmt.sql
                    .replacen("$1", &format!("'{}'", v.replace('\'', "''")), 1),
            );
        }

        // Use raw query with manual binding for simplicity
        let raw_sql = build_raw_latest_sql(filter, limit, offset);
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                raw_sql,
            ))
            .await?;

        parse_check_result_rows(rows)
    }

    pub async fn count_latest_results(&self, filter: &CertStatusFilter) -> Result<u64> {
        use sea_orm::{ConnectionTrait, Statement};
        let raw_sql = build_raw_latest_count_sql(filter);
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                raw_sql,
            ))
            .await?;
        if let Some(row) = rows.into_iter().next() {
            let count: i64 = row.try_get("", "cnt")?;
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }

    pub async fn query_result_by_domain(&self, domain: &str) -> Result<Option<CertCheckResult>> {
        let rows = CheckEntity::find()
            .filter(CheckCol::Domain.eq(domain))
            .order_by(CheckCol::CheckedAt, Order::Desc)
            .limit(1)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().next().map(model_to_check_result))
    }

    pub async fn query_check_results_by_domain_id(
        &self,
        domain_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CertCheckResult>> {
        let rows = CheckEntity::find()
            .filter(CheckCol::DomainId.eq(domain_id))
            .order_by(CheckCol::CheckedAt, Order::Desc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_check_result).collect())
    }

    pub async fn count_check_results_by_domain_id(&self, domain_id: &str) -> Result<u64> {
        Ok(CheckEntity::find()
            .filter(CheckCol::DomainId.eq(domain_id))
            .count(self.db())
            .await?)
    }

    // ---- cert summary ----

    pub async fn cert_summary(&self) -> Result<CertHealthSummary> {
        use sea_orm::{ConnectionTrait, Statement};
        let total: u64 = DomainEntity::find()
            .filter(DomainCol::Enabled.eq(true))
            .count(self.db())
            .await?;

        let sql = "SELECT r.is_valid, r.days_until_expiry
             FROM cert_check_results r
             INNER JOIN (
                 SELECT domain_id, MAX(checked_at) AS max_checked
                 FROM cert_check_results
                 GROUP BY domain_id
             ) latest ON r.domain_id = latest.domain_id AND r.checked_at = latest.max_checked
             INNER JOIN cert_domains d ON d.id = r.domain_id AND d.enabled = 1";

        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql.to_string(),
            ))
            .await?;

        let mut valid: u64 = 0;
        let mut invalid: u64 = 0;
        let mut expiring_soon: u64 = 0;

        for row in rows {
            let is_valid: bool = row.try_get("", "is_valid")?;
            let days: Option<i32> = row.try_get("", "days_until_expiry")?;
            if is_valid {
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
            total_domains: total,
            valid,
            invalid,
            expiring_soon,
        })
    }

    pub async fn cert_domain_summary(&self) -> Result<CertDomainSummary> {
        use sea_orm::{ConnectionTrait, Statement};
        let sql = "SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END), 0) AS enabled_count,
                COALESCE(SUM(CASE WHEN enabled = 0 THEN 1 ELSE 0 END), 0) AS disabled_count
             FROM cert_domains";
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql.to_string(),
            ))
            .await?;
        if let Some(row) = rows.into_iter().next() {
            let total: i64 = row.try_get("", "total")?;
            let enabled: i64 = row.try_get("", "enabled_count")?;
            let disabled: i64 = row.try_get("", "disabled_count")?;
            Ok(CertDomainSummary {
                total: total as u64,
                enabled: enabled as u64,
                disabled: disabled as u64,
            })
        } else {
            Ok(CertDomainSummary {
                total: 0,
                enabled: 0,
                disabled: 0,
            })
        }
    }

    pub async fn cert_status_summary(
        &self,
        filter: &CertStatusFilter,
    ) -> Result<CertStatusSummary> {
        use sea_orm::{ConnectionTrait, Statement};
        let raw_sql = build_status_summary_sql(filter);
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                raw_sql,
            ))
            .await?;
        if let Some(row) = rows.into_iter().next() {
            let total: i64 = row.try_get("", "total")?;
            let healthy: i64 = row.try_get("", "healthy_count")?;
            let failed: i64 = row.try_get("", "failed_count")?;
            let expiring_soon: i64 = row.try_get("", "expiring_soon_count")?;
            Ok(CertStatusSummary {
                total: total as u64,
                healthy: healthy as u64,
                failed: failed as u64,
                expiring_soon: expiring_soon as u64,
            })
        } else {
            Ok(CertStatusSummary::default())
        }
    }

    // ---- certificate_details CRUD ----

    pub async fn upsert_certificate_details(&self, details: &CertificateDetails) -> Result<()> {
        let existing = DetailEntity::find()
            .filter(DetailCol::Domain.eq(details.domain.as_str()))
            .one(self.db())
            .await?;

        let ip_json = serde_json::to_string(&details.ip_addresses)?;
        let san_json = serde_json::to_string(&details.subject_alt_names)?;
        let key_usage_json = details
            .key_usage
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let eku_json = details
            .extended_key_usage
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let ocsp_json = details
            .ocsp_urls
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let crl_json = details
            .crl_urls
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let ca_issuer_json = details
            .ca_issuer_urls
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let now = Utc::now().fixed_offset();

        if let Some(m) = existing {
            let mut am: certificate_detail::ActiveModel = m.into();
            am.not_before = Set(details.not_before.fixed_offset());
            am.not_after = Set(details.not_after.fixed_offset());
            am.ip_addresses = Set(ip_json);
            am.issuer_cn = Set(details.issuer_cn.clone());
            am.issuer_o = Set(details.issuer_o.clone());
            am.issuer_ou = Set(details.issuer_ou.clone());
            am.issuer_c = Set(details.issuer_c.clone());
            am.subject_alt_names = Set(Some(san_json));
            am.chain_valid = Set(details.chain_valid);
            am.chain_error = Set(details.chain_error.clone());
            am.last_checked = Set(details.last_checked.fixed_offset());
            am.updated_at = Set(now);
            am.serial_number = Set(details.serial_number.clone());
            am.fingerprint_sha256 = Set(details.fingerprint_sha256.clone());
            am.version = Set(details.version);
            am.signature_algorithm = Set(details.signature_algorithm.clone());
            am.public_key_algorithm = Set(details.public_key_algorithm.clone());
            am.public_key_bits = Set(details.public_key_bits);
            am.subject_cn = Set(details.subject_cn.clone());
            am.subject_o = Set(details.subject_o.clone());
            am.key_usage = Set(key_usage_json);
            am.extended_key_usage = Set(eku_json);
            am.is_ca = Set(details.is_ca);
            am.is_wildcard = Set(details.is_wildcard);
            am.ocsp_urls = Set(ocsp_json);
            am.crl_urls = Set(crl_json);
            am.ca_issuer_urls = Set(ca_issuer_json);
            am.sct_count = Set(details.sct_count);
            am.tls_version = Set(details.tls_version.clone());
            am.cipher_suite = Set(details.cipher_suite.clone());
            am.chain_depth = Set(details.chain_depth);
            am.update(self.db()).await?;
        } else {
            let id = oxmon_common::id::next_id();
            let am = certificate_detail::ActiveModel {
                id: Set(id),
                domain: Set(details.domain.clone()),
                not_before: Set(details.not_before.fixed_offset()),
                not_after: Set(details.not_after.fixed_offset()),
                ip_addresses: Set(ip_json),
                issuer_cn: Set(details.issuer_cn.clone()),
                issuer_o: Set(details.issuer_o.clone()),
                issuer_ou: Set(details.issuer_ou.clone()),
                issuer_c: Set(details.issuer_c.clone()),
                subject_alt_names: Set(Some(san_json)),
                chain_valid: Set(details.chain_valid),
                chain_error: Set(details.chain_error.clone()),
                last_checked: Set(details.last_checked.fixed_offset()),
                created_at: Set(now),
                updated_at: Set(now),
                serial_number: Set(details.serial_number.clone()),
                fingerprint_sha256: Set(details.fingerprint_sha256.clone()),
                version: Set(details.version),
                signature_algorithm: Set(details.signature_algorithm.clone()),
                public_key_algorithm: Set(details.public_key_algorithm.clone()),
                public_key_bits: Set(details.public_key_bits),
                subject_cn: Set(details.subject_cn.clone()),
                subject_o: Set(details.subject_o.clone()),
                key_usage: Set(key_usage_json),
                extended_key_usage: Set(eku_json),
                is_ca: Set(details.is_ca),
                is_wildcard: Set(details.is_wildcard),
                ocsp_urls: Set(ocsp_json),
                crl_urls: Set(crl_json),
                ca_issuer_urls: Set(ca_issuer_json),
                sct_count: Set(details.sct_count),
                tls_version: Set(details.tls_version.clone()),
                cipher_suite: Set(details.cipher_suite.clone()),
                chain_depth: Set(details.chain_depth),
            };
            am.insert(self.db()).await?;
        }

        // 自愈：证书详情存在但监控域名缺失时，自动补齐
        let domain_exists = DomainEntity::find()
            .filter(DomainCol::Domain.eq(details.domain.as_str()))
            .count(self.db())
            .await?
            > 0;
        if !domain_exists {
            let id = oxmon_common::id::next_id();
            let am = cert_domain::ActiveModel {
                id: Set(id),
                domain: Set(details.domain.clone()),
                port: Set(443),
                enabled: Set(true),
                check_interval_secs: Set(None),
                note: Set(None),
                last_checked_at: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            let _ = am.insert(self.db()).await; // ignore unique conflict
        }

        Ok(())
    }

    pub async fn get_certificate_details(
        &self,
        domain: &str,
    ) -> Result<Option<CertificateDetails>> {
        let model = DetailEntity::find()
            .filter(DetailCol::Domain.eq(domain))
            .one(self.db())
            .await?;
        Ok(model.map(model_to_details))
    }

    pub async fn get_certificate_details_by_id(
        &self,
        id: &str,
    ) -> Result<Option<CertificateDetails>> {
        let model = DetailEntity::find_by_id(id).one(self.db()).await?;
        Ok(model.map(model_to_details))
    }

    pub async fn list_certificate_details(
        &self,
        filter: &CertificateDetailsFilter,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CertificateDetails>> {
        let mut q = DetailEntity::find();
        if let Some(ref s) = filter.domain_contains {
            q = q.filter(DetailCol::Domain.contains(s.as_str()));
        }
        if let Some(ts) = filter.not_after_lte {
            let dt = chrono::DateTime::<Utc>::from_timestamp(ts, 0)
                .unwrap_or_default()
                .fixed_offset();
            q = q.filter(DetailCol::NotAfter.lte(dt));
        }
        let rows = q
            .order_by(DetailCol::Domain, Order::Asc)
            .limit(limit as u64)
            .offset(offset as u64)
            .all(self.db())
            .await?;
        Ok(rows.into_iter().map(model_to_details).collect())
    }

    pub async fn count_certificate_details(
        &self,
        filter: &CertificateDetailsFilter,
    ) -> Result<u64> {
        let mut q = DetailEntity::find();
        if let Some(ref s) = filter.domain_contains {
            q = q.filter(DetailCol::Domain.contains(s.as_str()));
        }
        if let Some(ts) = filter.not_after_lte {
            let dt = chrono::DateTime::<Utc>::from_timestamp(ts, 0)
                .unwrap_or_default()
                .fixed_offset();
            q = q.filter(DetailCol::NotAfter.lte(dt));
        }
        Ok(q.count(self.db()).await?)
    }

    // ---- missing domain sync ----

    pub async fn sync_missing_monitored_domains_from_certificate_details(&self) -> Result<u64> {
        use sea_orm::{ConnectionTrait, Statement};
        let sql = "SELECT DISTINCT c.domain
             FROM certificate_details c
             LEFT JOIN cert_domains d ON d.domain = c.domain
             WHERE d.domain IS NULL";
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql.to_string(),
            ))
            .await?;
        let now = Utc::now().fixed_offset();
        let mut inserted = 0u64;
        for row in rows {
            let domain: String = row.try_get("", "domain")?;
            let id = oxmon_common::id::next_id();
            let am = cert_domain::ActiveModel {
                id: Set(id),
                domain: Set(domain),
                port: Set(443),
                enabled: Set(true),
                check_interval_secs: Set(None),
                note: Set(None),
                last_checked_at: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            if am.insert(self.db()).await.is_ok() {
                inserted += 1;
            }
        }
        Ok(inserted)
    }

    pub async fn count_missing_monitored_domains_from_certificate_details(&self) -> Result<u64> {
        use sea_orm::{ConnectionTrait, Statement};
        let sql = "SELECT COUNT(DISTINCT c.domain) AS cnt
             FROM certificate_details c
             LEFT JOIN cert_domains d ON d.domain = c.domain
             WHERE d.domain IS NULL";
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql.to_string(),
            ))
            .await?;
        if let Some(row) = rows.into_iter().next() {
            let cnt: i64 = row.try_get("", "cnt")?;
            Ok(cnt as u64)
        } else {
            Ok(0)
        }
    }

    pub async fn preview_missing_monitored_domains_from_certificate_details(
        &self,
        limit: usize,
    ) -> Result<Vec<String>> {
        use sea_orm::{ConnectionTrait, Statement};
        let sql = format!(
            "SELECT DISTINCT c.domain
             FROM certificate_details c
             LEFT JOIN cert_domains d ON d.domain = c.domain
             WHERE d.domain IS NULL
             ORDER BY c.domain ASC
             LIMIT {limit}"
        );
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql,
            ))
            .await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let domain: String = row.try_get("", "domain")?;
            result.push(domain);
        }
        Ok(result)
    }

    pub async fn sync_missing_monitored_domains_from_certificate_details_with_preview(
        &self,
        preview_limit: usize,
    ) -> Result<(u64, Vec<String>)> {
        use sea_orm::{ConnectionTrait, Statement};
        let sql = "SELECT DISTINCT c.domain
             FROM certificate_details c
             LEFT JOIN cert_domains d ON d.domain = c.domain
             WHERE d.domain IS NULL
             ORDER BY c.domain ASC";
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                sql.to_string(),
            ))
            .await?;

        let mut missing_domains = Vec::new();
        for row in rows {
            let domain: String = row.try_get("", "domain")?;
            missing_domains.push(domain);
        }

        if missing_domains.is_empty() {
            return Ok((0, Vec::new()));
        }

        let preview: Vec<String> = missing_domains
            .iter()
            .take(preview_limit)
            .cloned()
            .collect();

        let now = Utc::now().fixed_offset();
        let mut inserted = 0u64;
        for domain in &missing_domains {
            let id = oxmon_common::id::next_id();
            let am = cert_domain::ActiveModel {
                id: Set(id),
                domain: Set(domain.clone()),
                port: Set(443),
                enabled: Set(true),
                check_interval_secs: Set(None),
                note: Set(None),
                last_checked_at: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            };
            if am.insert(self.db()).await.is_ok() {
                inserted += 1;
            }
        }
        Ok((inserted, preview))
    }
}

fn escape_sql_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn build_status_summary_sql(filter: &CertStatusFilter) -> String {
    let mut sql = String::from(
        "SELECT
            COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN r.is_valid = 1 AND r.chain_valid = 1 THEN 1 ELSE 0 END), 0) AS healthy_count,
            COALESCE(SUM(CASE WHEN NOT (r.is_valid = 1 AND r.chain_valid = 1) THEN 1 ELSE 0 END), 0) AS failed_count,
            COALESCE(SUM(CASE WHEN r.days_until_expiry >= 0 AND r.days_until_expiry <= 30 THEN 1 ELSE 0 END), 0) AS expiring_soon_count
         FROM cert_check_results r
         INNER JOIN (
             SELECT domain_id, MAX(checked_at) AS max_checked
             FROM cert_check_results
             GROUP BY domain_id
         ) latest ON r.domain_id = latest.domain_id AND r.checked_at = latest.max_checked
         INNER JOIN cert_domains d ON d.id = r.domain_id AND d.enabled = 1
         WHERE 1=1",
    );
    if let Some(ref s) = filter.domain_contains {
        let escaped = escape_sql_like(s);
        sql.push_str(&format!(" AND r.domain LIKE '%{escaped}%' ESCAPE '\\'"));
    }
    if let Some(v) = filter.is_valid {
        sql.push_str(&format!(" AND r.is_valid = {}", if v { 1 } else { 0 }));
    }
    if let Some(v) = filter.days_until_expiry_lte {
        sql.push_str(&format!(" AND r.days_until_expiry <= {v}"));
    }
    sql
}

fn build_raw_latest_sql(filter: &CertStatusFilter, limit: usize, offset: usize) -> String {
    let mut sql = String::from(
        "SELECT r.id, r.domain_id, r.domain, r.is_valid, r.chain_valid,
                r.not_before, r.not_after, r.days_until_expiry,
                r.issuer, r.subject, r.san_list, r.resolved_ips,
                r.error, r.checked_at, r.created_at, r.updated_at
         FROM cert_check_results r
         INNER JOIN (
             SELECT domain_id, MAX(checked_at) AS max_checked
             FROM cert_check_results
             GROUP BY domain_id
         ) latest ON r.domain_id = latest.domain_id AND r.checked_at = latest.max_checked
         INNER JOIN cert_domains d ON d.id = r.domain_id AND d.enabled = 1
         WHERE 1=1",
    );
    if let Some(ref s) = filter.domain_contains {
        let escaped = escape_sql_like(s);
        sql.push_str(&format!(" AND r.domain LIKE '%{escaped}%' ESCAPE '\\'"));
    }
    if let Some(v) = filter.is_valid {
        sql.push_str(&format!(" AND r.is_valid = {}", if v { 1 } else { 0 }));
    }
    if let Some(v) = filter.days_until_expiry_lte {
        sql.push_str(&format!(" AND r.days_until_expiry <= {v}"));
    }
    sql.push_str(&format!(
        " ORDER BY r.domain ASC LIMIT {limit} OFFSET {offset}"
    ));
    sql
}

fn build_raw_latest_count_sql(filter: &CertStatusFilter) -> String {
    let mut sql = String::from(
        "SELECT COUNT(*) AS cnt
         FROM cert_check_results r
         INNER JOIN (
             SELECT domain_id, MAX(checked_at) AS max_checked
             FROM cert_check_results
             GROUP BY domain_id
         ) latest ON r.domain_id = latest.domain_id AND r.checked_at = latest.max_checked
         INNER JOIN cert_domains d ON d.id = r.domain_id AND d.enabled = 1
         WHERE 1=1",
    );
    if let Some(ref s) = filter.domain_contains {
        let escaped = escape_sql_like(s);
        sql.push_str(&format!(" AND r.domain LIKE '%{escaped}%' ESCAPE '\\'"));
    }
    if let Some(v) = filter.is_valid {
        sql.push_str(&format!(" AND r.is_valid = {}", if v { 1 } else { 0 }));
    }
    if let Some(v) = filter.days_until_expiry_lte {
        sql.push_str(&format!(" AND r.days_until_expiry <= {v}"));
    }
    sql
}

fn parse_check_result_rows(rows: Vec<sea_orm::QueryResult>) -> Result<Vec<CertCheckResult>> {
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("", "id")?;
        let domain_id: String = row.try_get("", "domain_id")?;
        let domain: String = row.try_get("", "domain")?;
        let is_valid: bool = row.try_get("", "is_valid")?;
        let chain_valid: bool = row.try_get("", "chain_valid")?;
        let not_before: Option<chrono::DateTime<chrono::FixedOffset>> =
            row.try_get("", "not_before")?;
        let not_after: Option<chrono::DateTime<chrono::FixedOffset>> =
            row.try_get("", "not_after")?;
        let days_until_expiry: Option<i32> = row.try_get("", "days_until_expiry")?;
        let issuer: Option<String> = row.try_get("", "issuer")?;
        let subject: Option<String> = row.try_get("", "subject")?;
        let san_list_str: Option<String> = row.try_get("", "san_list")?;
        let resolved_ips_str: Option<String> = row.try_get("", "resolved_ips")?;
        let error: Option<String> = row.try_get("", "error")?;
        let checked_at: chrono::DateTime<chrono::FixedOffset> = row.try_get("", "checked_at")?;
        let created_at: chrono::DateTime<chrono::FixedOffset> = row.try_get("", "created_at")?;
        let updated_at: chrono::DateTime<chrono::FixedOffset> = row.try_get("", "updated_at")?;

        let san_list: Option<Vec<String>> = san_list_str
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        let resolved_ips: Option<Vec<String>> = resolved_ips_str
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());

        result.push(CertCheckResult {
            id,
            domain_id,
            domain,
            is_valid,
            chain_valid,
            not_before: not_before.map(|t| t.with_timezone(&Utc)),
            not_after: not_after.map(|t| t.with_timezone(&Utc)),
            days_until_expiry: days_until_expiry.map(|v| v as i64),
            issuer,
            subject,
            san_list,
            resolved_ips,
            error,
            checked_at: checked_at.with_timezone(&Utc),
            created_at: created_at.with_timezone(&Utc),
            updated_at: updated_at.with_timezone(&Utc),
        });
    }
    Ok(result)
}
