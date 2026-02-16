use chrono::Utc;
use oxmon_storage::cert_store::{AlertRuleRow, CertStore};

/// Default alert rule definitions for first-time startup.
struct RuleDef {
    name: &'static str,
    rule_type: &'static str,
    metric: &'static str,
    agent_pattern: &'static str,
    severity: &'static str,
    config_json: &'static str,
    silence_secs: u64,
}

const DEFAULT_RULES: &[RuleDef] = &[
    // ---- CPU ----
    RuleDef {
        name: "CPU 使用率严重告警",
        rule_type: "threshold",
        metric: "cpu.usage",
        agent_pattern: "*",
        severity: "critical",
        config_json: r#"{"operator":"greater_than","value":90.0,"duration_secs":60}"#,
        silence_secs: 300,
    },
    RuleDef {
        name: "CPU 使用率警告",
        rule_type: "threshold",
        metric: "cpu.usage",
        agent_pattern: "*",
        severity: "warning",
        config_json: r#"{"operator":"greater_than","value":80.0,"duration_secs":120}"#,
        silence_secs: 300,
    },
    // ---- Memory ----
    RuleDef {
        name: "内存使用率严重告警",
        rule_type: "threshold",
        metric: "memory.used_percent",
        agent_pattern: "*",
        severity: "critical",
        config_json: r#"{"operator":"greater_than","value":95.0,"duration_secs":60}"#,
        silence_secs: 300,
    },
    RuleDef {
        name: "内存使用率警告",
        rule_type: "threshold",
        metric: "memory.used_percent",
        agent_pattern: "*",
        severity: "warning",
        config_json: r#"{"operator":"greater_than","value":85.0,"duration_secs":120}"#,
        silence_secs: 300,
    },
    RuleDef {
        name: "内存使用率突增",
        rule_type: "rate_of_change",
        metric: "memory.used_percent",
        agent_pattern: "*",
        severity: "warning",
        config_json: r#"{"rate_threshold":20.0,"window_secs":300}"#,
        silence_secs: 600,
    },
    // ---- Disk ----
    RuleDef {
        name: "磁盘使用率严重告警",
        rule_type: "threshold",
        metric: "disk.used_percent",
        agent_pattern: "*",
        severity: "critical",
        config_json: r#"{"operator":"greater_than","value":95.0,"duration_secs":0}"#,
        silence_secs: 600,
    },
    RuleDef {
        name: "磁盘使用率警告",
        rule_type: "threshold",
        metric: "disk.used_percent",
        agent_pattern: "*",
        severity: "warning",
        config_json: r#"{"operator":"greater_than","value":85.0,"duration_secs":0}"#,
        silence_secs: 600,
    },
    RuleDef {
        name: "磁盘空间趋势预测",
        rule_type: "trend_prediction",
        metric: "disk.used_percent",
        agent_pattern: "*",
        severity: "warning",
        config_json: r#"{"predict_threshold":95.0,"horizon_secs":86400,"min_data_points":3}"#,
        silence_secs: 3600,
    },
    // ---- Certificate ----
    RuleDef {
        name: "SSL 证书即将过期",
        rule_type: "cert_expiration",
        metric: "cert.expiration",
        agent_pattern: "*",
        severity: "warning",
        config_json: r#"{"warning_days":30,"critical_days":7}"#,
        silence_secs: 86400,
    },
];

/// Initialize default alert rules if the database has no rules yet.
///
/// This runs after TOML migration so that TOML-migrated rules take priority.
/// Only seeds when `count_alert_rules() == 0`.
pub fn init_default_rules(cert_store: &CertStore) -> anyhow::Result<usize> {
    let count = cert_store.count_alert_rules()?;
    if count > 0 {
        tracing::debug!(
            existing = count,
            "Alert rules already exist, skipping seed initialization"
        );
        return Ok(0);
    }

    let now = Utc::now();
    let mut inserted = 0usize;

    for def in DEFAULT_RULES {
        let row = AlertRuleRow {
            id: oxmon_common::id::next_id(),
            name: def.name.to_string(),
            rule_type: def.rule_type.to_string(),
            metric: def.metric.to_string(),
            agent_pattern: def.agent_pattern.to_string(),
            severity: def.severity.to_string(),
            enabled: true,
            config_json: def.config_json.to_string(),
            silence_secs: def.silence_secs,
            source: "seed".to_string(),
            created_at: now,
            updated_at: now,
        };
        match cert_store.insert_alert_rule(&row) {
            Ok(_) => {
                inserted += 1;
                tracing::info!(name = %def.name, rule_type = %def.rule_type, "Seeded alert rule");
            }
            Err(e) => {
                tracing::warn!(name = %def.name, error = %e, "Failed to seed alert rule");
            }
        }
    }

    tracing::info!(
        inserted,
        total = DEFAULT_RULES.len(),
        "Default alert rules initialized"
    );
    Ok(inserted)
}
