use anyhow::Result;
use oxmon_alert::rules::cert_expiration::CertExpirationRule;
use oxmon_alert::rules::cloud_scale::CloudScaleRecommendationRule;
use oxmon_alert::rules::rate_of_change::RateOfChangeRule;
use oxmon_alert::rules::threshold::{CompareOp, ThresholdRule};
use oxmon_alert::rules::trend_prediction::TrendPredictionRule;
use oxmon_alert::AlertRule;
use oxmon_common::types::Severity;
use oxmon_storage::cert_store::{AlertRuleRow, CertStore};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use oxmon_alert::engine::AlertEngine;

// ---- Per-rule-type config JSON schemas ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub operator: String,
    pub value: f64,
    #[serde(default)]
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateOfChangeConfig {
    pub rate_threshold: f64,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

fn default_window_secs() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPredictionConfig {
    pub predict_threshold: f64,
    #[serde(default = "default_horizon_secs")]
    pub horizon_secs: u64,
    #[serde(default = "default_min_data_points")]
    pub min_data_points: usize,
}

fn default_horizon_secs() -> u64 {
    86400
}

fn default_min_data_points() -> usize {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertExpirationConfig {
    #[serde(default = "default_warning_days")]
    pub warning_days: i64,
    #[serde(default = "default_critical_days")]
    pub critical_days: i64,
}

fn default_warning_days() -> i64 {
    30
}

fn default_critical_days() -> i64 {
    7
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudScaleConfig {
    pub high_threshold: f64,
    pub low_threshold: f64,
    #[serde(default = "default_cloud_scale_duration_secs")]
    pub duration_secs: u64,
}

fn default_cloud_scale_duration_secs() -> u64 {
    300
}

// ---- DB row -> AlertRule trait object ----

/// Convert a single `AlertRuleRow` into a `Box<dyn AlertRule>`.
pub fn build_rule_from_row(row: &AlertRuleRow) -> Result<Box<dyn AlertRule>> {
    let severity: Severity = row.severity.parse().unwrap_or(Severity::Info);
    match row.rule_type.as_str() {
        "threshold" => {
            let cfg: ThresholdConfig = serde_json::from_str(&row.config_json)
                .map_err(|e| anyhow::anyhow!("invalid threshold config: {e}"))?;
            let op: CompareOp = cfg
                .operator
                .parse()
                .map_err(|e: String| anyhow::anyhow!("{e}"))?;
            Ok(Box::new(ThresholdRule {
                id: row.id.clone(),
                name: row.name.clone(),
                metric: row.metric.clone(),
                agent_pattern: row.agent_pattern.clone(),
                severity,
                operator: op,
                value: cfg.value,
                duration_secs: cfg.duration_secs,
                silence_secs: row.silence_secs,
            }))
        }
        "rate_of_change" => {
            let cfg: RateOfChangeConfig = serde_json::from_str(&row.config_json)
                .map_err(|e| anyhow::anyhow!("invalid rate_of_change config: {e}"))?;
            Ok(Box::new(RateOfChangeRule {
                id: row.id.clone(),
                name: row.name.clone(),
                metric: row.metric.clone(),
                agent_pattern: row.agent_pattern.clone(),
                severity,
                rate_threshold: cfg.rate_threshold,
                window_secs: cfg.window_secs,
                silence_secs: row.silence_secs,
            }))
        }
        "trend_prediction" => {
            let cfg: TrendPredictionConfig = serde_json::from_str(&row.config_json)
                .map_err(|e| anyhow::anyhow!("invalid trend_prediction config: {e}"))?;
            Ok(Box::new(TrendPredictionRule {
                id: row.id.clone(),
                name: row.name.clone(),
                metric: row.metric.clone(),
                agent_pattern: row.agent_pattern.clone(),
                severity,
                predict_threshold: cfg.predict_threshold,
                horizon_secs: cfg.horizon_secs,
                min_data_points: cfg.min_data_points,
                silence_secs: row.silence_secs,
            }))
        }
        "cert_expiration" => {
            let cfg: CertExpirationConfig =
                serde_json::from_str(&row.config_json).unwrap_or(CertExpirationConfig {
                    warning_days: 30,
                    critical_days: 7,
                });
            Ok(Box::new(CertExpirationRule::new(
                row.id.clone(),
                row.name.clone(),
                cfg.warning_days,
                cfg.critical_days,
                row.silence_secs,
            )))
        }
        "cloud_scale" => {
            let cfg: CloudScaleConfig = serde_json::from_str(&row.config_json)
                .map_err(|e| anyhow::anyhow!("invalid cloud_scale config: {e}"))?;
            Ok(Box::new(CloudScaleRecommendationRule {
                id: row.id.clone(),
                name: row.name.clone(),
                metric: row.metric.clone(),
                agent_pattern: row.agent_pattern.clone(),
                severity,
                high_threshold: cfg.high_threshold,
                low_threshold: cfg.low_threshold,
                duration_secs: cfg.duration_secs,
                silence_secs: row.silence_secs,
            }))
        }
        other => Err(anyhow::anyhow!("unknown rule type: {other}")),
    }
}

/// Convert multiple rows into trait objects, skipping invalid ones with warnings.
pub fn build_rules_from_rows(rows: &[AlertRuleRow]) -> Vec<Box<dyn AlertRule>> {
    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        match build_rule_from_row(row) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                tracing::warn!(
                    rule_id = %row.id,
                    rule_name = %row.name,
                    rule_type = %row.rule_type,
                    error = %e,
                    "Skipping invalid alert rule"
                );
            }
        }
    }
    rules
}

// ---- Engine reload ----

/// Reload alert engine rules from database. Returns the number of loaded rules.
pub fn reload_alert_engine(
    cert_store: &CertStore,
    alert_engine: &Mutex<AlertEngine>,
) -> Result<usize> {
    let rows = cert_store.list_enabled_alert_rules()?;
    let rules = build_rules_from_rows(&rows);
    let count = rules.len();

    let mut engine = alert_engine
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    engine.replace_rules(rules);

    tracing::info!(rule_count = count, "Alert engine reloaded from DB");
    Ok(count)
}
