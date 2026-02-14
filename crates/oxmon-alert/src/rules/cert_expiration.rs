use crate::AlertRule;
use chrono::{DateTime, Utc};
use oxmon_common::types::{AlertEvent, MetricDataPoint, Severity};

/// 证书过期告警规则
///
/// 当 `certificate.days_until_expiry` 指标低于配置的阈值时触发告警。
/// 支持两级阈值：warning（默认 30 天）和 critical（默认 7 天）。
pub struct CertExpirationRule {
    pub id: String,
    pub name: String,
    pub metric: String,
    pub agent_pattern: String,
    /// 警告阈值（天数），低于此值触发 Warning 告警
    pub warning_days: i64,
    /// 严重阈值（天数），低于此值触发 Critical 告警
    pub critical_days: i64,
    pub silence_secs: u64,
}

impl CertExpirationRule {
    pub fn new(
        id: String,
        name: String,
        warning_days: i64,
        critical_days: i64,
        silence_secs: u64,
    ) -> Self {
        Self {
            id,
            name,
            metric: "certificate.days_until_expiry".to_string(),
            agent_pattern: "cert-checker".to_string(),
            warning_days,
            critical_days,
            silence_secs,
        }
    }

    fn determine_severity(&self, days: f64) -> Option<Severity> {
        if days <= self.critical_days as f64 {
            Some(Severity::Critical)
        } else if days <= self.warning_days as f64 {
            Some(Severity::Warning)
        } else {
            None
        }
    }
}

impl AlertRule for CertExpirationRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn metric(&self) -> &str {
        &self.metric
    }

    fn agent_pattern(&self) -> &str {
        &self.agent_pattern
    }

    fn severity(&self) -> Severity {
        // 返回最高可能严重级别，实际严重级别在 evaluate 中根据值动态确定
        Severity::Critical
    }

    fn silence_secs(&self) -> u64 {
        self.silence_secs
    }

    fn evaluate(&self, window: &[MetricDataPoint], now: DateTime<Utc>) -> Option<AlertEvent> {
        // 获取最新的数据点
        let latest = window.last()?;

        let days = latest.value;
        let severity = self.determine_severity(days)?;

        let domain = latest
            .labels
            .get("domain")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let message = if days <= 0.0 {
            format!("证书已过期: {} (已过期 {:.0} 天)", domain, -days)
        } else if severity == Severity::Critical {
            format!(
                "证书即将过期: {} (剩余 {:.0} 天，低于 {} 天严重阈值)",
                domain, days, self.critical_days
            )
        } else {
            format!(
                "证书即将过期: {} (剩余 {:.0} 天，低于 {} 天警告阈值)",
                domain, days, self.warning_days
            )
        };

        Some(AlertEvent {
            id: oxmon_common::id::next_id(),
            rule_id: self.id.clone(),
            rule_name: self.name.clone(),
            agent_id: latest.agent_id.clone(),
            metric_name: self.metric.clone(),
            severity,
            message,
            value: days,
            threshold: if severity == Severity::Critical {
                self.critical_days as f64
            } else {
                self.warning_days as f64
            },
            timestamp: now,
            predicted_breach: None,
            status: 1,
            labels: latest.labels.clone(),
            first_triggered_at: None,
            created_at: now,
            updated_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_rule() -> CertExpirationRule {
        CertExpirationRule::new(
            "cert-expiry".to_string(),
            "证书过期检查".to_string(),
            30,
            7,
            3600,
        )
    }

    fn make_dp(days: f64, domain: &str) -> MetricDataPoint {
        let mut labels = HashMap::new();
        labels.insert("domain".to_string(), domain.to_string());
        let ts = Utc::now();
        MetricDataPoint {
            id: oxmon_common::id::next_id(),
            timestamp: ts,
            agent_id: "cert-checker".to_string(),
            metric_name: "certificate.days_until_expiry".to_string(),
            value: days,
            labels,
            created_at: ts,
            updated_at: ts,
        }
    }

    #[test]
    fn test_no_alert_when_days_sufficient() {
        oxmon_common::id::init(1, 1);
        let rule = make_rule();
        let dp = make_dp(90.0, "example.com");
        let result = rule.evaluate(&[dp], Utc::now());
        assert!(result.is_none());
    }

    #[test]
    fn test_warning_alert() {
        oxmon_common::id::init(1, 1);
        let rule = make_rule();
        let dp = make_dp(20.0, "example.com");
        let result = rule.evaluate(&[dp], Utc::now());
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.severity, Severity::Warning);
        assert!(event.message.contains("example.com"));
        assert!(event.message.contains("20"));
    }

    #[test]
    fn test_critical_alert() {
        oxmon_common::id::init(1, 1);
        let rule = make_rule();
        let dp = make_dp(5.0, "example.com");
        let result = rule.evaluate(&[dp], Utc::now());
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.severity, Severity::Critical);
    }

    #[test]
    fn test_expired_cert() {
        oxmon_common::id::init(1, 1);
        let rule = make_rule();
        let dp = make_dp(-3.0, "expired.com");
        let result = rule.evaluate(&[dp], Utc::now());
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.severity, Severity::Critical);
        assert!(event.message.contains("已过期"));
    }

    #[test]
    fn test_boundary_warning() {
        oxmon_common::id::init(1, 1);
        let rule = make_rule();
        let dp = make_dp(30.0, "example.com");
        let result = rule.evaluate(&[dp], Utc::now());
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, Severity::Warning);
    }

    #[test]
    fn test_boundary_critical() {
        oxmon_common::id::init(1, 1);
        let rule = make_rule();
        let dp = make_dp(7.0, "example.com");
        let result = rule.evaluate(&[dp], Utc::now());
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, Severity::Critical);
    }
}
