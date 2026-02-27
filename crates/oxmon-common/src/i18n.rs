//! Lightweight i18n translation registry.
//!
//! Provides a centralized, static translation map keyed by `(locale, message_key)`.
//! Supported locales: `zh-CN`, `en`. No external i18n framework dependency.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Default locale when none is configured.
pub const DEFAULT_LOCALE: &str = "zh-CN";

/// Supported locales.
pub const SUPPORTED_LOCALES: &[&str] = &["zh-CN", "en"];

/// Central translation registry.
pub struct Translations {
    map: HashMap<(&'static str, &'static str), &'static str>,
}

impl Translations {
    /// Get a translated string for the given locale and key.
    /// Falls back to `en` if the locale is not found, then to the provided default.
    pub fn get<'a>(&self, locale: &str, key: &str, default: &'a str) -> &'a str {
        // Dereference to extract &'static str (which outlives any 'a)
        // from the &&'static str returned by HashMap::get
        if let Some(&val) = self.map.get(&(locale, key)) {
            return val;
        }
        if locale != "en" {
            if let Some(&val) = self.map.get(&("en", key)) {
                return val;
            }
        }
        default
    }

    /// Get a translated template string for formatting.
    /// Returns `None` if no translation is found for any locale.
    pub fn get_template(&self, locale: &str, key: &str) -> Option<&'static str> {
        self.map
            .get(&(locale, key))
            .or_else(|| {
                if locale != "en" {
                    self.map.get(&("en", key))
                } else {
                    None
                }
            })
            .copied()
    }
}

/// Global translation singleton.
pub static TRANSLATIONS: LazyLock<Translations> = LazyLock::new(|| {
    let mut map = HashMap::new();

    // Helper macro to reduce boilerplate
    macro_rules! t {
        ($locale:expr, $key:expr, $val:expr) => {
            map.insert(($locale, $key), $val);
        };
    }

    // ---- Alert messages ----

    // Threshold rule
    t!(
        "en",
        "alert.threshold",
        "{metric}{labels} has been {op} {threshold:.1} for the configured duration on {agent}"
    );
    t!(
        "zh-CN",
        "alert.threshold",
        "{metric}{labels} 在 {agent} 上持续{op} {threshold:.1}"
    );

    // Rate of change rule
    t!(
        "en",
        "alert.rate_of_change",
        "{metric}{labels} changed by {rate:.1}% (threshold: {rate_threshold:.1}%) on {agent}"
    );
    t!(
        "zh-CN",
        "alert.rate_of_change",
        "{metric}{labels} 在 {agent} 上变化了 {rate:.1}%（阈值: {rate_threshold:.1}%）"
    );

    // Trend prediction rule
    t!("en", "alert.trend_prediction", "{metric}{labels} predicted to reach threshold {threshold:.1} in {time_display} (host: {agent})");
    t!(
        "zh-CN",
        "alert.trend_prediction",
        "{metric}{labels} 预计在 {time_display} 后达到阈值 {threshold:.1}（主机: {agent}）"
    );

    // Certificate expiration
    t!(
        "en",
        "alert.cert_expired",
        "Certificate expired: {domain} (expired {days:.0} days ago)"
    );
    t!(
        "zh-CN",
        "alert.cert_expired",
        "证书已过期: {domain} (已过期 {days:.0} 天)"
    );

    t!("en", "alert.cert_expiring_critical", "Certificate expiring soon: {domain} ({days:.0} days left, below {threshold} day critical threshold)");
    t!(
        "zh-CN",
        "alert.cert_expiring_critical",
        "证书即将过期: {domain} (剩余 {days:.0} 天，低于 {threshold} 天严重阈值)"
    );

    t!("en", "alert.cert_expiring_warning", "Certificate expiring soon: {domain} ({days:.0} days left, below {threshold} day warning threshold)");
    t!(
        "zh-CN",
        "alert.cert_expiring_warning",
        "证书即将过期: {domain} (剩余 {days:.0} 天，低于 {threshold} 天警告阈值)"
    );

    // Recovery
    t!(
        "en",
        "alert.recovered",
        "[RECOVERED] {metric} has returned to normal on {agent}"
    );
    t!(
        "zh-CN",
        "alert.recovered",
        "[已恢复] {metric} 在 {agent} 上已恢复正常"
    );

    // ---- Cloud scale recommendation ----
    t!(
        "en",
        "alert.scale.out.recommendation",
        "Scale-Out Recommendation"
    );
    t!("zh-CN", "alert.scale.out.recommendation", "扩容建议");
    t!(
        "en",
        "alert.scale.in.recommendation",
        "Scale-In Recommendation"
    );
    t!("zh-CN", "alert.scale.in.recommendation", "缩容建议");
    t!(
        "en",
        "alert.scale.continuously_high",
        "usage continuously exceeds"
    );
    t!("zh-CN", "alert.scale.continuously_high", "使用率持续超过");
    t!(
        "en",
        "alert.scale.continuously_low",
        "usage continuously below"
    );
    t!("zh-CN", "alert.scale.continuously_low", "使用率持续低于");
    t!("en", "alert.scale.avg_value", "Average");
    t!("zh-CN", "alert.scale.avg_value", "平均值");
    t!("en", "alert.scale.trend", "Trend");
    t!("zh-CN", "alert.scale.trend", "趋势");
    t!(
        "en",
        "alert.scale.out.action",
        "Consider adding more instances or upgrading instance specifications."
    );
    t!(
        "zh-CN",
        "alert.scale.out.action",
        "建议增加实例数量或升级实例规格。"
    );
    t!(
        "en",
        "alert.scale.in.action",
        "Consider reducing instances or downgrading specifications to save costs."
    );
    t!(
        "zh-CN",
        "alert.scale.in.action",
        "建议减少实例数量或降低规格以节约成本。"
    );
    t!("en", "alert.trend.rising", "Rising");
    t!("zh-CN", "alert.trend.rising", "上升");
    t!("en", "alert.trend.falling", "Falling");
    t!("zh-CN", "alert.trend.falling", "下降");
    t!("en", "alert.trend.stable", "Stable");
    t!("zh-CN", "alert.trend.stable", "稳定");
    t!("en", "metric.cpu", "CPU");
    t!("zh-CN", "metric.cpu", "CPU");
    t!("en", "metric.memory", "Memory");
    t!("zh-CN", "metric.memory", "内存");

    // ---- Threshold operator display ----
    t!("en", "op.above", "above");
    t!("zh-CN", "op.above", "高于");
    t!("en", "op.below", "below");
    t!("zh-CN", "op.below", "低于");
    t!("en", "op.at_or_above", "at or above");
    t!("zh-CN", "op.at_or_above", "大于等于");
    t!("en", "op.at_or_below", "at or below");
    t!("zh-CN", "op.at_or_below", "小于等于");

    // ---- Time display ----
    t!("en", "time.minutes", "{n} minutes");
    t!("zh-CN", "time.minutes", "{n} 分钟");
    t!("en", "time.hours", "{n} hours");
    t!("zh-CN", "time.hours", "{n} 小时");

    // ---- Certificate alert report ----
    t!("en", "cert_report.title", "Certificate Alert Report");
    t!("zh-CN", "cert_report.title", "证书告警报告");
    t!("en", "cert_report.date", "Report Date");
    t!("zh-CN", "cert_report.date", "报告日期");
    t!("en", "cert_report.total_checked", "Checked Domains");
    t!("zh-CN", "cert_report.total_checked", "检查域名数");
    t!("en", "cert_report.alert_count", "Alert Domains");
    t!("zh-CN", "cert_report.alert_count", "告警域名数");
    t!("en", "cert_report.critical", "Critical");
    t!("zh-CN", "cert_report.critical", "严重");
    t!("en", "cert_report.warning", "Warning");
    t!("zh-CN", "cert_report.warning", "警告");
    t!("en", "cert_report.domain", "Domain");
    t!("zh-CN", "cert_report.domain", "域名");
    t!("en", "cert_report.days_left", "Days Left");
    t!("zh-CN", "cert_report.days_left", "剩余天数");
    t!("en", "cert_report.expiry_date", "Expiry Date");
    t!("zh-CN", "cert_report.expiry_date", "过期日期");
    t!("en", "cert_report.issuer", "Issuer");
    t!("zh-CN", "cert_report.issuer", "颁发者");
    t!("en", "cert_report.expired_tag", "Expired");
    t!("zh-CN", "cert_report.expired_tag", "已过期");
    t!("en", "cert_report.subject_prefix", "[oxmon][Cert Alert]");
    t!("zh-CN", "cert_report.subject_prefix", "[oxmon][证书告警]");

    // ---- Notification labels ----
    t!("en", "notify.severity", "Severity");
    t!("zh-CN", "notify.severity", "级别");
    t!("en", "notify.agent", "Agent");
    t!("zh-CN", "notify.agent", "主机");
    t!("en", "notify.metric", "Metric");
    t!("zh-CN", "notify.metric", "指标");
    t!("en", "notify.value", "Value");
    t!("zh-CN", "notify.value", "当前值");
    t!("en", "notify.threshold", "Threshold");
    t!("zh-CN", "notify.threshold", "阈值");
    t!("en", "notify.time", "Time");
    t!("zh-CN", "notify.time", "时间");
    t!("en", "notify.rule", "Rule");
    t!("zh-CN", "notify.rule", "规则");
    t!("en", "notify.labels", "Labels");
    t!("zh-CN", "notify.labels", "标签");
    t!("en", "notify.message", "Message");
    t!("zh-CN", "notify.message", "消息");
    t!("en", "notify.recovered_tag", "[RECOVERED]");
    t!("zh-CN", "notify.recovered_tag", "[已恢复]");
    t!("en", "notify.alert", "Alert");
    t!("zh-CN", "notify.alert", "告警");
    t!("en", "notify.at_all", "@All");
    t!("zh-CN", "notify.at_all", "@所有人");

    Translations { map }
});

/// Check if a locale string is supported.
pub fn is_supported_locale(locale: &str) -> bool {
    SUPPORTED_LOCALES.contains(&locale)
}

/// Normalize locale: return the locale if supported, otherwise return the default.
pub fn normalize_locale(locale: &str) -> &str {
    if is_supported_locale(locale) {
        locale
    } else {
        DEFAULT_LOCALE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_translation_zh_cn() {
        let t = &*TRANSLATIONS;
        assert_eq!(t.get("zh-CN", "notify.severity", ""), "级别");
        assert_eq!(t.get("zh-CN", "notify.agent", ""), "主机");
    }

    #[test]
    fn test_get_translation_en() {
        let t = &*TRANSLATIONS;
        assert_eq!(t.get("en", "notify.severity", ""), "Severity");
        assert_eq!(t.get("en", "notify.agent", ""), "Agent");
    }

    #[test]
    fn test_fallback_to_en() {
        let t = &*TRANSLATIONS;
        // Unknown locale should fall back to "en"
        assert_eq!(t.get("fr", "notify.severity", "fallback"), "Severity");
    }

    #[test]
    fn test_fallback_to_default() {
        let t = &*TRANSLATIONS;
        // Unknown key should fall back to default
        assert_eq!(t.get("en", "nonexistent.key", "default_val"), "default_val");
    }

    #[test]
    fn test_all_keys_have_both_locales() {
        let t = &*TRANSLATIONS;
        // Collect all unique keys
        let keys: std::collections::HashSet<&str> = t.map.keys().map(|(_, key)| *key).collect();

        for key in &keys {
            assert!(
                t.map.contains_key(&("zh-CN", key)),
                "Missing zh-CN translation for key: {key}"
            );
            assert!(
                t.map.contains_key(&("en", key)),
                "Missing en translation for key: {key}"
            );
        }
    }

    #[test]
    fn test_is_supported_locale() {
        assert!(is_supported_locale("zh-CN"));
        assert!(is_supported_locale("en"));
        assert!(!is_supported_locale("fr"));
    }

    #[test]
    fn test_normalize_locale() {
        assert_eq!(normalize_locale("zh-CN"), "zh-CN");
        assert_eq!(normalize_locale("en"), "en");
        assert_eq!(normalize_locale("fr"), DEFAULT_LOCALE);
    }
}
