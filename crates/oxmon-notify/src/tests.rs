use crate::manager::SilenceWindow;
use crate::plugin::ChannelRegistry;
use crate::routing::ChannelRoute;
use chrono::NaiveTime;
use oxmon_common::types::Severity;

#[test]
fn silence_window_active_within_range() {
    let window = SilenceWindow {
        start: NaiveTime::from_hms_opt(2, 0, 0).unwrap(),
        end: NaiveTime::from_hms_opt(4, 0, 0).unwrap(),
        recurrence: Some("daily".into()),
    };

    // Simulate a time within the window
    let within = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
        .unwrap()
        .and_hms_opt(3, 0, 0)
        .unwrap()
        .and_utc();
    assert!(window.is_active(within));

    let outside = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
        .unwrap()
        .and_hms_opt(5, 0, 0)
        .unwrap()
        .and_utc();
    assert!(!window.is_active(outside));
}

#[test]
fn silence_window_overnight() {
    let window = SilenceWindow {
        start: NaiveTime::from_hms_opt(23, 0, 0).unwrap(),
        end: NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
        recurrence: None,
    };

    let late_night = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
        .unwrap()
        .and_hms_opt(23, 30, 0)
        .unwrap()
        .and_utc();
    assert!(window.is_active(late_night));

    let early_morning = chrono::NaiveDate::from_ymd_opt(2024, 1, 2)
        .unwrap()
        .and_hms_opt(2, 0, 0)
        .unwrap()
        .and_utc();
    assert!(window.is_active(early_morning));

    let daytime = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
        .unwrap()
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc();
    assert!(!window.is_active(daytime));
}

#[test]
fn routing_severity_filter() {
    let route_warning = ChannelRoute {
        min_severity: Severity::Warning,
        channel_index: 0,
    };
    let route_info = ChannelRoute {
        min_severity: Severity::Info,
        channel_index: 1,
    };

    // Info should not pass warning filter
    assert!(!route_warning.should_send(Severity::Info));
    assert!(route_warning.should_send(Severity::Warning));
    assert!(route_warning.should_send(Severity::Critical));

    // Info filter accepts everything
    assert!(route_info.should_send(Severity::Info));
    assert!(route_info.should_send(Severity::Warning));
    assert!(route_info.should_send(Severity::Critical));
}

// ── Plugin registry tests ──

#[test]
fn registry_default_has_all_builtin_plugins() {
    let registry = ChannelRegistry::default();
    let mut names = registry.plugin_names();
    names.sort();
    assert_eq!(names, vec!["dingtalk", "email", "sms", "webhook", "weixin"]);
}

#[test]
fn registry_unknown_plugin_returns_error() {
    let registry = ChannelRegistry::default();
    let config = serde_json::json!({});
    let result = registry.create_channel("nonexistent", &config);
    let err = result.err().expect("should return error for unknown plugin");
    assert!(
        err.to_string().contains("Unknown channel plugin type"),
        "error message was: {}",
        err
    );
}

#[test]
fn dingtalk_plugin_validates_config() {
    let registry = ChannelRegistry::default();

    // Valid config
    let valid = serde_json::json!({
        "webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=test",
        "secret": "SEC_test"
    });
    assert!(registry.create_channel("dingtalk", &valid).is_ok());

    // Valid without optional secret
    let valid_no_secret = serde_json::json!({
        "webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=test"
    });
    assert!(registry.create_channel("dingtalk", &valid_no_secret).is_ok());

    // Missing required webhook_url
    let invalid = serde_json::json!({});
    assert!(registry.create_channel("dingtalk", &invalid).is_err());
}

#[test]
fn weixin_plugin_validates_config() {
    let registry = ChannelRegistry::default();

    // Valid config
    let valid = serde_json::json!({
        "webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test"
    });
    assert!(registry.create_channel("weixin", &valid).is_ok());

    // Missing required webhook_url
    let invalid = serde_json::json!({});
    assert!(registry.create_channel("weixin", &invalid).is_err());
}

#[test]
fn dingtalk_hmac_signing_produces_correct_url_format() {
    let channel = crate::channels::dingtalk::DingTalkChannel::new(
        "https://oapi.dingtalk.com/robot/send?access_token=test",
        Some("SEC_test_secret".to_string()),
    );
    let signed_url = channel.sign_url("https://oapi.dingtalk.com/robot/send?access_token=test");
    assert!(signed_url.contains("&timestamp="));
    assert!(signed_url.contains("&sign="));
    assert!(signed_url.starts_with("https://oapi.dingtalk.com/robot/send?access_token=test&timestamp="));
}

#[test]
fn dingtalk_no_secret_returns_url_unchanged() {
    let channel = crate::channels::dingtalk::DingTalkChannel::new(
        "https://oapi.dingtalk.com/robot/send?access_token=test",
        None,
    );
    let url = "https://oapi.dingtalk.com/robot/send?access_token=test";
    assert_eq!(channel.sign_url(url), url);
}

#[test]
fn email_plugin_validates_config() {
    let registry = ChannelRegistry::default();

    let valid = serde_json::json!({
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "from": "test@example.com",
        "recipients": ["admin@example.com"]
    });
    assert!(registry.create_channel("email", &valid).is_ok());

    let invalid = serde_json::json!({});
    assert!(registry.create_channel("email", &invalid).is_err());
}

#[test]
fn webhook_plugin_validates_config() {
    let registry = ChannelRegistry::default();

    let valid = serde_json::json!({
        "url": "https://hooks.example.com/webhook"
    });
    assert!(registry.create_channel("webhook", &valid).is_ok());

    let invalid = serde_json::json!({});
    assert!(registry.create_channel("webhook", &invalid).is_err());
}

#[test]
fn sms_plugin_validates_config() {
    let registry = ChannelRegistry::default();

    let valid = serde_json::json!({
        "gateway_url": "https://sms.example.com/send",
        "api_key": "test-key",
        "phone_numbers": ["+8613800138000"]
    });
    assert!(registry.create_channel("sms", &valid).is_ok());

    let invalid = serde_json::json!({});
    assert!(registry.create_channel("sms", &invalid).is_err());
}
