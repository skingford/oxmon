use crate::manager::{is_meaningful_config, parse_config_json, SilenceWindow};
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
        channel_id: "ch-1".to_string(),
        min_severity: Severity::Warning,
    };
    let route_info = ChannelRoute {
        channel_id: "ch-2".to_string(),
        min_severity: Severity::Info,
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
    let result = registry.create_channel("nonexistent", "test-id", &config);
    let err = result
        .err()
        .expect("should return error for unknown plugin");
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
    assert!(registry.create_channel("dingtalk", "dt-1", &valid).is_ok());

    // Valid without optional secret
    let valid_no_secret = serde_json::json!({
        "webhook_url": "https://oapi.dingtalk.com/robot/send?access_token=test"
    });
    assert!(registry
        .create_channel("dingtalk", "dt-2", &valid_no_secret)
        .is_ok());

    // Missing required webhook_url
    let invalid = serde_json::json!({});
    assert!(registry.create_channel("dingtalk", "dt-3", &invalid).is_err());
}

#[test]
fn weixin_plugin_validates_config() {
    let registry = ChannelRegistry::default();

    // Valid config
    let valid = serde_json::json!({
        "webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test"
    });
    assert!(registry.create_channel("weixin", "wx-1", &valid).is_ok());

    // Missing required webhook_url
    let invalid = serde_json::json!({});
    assert!(registry.create_channel("weixin", "wx-2", &invalid).is_err());
}

#[test]
fn dingtalk_hmac_signing_produces_correct_url_format() {
    let channel = crate::channels::dingtalk::DingTalkChannel::new(
        "test-instance",
        "https://oapi.dingtalk.com/robot/send?access_token=test",
        Some("SEC_test_secret".to_string()),
    );
    let signed_url = channel.sign_url("https://oapi.dingtalk.com/robot/send?access_token=test");
    assert!(signed_url.contains("&timestamp="));
    assert!(signed_url.contains("&sign="));
    assert!(
        signed_url.starts_with("https://oapi.dingtalk.com/robot/send?access_token=test&timestamp=")
    );
}

#[test]
fn dingtalk_no_secret_returns_url_unchanged() {
    let channel = crate::channels::dingtalk::DingTalkChannel::new(
        "test-instance",
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
        "from": "test@example.com"
    });
    assert!(registry.create_channel("email", "em-1", &valid).is_ok());

    let invalid = serde_json::json!({});
    assert!(registry.create_channel("email", "em-2", &invalid).is_err());
}

#[test]
fn webhook_plugin_validates_config() {
    let registry = ChannelRegistry::default();

    // Webhook config only needs optional body_template now
    let valid = serde_json::json!({});
    assert!(registry.create_channel("webhook", "wh-1", &valid).is_ok());

    // With body_template
    let valid_template = serde_json::json!({
        "body_template": "{\"text\": \"{{message}}\"}"
    });
    assert!(registry.create_channel("webhook", "wh-2", &valid_template).is_ok());
}

#[test]
fn sms_plugin_validates_config() {
    let registry = ChannelRegistry::default();

    // generic without provider field (backward compatible)
    let valid = serde_json::json!({
        "gateway_url": "https://sms.example.com/send",
        "api_key": "test-key"
    });
    assert!(registry.create_channel("sms", "sms-1", &valid).is_ok());

    let invalid = serde_json::json!({});
    assert!(registry.create_channel("sms", "sms-2", &invalid).is_err());
}

#[test]
fn sms_plugin_validates_generic_with_provider_field() {
    let registry = ChannelRegistry::default();
    let valid = serde_json::json!({
        "provider": "generic",
        "gateway_url": "https://sms.example.com/send",
        "api_key": "test-key"
    });
    assert!(registry.create_channel("sms", "sms-g", &valid).is_ok());
}

#[test]
fn sms_plugin_validates_aliyun_config() {
    let registry = ChannelRegistry::default();

    let valid = serde_json::json!({
        "provider": "aliyun",
        "access_key_id": "LTAI5tXXXXXX",
        "access_key_secret": "xxxxxxxxxxxxxxxx",
        "sign_name": "oxmon",
        "template_code": "SMS_123456"
    });
    assert!(registry.create_channel("sms", "sms-ali-1", &valid).is_ok());

    // with optional fields
    let valid_full = serde_json::json!({
        "provider": "aliyun",
        "access_key_id": "LTAI5tXXXXXX",
        "access_key_secret": "xxxxxxxxxxxxxxxx",
        "sign_name": "oxmon",
        "template_code": "SMS_123456",
        "template_param": "{\"code\":\"1234\"}",
        "endpoint": "dysmsapi.aliyuncs.com"
    });
    assert!(registry.create_channel("sms", "sms-ali-2", &valid_full).is_ok());

    // missing required field
    let invalid = serde_json::json!({
        "provider": "aliyun",
        "access_key_id": "LTAI5tXXXXXX"
    });
    assert!(registry.create_channel("sms", "sms-ali-3", &invalid).is_err());
}

#[test]
fn sms_plugin_validates_tencent_config() {
    let registry = ChannelRegistry::default();

    let valid = serde_json::json!({
        "provider": "tencent",
        "secret_id": "AKIDxxxxxxxx",
        "secret_key": "xxxxxxxxxxxxxxxx",
        "sdk_app_id": "1400123456",
        "sign_name": "oxmon",
        "template_id": "12345"
    });
    assert!(registry.create_channel("sms", "sms-tc-1", &valid).is_ok());

    // missing required field
    let invalid = serde_json::json!({
        "provider": "tencent",
        "secret_id": "AKIDxxxxxxxx"
    });
    assert!(registry.create_channel("sms", "sms-tc-2", &invalid).is_err());
}

#[test]
fn sms_plugin_rejects_unknown_provider() {
    let registry = ChannelRegistry::default();
    let config = serde_json::json!({
        "provider": "unknown_provider",
        "some_field": "value"
    });
    let result = registry.create_channel("sms", "sms-unknown", &config);
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected error for unknown provider"),
    };
    assert!(err.to_string().contains("Unknown sms provider"));
}

#[test]
fn sms_aliyun_percent_encode() {
    use crate::channels::sms::SmsChannel;
    assert_eq!(SmsChannel::aliyun_percent_encode("/"), "%2F");
    assert_eq!(SmsChannel::aliyun_percent_encode("a b+c"), "a%20b%2Bc");
    assert_eq!(SmsChannel::aliyun_percent_encode("hello"), "hello");
    assert_eq!(SmsChannel::aliyun_percent_encode("a~b_c-d.e"), "a~b_c-d.e");
}

#[test]
fn sms_aliyun_sign_deterministic() {
    use crate::channels::sms::SmsChannel;
    let params = vec![
        ("Action".to_string(), "SendSms".to_string()),
        ("AccessKeyId".to_string(), "testkey".to_string()),
    ];
    let sig1 = SmsChannel::aliyun_sign(&params, "testsecret");
    let sig2 = SmsChannel::aliyun_sign(&params, "testsecret");
    assert_eq!(sig1, sig2);
    assert!(!sig1.is_empty());
}

#[test]
fn sms_tencent_sign_produces_valid_authorization() {
    use crate::channels::sms::SmsChannel;
    let auth = SmsChannel::tencent_sign(
        "AKIDtest",
        "testsecretkey",
        "sms",
        "sms.tencentcloudapi.com",
        "{}",
        1700000000,
    );
    assert!(auth.starts_with("TC3-HMAC-SHA256 Credential=AKIDtest/"));
    assert!(auth.contains("SignedHeaders=content-type;host"));
    assert!(auth.contains("Signature="));
}

#[test]
fn sms_redact_config_covers_all_providers() {
    let registry = ChannelRegistry::default();
    let plugin = registry.get_plugin("sms").unwrap();

    // Generic
    let generic = serde_json::json!({"api_key": "secret123", "gateway_url": "https://x.com"});
    let redacted = plugin.redact_config(&generic);
    assert_eq!(redacted["api_key"], "***");
    assert_eq!(redacted["gateway_url"], "https://x.com");

    // Aliyun
    let aliyun = serde_json::json!({"access_key_secret": "secret123", "access_key_id": "visible"});
    let redacted = plugin.redact_config(&aliyun);
    assert_eq!(redacted["access_key_secret"], "***");
    assert_eq!(redacted["access_key_id"], "visible");

    // Tencent
    let tencent = serde_json::json!({"secret_key": "secret123", "secret_id": "visible"});
    let redacted = plugin.redact_config(&tencent);
    assert_eq!(redacted["secret_key"], "***");
    assert_eq!(redacted["secret_id"], "visible");
}

// ── Config resolution helper tests ──

#[test]
fn is_meaningful_config_empty_object() {
    assert!(!is_meaningful_config(&serde_json::json!({})));
}

#[test]
fn is_meaningful_config_null() {
    assert!(!is_meaningful_config(&serde_json::Value::Null));
}

#[test]
fn is_meaningful_config_with_fields() {
    assert!(is_meaningful_config(&serde_json::json!({"smtp_host": "mail.example.com"})));
}

#[test]
fn is_meaningful_config_array_not_meaningful() {
    assert!(!is_meaningful_config(&serde_json::json!([1, 2, 3])));
}

#[test]
fn parse_config_json_valid() {
    let result = parse_config_json(r#"{"key": "value"}"#);
    assert!(result.is_some());
    assert!(is_meaningful_config(&result.unwrap()));
}

#[test]
fn parse_config_json_empty_string() {
    assert!(parse_config_json("").is_none());
}

#[test]
fn parse_config_json_whitespace_only() {
    assert!(parse_config_json("   ").is_none());
}

#[test]
fn parse_config_json_invalid_json() {
    assert!(parse_config_json("{invalid}").is_none());
}

#[test]
fn parse_config_json_empty_object() {
    let result = parse_config_json("{}");
    assert!(result.is_some());
    assert!(!is_meaningful_config(&result.unwrap()));
}
