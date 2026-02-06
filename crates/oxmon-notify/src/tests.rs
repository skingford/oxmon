use crate::manager::SilenceWindow;
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
