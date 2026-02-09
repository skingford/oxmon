use chrono::{DateTime, Duration, Utc};
use oxmon_common::types::MetricDataPoint;
use std::collections::VecDeque;

/// A time-bounded sliding window that holds recent [`MetricDataPoint`]s.
///
/// Data points older than `window_secs` are automatically evicted on each
/// push or explicit `evict()` call.
///
/// # Examples
///
/// ```
/// use oxmon_alert::window::SlidingWindow;
/// use oxmon_common::types::MetricDataPoint;
/// use chrono::Utc;
/// use std::collections::HashMap;
///
/// let mut window = SlidingWindow::new(300); // 5-minute window
/// window.push(MetricDataPoint {
///     id: "1".into(),
///     timestamp: Utc::now(),
///     agent_id: "agent-1".into(),
///     metric_name: "cpu.usage".into(),
///     value: 85.0,
///     labels: HashMap::new(),
///     created_at: Utc::now(),
///     updated_at: Utc::now(),
/// });
/// assert_eq!(window.len(), 1);
/// assert!(!window.is_empty());
/// ```
pub struct SlidingWindow {
    window_secs: i64,
    data: VecDeque<MetricDataPoint>,
}

impl SlidingWindow {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs: window_secs as i64,
            data: VecDeque::new(),
        }
    }

    pub fn push(&mut self, point: MetricDataPoint) {
        self.data.push_back(point);
        self.evict(Utc::now());
    }

    pub fn evict(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.window_secs);
        while let Some(front) = self.data.front() {
            if front.timestamp < cutoff {
                self.data.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn data(&self) -> &VecDeque<MetricDataPoint> {
        &self.data
    }

    /// Returns a contiguous slice of the window data, rearranging internal
    /// storage if necessary. Prefer this over `data()` when a `&[MetricDataPoint]`
    /// is needed, as it avoids allocating an intermediate `Vec`.
    pub fn as_contiguous_slice(&mut self) -> &[MetricDataPoint] {
        self.data.make_contiguous()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}
