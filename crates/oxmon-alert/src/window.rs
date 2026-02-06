use chrono::{DateTime, Duration, Utc};
use oxmon_common::types::MetricDataPoint;
use std::collections::VecDeque;

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

    pub fn as_slice(&self) -> Vec<&MetricDataPoint> {
        self.data.iter().collect()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}
