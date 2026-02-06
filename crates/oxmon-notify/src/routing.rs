use oxmon_common::types::Severity;

pub struct ChannelRoute {
    pub min_severity: Severity,
    pub channel_index: usize,
}

impl ChannelRoute {
    pub fn should_send(&self, event_severity: Severity) -> bool {
        event_severity >= self.min_severity
    }
}
