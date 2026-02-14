use oxmon_common::types::Severity;

pub struct ChannelRoute {
    pub channel_id: String,
    pub min_severity: Severity,
}

impl ChannelRoute {
    pub fn should_send(&self, event_severity: Severity) -> bool {
        event_severity >= self.min_severity
    }
}
