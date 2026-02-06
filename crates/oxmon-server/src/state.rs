use chrono::{DateTime, Duration, Utc};
use oxmon_alert::engine::AlertEngine;
use oxmon_common::types::AgentInfo;
use oxmon_notify::manager::NotificationManager;
use oxmon_storage::engine::SqliteStorageEngine;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct AgentRegistry {
    agents: HashMap<String, DateTime<Utc>>,
    collection_interval_secs: u64,
}

impl AgentRegistry {
    pub fn new(collection_interval_secs: u64) -> Self {
        Self {
            agents: HashMap::new(),
            collection_interval_secs,
        }
    }

    pub fn update_agent(&mut self, agent_id: &str) {
        self.agents.insert(agent_id.to_string(), Utc::now());
    }

    pub fn list_agents(&self) -> Vec<AgentInfo> {
        let now = Utc::now();
        let timeout = Duration::seconds((self.collection_interval_secs * 3) as i64);
        self.agents
            .iter()
            .map(|(id, last_seen)| AgentInfo {
                agent_id: id.clone(),
                last_seen: *last_seen,
                active: now - *last_seen < timeout,
            })
            .collect()
    }

    pub fn get_agent(&self, agent_id: &str) -> Option<AgentInfo> {
        let now = Utc::now();
        let timeout = Duration::seconds((self.collection_interval_secs * 3) as i64);
        self.agents.get(agent_id).map(|last_seen| AgentInfo {
            agent_id: agent_id.to_string(),
            last_seen: *last_seen,
            active: now - *last_seen < timeout,
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<SqliteStorageEngine>,
    pub alert_engine: Arc<Mutex<AlertEngine>>,
    pub notifier: Arc<NotificationManager>,
    pub agent_registry: Arc<Mutex<AgentRegistry>>,
    pub start_time: DateTime<Utc>,
}
