use crate::config::ServerConfig;
use chrono::{DateTime, Duration, Utc};
use oxmon_alert::engine::AlertEngine;
use oxmon_common::types::AgentInfo;
use oxmon_notify::manager::NotificationManager;
use oxmon_storage::auth::PasswordEncryptor;
use oxmon_storage::engine::SqliteStorageEngine;
use oxmon_storage::CertStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct AgentRegistry {
    agents: HashMap<String, DateTime<Utc>>,
    default_collection_interval_secs: u64,
}

impl AgentRegistry {
    pub fn new(default_collection_interval_secs: u64) -> Self {
        Self {
            agents: HashMap::new(),
            default_collection_interval_secs,
        }
    }

    pub fn update_agent(&mut self, agent_id: &str) {
        self.agents.insert(agent_id.to_string(), Utc::now());
    }

    pub fn list_agents(&self) -> Vec<AgentInfo> {
        let now = Utc::now();
        let default_interval = self.default_collection_interval_secs;
        self.agents
            .iter()
            .map(|(id, last_seen)| {
                let timeout = Duration::seconds((default_interval * 3) as i64);
                AgentInfo {
                    id: String::new(),
                    agent_id: id.clone(),
                    last_seen: *last_seen,
                    active: now - *last_seen < timeout,
                    collection_interval_secs: None, // 从数据库查询
                    description: None,              // 从数据库查询
                }
            })
            .collect()
    }

    pub fn remove_agent(&mut self, agent_id: &str) -> bool {
        self.agents.remove(agent_id).is_some()
    }

    pub fn get_agent(&self, agent_id: &str) -> Option<AgentInfo> {
        let now = Utc::now();
        let timeout = Duration::seconds((self.default_collection_interval_secs * 3) as i64);
        self.agents.get(agent_id).map(|last_seen| AgentInfo {
            id: String::new(),
            agent_id: agent_id.to_string(),
            last_seen: *last_seen,
            active: now - *last_seen < timeout,
            collection_interval_secs: None, // 从数据库查询
            description: None,              // 从数据库查询
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<SqliteStorageEngine>,
    pub alert_engine: Arc<Mutex<AlertEngine>>,
    pub notifier: Arc<NotificationManager>,
    pub agent_registry: Arc<Mutex<AgentRegistry>>,
    pub cert_store: Arc<CertStore>,
    pub connect_timeout_secs: u64,
    pub start_time: DateTime<Utc>,
    pub jwt_secret: Arc<String>,
    pub token_expire_secs: u64,
    pub password_encryptor: Arc<PasswordEncryptor>,
    pub config: Arc<ServerConfig>,
}
