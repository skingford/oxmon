use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub server_endpoint: String,
    #[serde(default = "default_collection_interval")]
    pub collection_interval_secs: u64,
    #[serde(default = "default_buffer_max_size")]
    pub buffer_max_size: usize,
}

fn default_collection_interval() -> u64 {
    10
}

fn default_buffer_max_size() -> usize {
    1000
}

impl AgentConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}
