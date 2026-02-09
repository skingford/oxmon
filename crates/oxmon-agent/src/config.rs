use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub server_endpoint: String,
    /// Enable TLS for gRPC connection
    #[serde(default)]
    pub tls: bool,
    #[serde(default = "default_collection_interval")]
    pub collection_interval_secs: u64,
    #[serde(default = "default_buffer_max_size")]
    pub buffer_max_size: usize,
    /// Optional authentication token for server whitelist
    pub auth_token: Option<String>,
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

    /// Build the gRPC endpoint URI from server_endpoint and tls config.
    pub fn grpc_endpoint(&self) -> String {
        let addr = self.server_endpoint.trim();
        if addr.contains("://") {
            return addr.to_string();
        }
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{addr}")
    }
}
