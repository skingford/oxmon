use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_require_agent_auth")]
    pub require_agent_auth: bool,
    /// Agent 采集间隔（秒），用于判断 agent 活跃状态
    /// 超时阈值 = agent_collection_interval_secs * 3
    #[serde(default = "default_agent_collection_interval_secs")]
    pub agent_collection_interval_secs: u64,

    /// CORS 允许的 origins 列表，为空时允许所有来源（开发模式）
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,

    /// 是否启用 API 速率限制（默认 true）
    #[serde(default = "default_rate_limit_enabled")]
    pub rate_limit_enabled: bool,

    #[serde(default)]
    pub cert_check: CertCheckConfig,
    #[serde(default)]
    pub cloud_check: CloudCheckConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub app_id: AppIdConfig,
}

// ---- Seed file types (used by `init-channels` CLI subcommand) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedFile {
    #[serde(default)]
    pub channels: Vec<SeedChannel>,
    #[serde(default)]
    pub silence_windows: Vec<SeedSilenceWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedChannel {
    pub name: String,
    pub channel_type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_seed_min_severity")]
    pub min_severity: String,
    #[serde(default = "default_seed_enabled")]
    pub enabled: bool,
    pub config: serde_json::Value,
    #[serde(default)]
    pub recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedSilenceWindow {
    pub start_time: String,
    pub end_time: String,
    pub recurrence: Option<String>,
}

// ---- Rules seed file types (used by `init-rules` CLI subcommand) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesSeedFile {
    #[serde(default)]
    pub rules: Vec<SeedAlertRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedAlertRule {
    pub name: String,
    pub rule_type: String,
    pub metric: String,
    #[serde(default = "default_agent_pattern")]
    pub agent_pattern: String,
    #[serde(default = "default_seed_severity")]
    pub severity: String,
    #[serde(default = "default_seed_enabled")]
    pub enabled: bool,
    #[serde(default = "default_silence_secs")]
    pub silence_secs: u64,
    pub config: serde_json::Value,
}

// ---- System configs seed file types (used by `init-configs` CLI subcommand) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfigsSeedFile {
    #[serde(default)]
    pub configs: Vec<SeedSystemConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedSystemConfig {
    pub config_key: String,
    pub config_type: String,
    #[serde(default)]
    pub provider: Option<String>,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub config: serde_json::Value,
    #[serde(default = "default_seed_enabled")]
    pub enabled: bool,
}

fn default_seed_severity() -> String {
    "info".to_string()
}

// ---- Cloud accounts seed file types (used by `init-cloud-accounts` CLI subcommand) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAccountsSeedFile {
    #[serde(default)]
    pub accounts: Vec<SeedCloudAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedCloudAccount {
    pub config_key: String,
    pub provider: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub config: serde_json::Value,
    #[serde(default = "default_seed_enabled")]
    pub enabled: bool,
}

// ---- Dictionaries seed file types (used by `init-dictionaries` CLI subcommand) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionariesSeedFile {
    #[serde(default)]
    pub dictionaries: Vec<SeedDictionary>,
    #[serde(default)]
    pub dictionary_types: Option<Vec<SeedDictionaryType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedDictionaryType {
    pub dict_type: String,
    pub dict_type_label: String,
    #[serde(default)]
    pub sort_order: Option<i32>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedDictionary {
    pub dict_type: String,
    pub dict_key: String,
    pub dict_label: String,
    #[serde(default)]
    pub dict_value: Option<String>,
    #[serde(default)]
    pub sort_order: Option<i32>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub is_system: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub extra_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertCheckConfig {
    #[serde(default = "default_cert_check_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cert_check_default_interval_secs")]
    pub default_interval_secs: u64,
    #[serde(default = "default_cert_check_tick_secs")]
    pub tick_secs: u64,
    #[serde(default = "default_cert_check_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_cert_check_max_concurrent")]
    pub max_concurrent: usize,
}

impl Default for CertCheckConfig {
    fn default() -> Self {
        Self {
            enabled: default_cert_check_enabled(),
            default_interval_secs: default_cert_check_default_interval_secs(),
            tick_secs: default_cert_check_tick_secs(),
            connect_timeout_secs: default_cert_check_connect_timeout_secs(),
            max_concurrent: default_cert_check_max_concurrent(),
        }
    }
}

fn default_cert_check_enabled() -> bool {
    true
}

fn default_cert_check_default_interval_secs() -> u64 {
    86400
}

fn default_cert_check_tick_secs() -> u64 {
    60
}

fn default_cert_check_connect_timeout_secs() -> u64 {
    10
}

fn default_cert_check_max_concurrent() -> usize {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudCheckConfig {
    #[serde(default = "default_cloud_check_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cloud_check_tick_secs")]
    pub tick_secs: u64,
    #[serde(default = "default_cloud_check_max_concurrent")]
    pub max_concurrent: usize,
}

impl Default for CloudCheckConfig {
    fn default() -> Self {
        Self {
            enabled: default_cloud_check_enabled(),
            tick_secs: default_cloud_check_tick_secs(),
            max_concurrent: default_cloud_check_max_concurrent(),
        }
    }
}

fn default_cloud_check_enabled() -> bool {
    true
}

fn default_cloud_check_tick_secs() -> u64 {
    60 // Check for due accounts every 60 seconds
}

fn default_cloud_check_max_concurrent() -> usize {
    5 // Max 5 concurrent API calls
}

fn default_grpc_port() -> u16 {
    9090
}

fn default_http_port() -> u16 {
    8080
}

fn default_data_dir() -> String {
    "data".to_string()
}

fn default_retention_days() -> u32 {
    7
}

fn default_agent_pattern() -> String {
    "*".to_string()
}

fn default_silence_secs() -> u64 {
    600
}

fn default_seed_min_severity() -> String {
    "info".to_string()
}

fn default_seed_enabled() -> bool {
    true
}

fn default_require_agent_auth() -> bool {
    false
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_agent_collection_interval_secs() -> u64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub jwt_secret: Option<String>,
    #[serde(default = "default_token_expire_secs")]
    pub token_expire_secs: u64,
    #[serde(default = "default_username")]
    pub default_username: String,
    #[serde(default = "default_password")]
    pub default_password: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: None,
            token_expire_secs: default_token_expire_secs(),
            default_username: default_username(),
            default_password: default_password(),
        }
    }
}

fn default_token_expire_secs() -> u64 {
    86400
}

fn default_username() -> String {
    "admin".to_string()
}

fn default_password() -> String {
    "changeme".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppIdConfig {
    /// Whether to require ox-app-id header on public/auth routes (default: false)
    #[serde(default = "default_require_app_id")]
    pub require_app_id: bool,
    /// List of allowed ox-app-id values
    #[serde(default)]
    pub allowed_app_ids: Vec<String>,
}

impl Default for AppIdConfig {
    fn default() -> Self {
        Self {
            require_app_id: default_require_app_id(),
            allowed_app_ids: Vec::new(),
        }
    }
}

fn default_require_app_id() -> bool {
    false
}

impl ServerConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}
