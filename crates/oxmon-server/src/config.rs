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

    #[serde(default)]
    pub alert: AlertConfig,
    #[serde(default)]
    pub notification: NotificationConfig,
    #[serde(default)]
    pub cert_check: CertCheckConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertConfig {
    #[serde(default)]
    pub rules: Vec<AlertRuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub metric: String,
    #[serde(default = "default_agent_pattern")]
    pub agent_pattern: String,
    pub severity: String,

    // Threshold rule fields
    pub operator: Option<String>,
    pub value: Option<f64>,
    pub duration_secs: Option<u64>,

    // Rate-of-change fields
    pub rate_threshold: Option<f64>,
    pub window_secs: Option<u64>,

    // Trend prediction fields
    pub predict_threshold: Option<f64>,
    pub horizon_secs: Option<u64>,
    pub min_data_points: Option<usize>,

    // Cert expiration fields
    pub warning_days: Option<i64>,
    pub critical_days: Option<i64>,

    #[serde(default = "default_silence_secs")]
    pub silence_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationConfig {
    #[serde(default = "default_aggregation_window_secs")]
    pub aggregation_window_secs: u64,
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

fn default_aggregation_window_secs() -> u64 {
    60
}

fn default_require_agent_auth() -> bool {
    false
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

impl ServerConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}
