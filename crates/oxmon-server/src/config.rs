use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    #[serde(default)]
    pub alert: AlertConfig,
    #[serde(default)]
    pub notification: NotificationConfig,
    #[serde(default)]
    pub cert_check: CertCheckConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct AlertConfig {
    #[serde(default)]
    pub rules: Vec<AlertRuleConfig>,
}

#[derive(Debug, Deserialize)]
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

    #[serde(default = "default_silence_secs")]
    pub silence_secs: u64,
}

#[derive(Debug, Default, Deserialize)]
pub struct NotificationConfig {
    #[serde(default)]
    pub channels: Vec<ChannelConfig>,
    #[serde(default)]
    pub silence_windows: Vec<SilenceWindowConfig>,
    #[serde(default = "default_aggregation_window_secs")]
    pub aggregation_window_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct ChannelConfig {
    #[serde(rename = "type")]
    pub channel_type: String,
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    // Email fields
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub from: Option<String>,
    pub recipients: Option<Vec<String>>,

    // Webhook fields
    pub url: Option<String>,
    pub body_template: Option<String>,

    // SMS fields
    pub gateway_url: Option<String>,
    pub api_key: Option<String>,
    pub phone_numbers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct SilenceWindowConfig {
    pub start_time: String,
    pub end_time: String,
    pub recurrence: Option<String>,
}

#[derive(Debug, Deserialize)]
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

fn default_min_severity() -> String {
    "info".to_string()
}

fn default_aggregation_window_secs() -> u64 {
    60
}

impl ServerConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
}
