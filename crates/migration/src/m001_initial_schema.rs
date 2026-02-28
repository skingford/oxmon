use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m001_initial_schema"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 按依赖顺序建表
        manager.get_connection().execute_unprepared(UP_SQL).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(DOWN_SQL)
            .await?;
        Ok(())
    }
}

const UP_SQL: &str = "
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL UNIQUE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    collection_interval_secs INTEGER,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen DESC);

CREATE TABLE IF NOT EXISTS agent_whitelist (
    id TEXT PRIMARY KEY NOT NULL,
    agent_id TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    encrypted_token TEXT,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cert_domains (
    id TEXT PRIMARY KEY NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    port INTEGER NOT NULL DEFAULT 443,
    enabled INTEGER NOT NULL DEFAULT 1,
    check_interval_secs INTEGER,
    note TEXT,
    last_checked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_domains_domain ON cert_domains(domain);
CREATE INDEX IF NOT EXISTS idx_cert_domains_enabled ON cert_domains(enabled);

CREATE TABLE IF NOT EXISTS cert_check_results (
    id TEXT PRIMARY KEY NOT NULL,
    domain_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    is_valid INTEGER NOT NULL DEFAULT 0,
    chain_valid INTEGER NOT NULL DEFAULT 0,
    not_before TEXT,
    not_after TEXT,
    days_until_expiry INTEGER,
    issuer TEXT,
    subject TEXT,
    san_list TEXT,
    resolved_ips TEXT,
    error TEXT,
    checked_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_results_domain_id ON cert_check_results(domain_id);
CREATE INDEX IF NOT EXISTS idx_cert_results_checked_at ON cert_check_results(checked_at);
CREATE INDEX IF NOT EXISTS idx_cert_results_domain ON cert_check_results(domain);

CREATE TABLE IF NOT EXISTS certificate_details (
    id TEXT PRIMARY KEY NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    ip_addresses TEXT NOT NULL,
    issuer_cn TEXT,
    issuer_o TEXT,
    issuer_ou TEXT,
    issuer_c TEXT,
    subject_alt_names TEXT,
    chain_valid INTEGER NOT NULL DEFAULT 0,
    chain_error TEXT,
    last_checked TEXT NOT NULL,
    serial_number TEXT,
    fingerprint_sha256 TEXT,
    version INTEGER,
    signature_algorithm TEXT,
    public_key_algorithm TEXT,
    public_key_bits INTEGER,
    subject_cn TEXT,
    subject_o TEXT,
    key_usage TEXT,
    extended_key_usage TEXT,
    is_ca INTEGER,
    is_wildcard INTEGER,
    ocsp_urls TEXT,
    crl_urls TEXT,
    ca_issuer_urls TEXT,
    sct_count INTEGER,
    tls_version TEXT,
    cipher_suite TEXT,
    chain_depth INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_details_not_after ON certificate_details(not_after);
CREATE INDEX IF NOT EXISTS idx_cert_details_domain ON certificate_details(domain);

CREATE TABLE IF NOT EXISTS alert_rules (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    rule_type TEXT NOT NULL,
    metric TEXT NOT NULL,
    agent_pattern TEXT NOT NULL DEFAULT '*',
    severity TEXT NOT NULL DEFAULT 'info',
    enabled INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL DEFAULT '{}',
    silence_secs INTEGER NOT NULL DEFAULT 600,
    source TEXT NOT NULL DEFAULT 'api',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_name ON alert_rules(name);
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);

CREATE TABLE IF NOT EXISTS system_configs (
    id TEXT PRIMARY KEY NOT NULL,
    config_key TEXT NOT NULL UNIQUE,
    config_type TEXT NOT NULL,
    provider TEXT,
    display_name TEXT NOT NULL,
    description TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_channels (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    channel_type TEXT NOT NULL,
    description TEXT,
    min_severity TEXT NOT NULL DEFAULT 'info',
    enabled INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL DEFAULT '{}',
    system_config_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_recipients (
    id TEXT PRIMARY KEY NOT NULL,
    channel_id TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notif_recipients_channel ON notification_recipients(channel_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_recipients_uniq ON notification_recipients(channel_id, value);

CREATE TABLE IF NOT EXISTS notification_silence_windows (
    id TEXT PRIMARY KEY NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    recurrence TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_logs (
    id TEXT PRIMARY KEY NOT NULL,
    alert_event_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    channel_name TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    recipient_count INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'info',
    http_status_code INTEGER,
    response_body TEXT,
    request_body TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    recipient_details TEXT,
    api_message_id TEXT,
    api_error_code TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notif_logs_created_at ON notification_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_notif_logs_channel_id ON notification_logs(channel_id);
CREATE INDEX IF NOT EXISTS idx_notif_logs_status ON notification_logs(status);
CREATE INDEX IF NOT EXISTS idx_notif_logs_alert_event ON notification_logs(alert_event_id);

CREATE TABLE IF NOT EXISTS system_dictionaries (
    id TEXT PRIMARY KEY NOT NULL,
    dict_type TEXT NOT NULL,
    dict_key TEXT NOT NULL,
    dict_label TEXT NOT NULL,
    dict_value TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    is_system INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    extra_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dict_type_key ON system_dictionaries(dict_type, dict_key);
CREATE INDEX IF NOT EXISTS idx_dict_type ON system_dictionaries(dict_type);
CREATE INDEX IF NOT EXISTS idx_dict_enabled ON system_dictionaries(enabled);

CREATE TABLE IF NOT EXISTS dictionary_types (
    dict_type TEXT PRIMARY KEY NOT NULL,
    dict_type_label TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_accounts (
    id TEXT PRIMARY KEY NOT NULL,
    config_key TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    api_key TEXT NOT NULL,
    api_secret TEXT,
    model TEXT,
    extra_config TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_accounts_provider ON ai_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_ai_accounts_enabled ON ai_accounts(enabled);

CREATE TABLE IF NOT EXISTS ai_reports (
    id TEXT PRIMARY KEY NOT NULL,
    report_date TEXT NOT NULL UNIQUE,
    ai_account_id TEXT NOT NULL,
    ai_provider TEXT NOT NULL,
    ai_model TEXT NOT NULL,
    total_agents INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL,
    ai_analysis TEXT NOT NULL,
    html_content TEXT NOT NULL,
    raw_metrics_json TEXT NOT NULL,
    notified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_reports_date ON ai_reports(report_date);
CREATE INDEX IF NOT EXISTS idx_ai_reports_provider ON ai_reports(ai_provider);
CREATE INDEX IF NOT EXISTS idx_ai_reports_account ON ai_reports(ai_account_id);

CREATE TABLE IF NOT EXISTS cloud_accounts (
    id TEXT PRIMARY KEY NOT NULL,
    config_key TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    account_name TEXT NOT NULL DEFAULT '',
    secret_id TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    regions TEXT NOT NULL DEFAULT '[]',
    collection_interval_secs INTEGER NOT NULL DEFAULT 3600,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider ON cloud_accounts(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_enabled ON cloud_accounts(enabled);

CREATE TABLE IF NOT EXISTS cloud_instances (
    id TEXT PRIMARY KEY NOT NULL,
    instance_id TEXT NOT NULL,
    instance_name TEXT,
    provider TEXT NOT NULL,
    account_config_key TEXT NOT NULL,
    region TEXT NOT NULL,
    public_ip TEXT,
    private_ip TEXT,
    os TEXT,
    status TEXT,
    instance_type TEXT,
    cpu_cores INTEGER,
    memory_gb REAL,
    disk_gb REAL,
    created_time TEXT,
    expired_time TEXT,
    charge_type TEXT,
    vpc_id TEXT,
    subnet_id TEXT,
    security_group_ids TEXT,
    zone TEXT,
    internet_max_bandwidth INTEGER,
    ipv6_addresses TEXT,
    eip_allocation_id TEXT,
    internet_charge_type TEXT,
    image_id TEXT,
    hostname TEXT,
    description TEXT,
    gpu INTEGER,
    io_optimized TEXT,
    latest_operation TEXT,
    latest_operation_state TEXT,
    tags TEXT,
    project_id TEXT,
    resource_group_id TEXT,
    auto_renew_flag INTEGER,
    last_seen_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(provider, instance_id)
);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_provider ON cloud_instances(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_region ON cloud_instances(region);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_account_key ON cloud_instances(account_config_key);

CREATE TABLE IF NOT EXISTS cloud_collection_state (
    config_key TEXT PRIMARY KEY NOT NULL,
    last_collected_at TEXT NOT NULL,
    last_instance_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    updated_at TEXT NOT NULL
);
";

const DOWN_SQL: &str = "
DROP TABLE IF EXISTS cloud_collection_state;
DROP TABLE IF EXISTS cloud_instances;
DROP TABLE IF EXISTS cloud_accounts;
DROP TABLE IF EXISTS ai_reports;
DROP TABLE IF EXISTS ai_accounts;
DROP TABLE IF EXISTS dictionary_types;
DROP TABLE IF EXISTS system_dictionaries;
DROP TABLE IF EXISTS notification_logs;
DROP TABLE IF EXISTS notification_silence_windows;
DROP TABLE IF EXISTS notification_recipients;
DROP TABLE IF EXISTS notification_channels;
DROP TABLE IF EXISTS system_configs;
DROP TABLE IF EXISTS alert_rules;
DROP TABLE IF EXISTS certificate_details;
DROP TABLE IF EXISTS cert_check_results;
DROP TABLE IF EXISTS cert_domains;
DROP TABLE IF EXISTS agent_whitelist;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS users;
";
