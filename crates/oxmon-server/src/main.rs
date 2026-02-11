use anyhow::Result;
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_alert::rules::cert_expiration::CertExpirationRule;
use oxmon_alert::rules::rate_of_change::RateOfChangeRule;
use oxmon_alert::rules::threshold::{CompareOp, ThresholdRule};
use oxmon_alert::rules::trend_prediction::TrendPredictionRule;
use oxmon_alert::AlertRule;
use oxmon_common::proto::metric_service_server::MetricServiceServer;
use oxmon_common::types::Severity;
use oxmon_notify::manager::NotificationManager;
use oxmon_notify::plugin::ChannelRegistry;
use oxmon_storage::cert_store::CertStore;
use oxmon_storage::engine::SqliteStorageEngine;
use oxmon_storage::StorageEngine;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::time::{interval, Duration};
use tonic::transport::Server as TonicServer;
use tracing_subscriber::EnvFilter;

use oxmon_server::app;
use oxmon_server::cert::scheduler::CertCheckScheduler;
use oxmon_server::config;
use oxmon_server::grpc;
use oxmon_server::state::{AgentRegistry, AppState};

fn build_alert_rules(cfg: &[config::AlertRuleConfig]) -> Vec<Box<dyn AlertRule>> {
    let mut rules: Vec<Box<dyn AlertRule>> = Vec::new();
    for r in cfg {
        let severity: Severity = r.severity.parse().unwrap_or(Severity::Info);
        match r.rule_type.as_str() {
            "threshold" => {
                if let (Some(op_str), Some(value), Some(duration)) =
                    (&r.operator, r.value, r.duration_secs)
                {
                    if let Ok(op) = op_str.parse::<CompareOp>() {
                        rules.push(Box::new(ThresholdRule {
                            id: r.name.clone(),
                            metric: r.metric.clone(),
                            agent_pattern: r.agent_pattern.clone(),
                            severity,
                            operator: op,
                            value,
                            duration_secs: duration,
                            silence_secs: r.silence_secs,
                        }));
                    }
                }
            }
            "rate_of_change" => {
                if let (Some(rate), Some(window)) = (r.rate_threshold, r.window_secs) {
                    rules.push(Box::new(RateOfChangeRule {
                        id: r.name.clone(),
                        metric: r.metric.clone(),
                        agent_pattern: r.agent_pattern.clone(),
                        severity,
                        rate_threshold: rate,
                        window_secs: window,
                        silence_secs: r.silence_secs,
                    }));
                }
            }
            "trend_prediction" => {
                if let (Some(thresh), Some(horizon), Some(min_dp)) =
                    (r.predict_threshold, r.horizon_secs, r.min_data_points)
                {
                    rules.push(Box::new(TrendPredictionRule {
                        id: r.name.clone(),
                        metric: r.metric.clone(),
                        agent_pattern: r.agent_pattern.clone(),
                        severity,
                        predict_threshold: thresh,
                        horizon_secs: horizon,
                        min_data_points: min_dp,
                        silence_secs: r.silence_secs,
                    }));
                }
            }
            "cert_expiration" => {
                let warning = r.warning_days.unwrap_or(30);
                let critical = r.critical_days.unwrap_or(7);
                rules.push(Box::new(CertExpirationRule::new(
                    r.name.clone(),
                    warning,
                    critical,
                    r.silence_secs,
                )));
            }
            other => tracing::warn!(rule_type = other, "Unknown alert rule type"),
        }
    }
    rules
}

/// 将 TOML 配置中的通知渠道 / 静默窗口迁移到 DB（仅首次）。
fn migrate_toml_channels_to_db(
    config: &config::ServerConfig,
    cert_store: &CertStore,
) {
    use oxmon_storage::cert_store::{NotificationChannelRow, SilenceWindowRow};

    // 只有当 DB 中没有任何渠道配置时才从 TOML 迁移
    let existing = cert_store.count_notification_channels().unwrap_or(0);
    if existing > 0 {
        return;
    }

    for ch in &config.notification.channels {
        let row = NotificationChannelRow {
            id: oxmon_common::id::next_id(),
            name: ch.channel_type.clone(),
            channel_type: ch.channel_type.clone(),
            description: None,
            min_severity: ch.min_severity.clone(),
            enabled: true,
            config_json: ch.plugin_config.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        if let Err(e) = cert_store.insert_notification_channel(&row) {
            tracing::warn!(channel = %ch.channel_type, error = %e, "Failed to migrate TOML channel to DB");
        } else {
            tracing::info!(channel = %ch.channel_type, id = %row.id, "Migrated TOML channel config to DB");
        }
    }

    for sw in &config.notification.silence_windows {
        let row = SilenceWindowRow {
            id: oxmon_common::id::next_id(),
            start_time: sw.start_time.clone(),
            end_time: sw.end_time.clone(),
            recurrence: sw.recurrence.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        if let Err(e) = cert_store.insert_silence_window(&row) {
            tracing::warn!(error = %e, "Failed to migrate TOML silence window to DB");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    // 初始化 Snowflake ID 生成器 (machine_id=1, node_id=1)
    oxmon_common::id::init(1, 1);

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("oxmon=info".parse()?))
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config/server.toml".to_string());

    let config = config::ServerConfig::load(&config_path)?;
    tracing::info!(
        grpc_port = config.grpc_port,
        http_port = config.http_port,
        data_dir = %config.data_dir,
        "oxmon-server starting"
    );

    // Build components
    let storage = Arc::new(SqliteStorageEngine::new(Path::new(&config.data_dir))?);
    let rules = build_alert_rules(&config.alert.rules);
    let alert_engine = Arc::new(Mutex::new(AlertEngine::new(rules)));
    let agent_registry = Arc::new(Mutex::new(AgentRegistry::new(30)));
    let cert_store = Arc::new(CertStore::new(Path::new(&config.data_dir))?);

    // Migrate TOML channel configs to DB (first-time only)
    migrate_toml_channels_to_db(&config, &cert_store);

    // Build notification manager backed by DB
    let registry = ChannelRegistry::default();
    let notifier = Arc::new(NotificationManager::new(
        registry,
        cert_store.clone(),
        config.notification.aggregation_window_secs,
    ));

    // Load channels from DB
    if let Err(e) = notifier.reload().await {
        tracing::error!(error = %e, "Failed to load notification channels from DB");
    }

    // JWT secret: use configured value or generate random
    let jwt_secret = match &config.auth.jwt_secret {
        Some(secret) => Arc::new(secret.clone()),
        None => {
            let secret = oxmon_storage::auth::generate_token();
            tracing::warn!("No jwt_secret configured. A random secret was generated and will change on restart. Set [auth].jwt_secret in config for production use.");
            Arc::new(secret)
        }
    };

    // Default admin account: create if users table is empty
    match cert_store.count_users() {
        Ok(0) => {
            let password_hash = oxmon_storage::auth::hash_token(&config.auth.default_password)?;
            match cert_store.create_user(&config.auth.default_username, &password_hash) {
                Ok(_) => {
                    tracing::info!(
                        username = %config.auth.default_username,
                        "Created default admin account"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to create default admin account");
                }
            }
        }
        Ok(count) => {
            tracing::info!(
                count,
                "Users table already has accounts, skipping default admin creation"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check users table");
        }
    }

    let state = AppState {
        storage: storage.clone(),
        alert_engine,
        notifier,
        agent_registry,
        cert_store: cert_store.clone(),
        connect_timeout_secs: config.cert_check.connect_timeout_secs,
        start_time: Utc::now(),
        jwt_secret,
        token_expire_secs: config.auth.token_expire_secs,
        config: Arc::new(config.clone()),
    };

    // gRPC server
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", config.grpc_port).parse()?;
    let grpc_service = MetricServiceServer::new(grpc::MetricServiceImpl::new(
        state.clone(),
        config.require_agent_auth,
    ));
    let grpc_server = TonicServer::builder()
        .add_service(grpc_service)
        .serve(grpc_addr);

    // HTTP/REST server
    let http_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse()?;
    let app = app::build_http_app(state.clone());
    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    let http_server = axum::serve(http_listener, app);

    // Periodic cleanup task
    let retention_days = config.retention_days;
    let cleanup_storage = storage.clone();
    let cleanup_handle = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(3600)); // Every hour
        loop {
            tick.tick().await;
            match cleanup_storage.cleanup(retention_days) {
                Ok(removed) if removed > 0 => {
                    tracing::info!(removed, "Cleaned up expired partitions")
                }
                Err(e) => tracing::error!(error = %e, "Cleanup failed"),
                _ => {}
            }
        }
    });

    // Cert check scheduler
    let cert_check_handle = if config.cert_check.enabled {
        let scheduler = CertCheckScheduler::new(
            cert_store,
            storage.clone(),
            config.cert_check.default_interval_secs,
            config.cert_check.tick_secs,
            config.cert_check.connect_timeout_secs,
            config.cert_check.max_concurrent,
        );
        Some(tokio::spawn(async move {
            scheduler.run().await;
        }))
    } else {
        tracing::info!("Certificate check scheduler disabled");
        None
    };

    tracing::info!(grpc = %grpc_addr, http = %http_addr, "Server started");

    // Run all services concurrently
    tokio::select! {
        result = grpc_server => {
            if let Err(e) = result {
                tracing::error!(error = %e, "gRPC server error");
            }
        }
        result = http_server.with_graceful_shutdown(async { signal::ctrl_c().await.ok(); }) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HTTP server error");
            }
        }
        _ = signal::ctrl_c() => {
            tracing::info!("Shutting down gracefully");
        }
    }

    cleanup_handle.abort();
    if let Some(h) = cert_check_handle {
        h.abort();
    }
    tracing::info!("Server stopped");

    Ok(())
}
