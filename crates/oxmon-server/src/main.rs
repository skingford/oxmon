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
use oxmon_server::config::{self, SeedFile};
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

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  oxmon-server [config.toml]                           Start the server");
    eprintln!("  oxmon-server init-channels <config.toml> <seed.json> Initialize channels from seed file");
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    oxmon_common::id::init(1, 1);

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("oxmon=info".parse()?))
        .init();

    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("init-channels") => {
            let config_path = args.get(2).ok_or_else(|| {
                print_usage();
                anyhow::anyhow!("init-channels requires <config.toml> and <seed.json> arguments")
            })?;
            let seed_path = args.get(3).ok_or_else(|| {
                print_usage();
                anyhow::anyhow!("init-channels requires <seed.json> argument")
            })?;
            run_init_channels(config_path, seed_path)
        }
        Some("--help" | "-h") => {
            print_usage();
            Ok(())
        }
        _ => {
            let config_path = args
                .get(1)
                .map(|s| s.as_str())
                .unwrap_or("config/server.toml");
            run_server(config_path).await
        }
    }
}

/// Initialize notification channels and silence windows from a JSON seed file.
fn run_init_channels(config_path: &str, seed_path: &str) -> Result<()> {
    use oxmon_storage::cert_store::{NotificationChannelRow, SilenceWindowRow};

    let config = config::ServerConfig::load(config_path)?;
    let cert_store = CertStore::new(Path::new(&config.data_dir))?;

    let seed_content = std::fs::read_to_string(seed_path)
        .map_err(|e| anyhow::anyhow!("Failed to read seed file '{}': {}", seed_path, e))?;
    let seed: SeedFile = serde_json::from_str(&seed_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse seed file '{}': {}", seed_path, e))?;

    let mut channels_created = 0u32;
    let mut channels_skipped = 0u32;
    let mut recipients_set = 0u32;

    // List existing channel names for dedup
    let existing = cert_store.list_notification_channels(10000, 0)?;
    let existing_names: std::collections::HashSet<String> =
        existing.iter().map(|ch| ch.name.clone()).collect();

    for ch in &seed.channels {
        if existing_names.contains(&ch.name) {
            tracing::warn!(name = %ch.name, "Channel already exists, skipping");
            channels_skipped += 1;
            continue;
        }

        let row = NotificationChannelRow {
            id: oxmon_common::id::next_id(),
            name: ch.name.clone(),
            channel_type: ch.channel_type.clone(),
            description: ch.description.clone(),
            min_severity: ch.min_severity.clone(),
            enabled: ch.enabled,
            config_json: ch.config.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        match cert_store.insert_notification_channel(&row) {
            Ok(inserted) => {
                tracing::info!(name = %ch.name, id = %inserted.id, "Channel created");
                channels_created += 1;

                if !ch.recipients.is_empty() {
                    match cert_store.set_channel_recipients(&inserted.id, &ch.recipients) {
                        Ok(recs) => {
                            recipients_set += recs.len() as u32;
                            tracing::info!(
                                channel = %ch.name,
                                count = recs.len(),
                                "Recipients set"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                channel = %ch.name,
                                error = %e,
                                "Failed to set recipients"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(name = %ch.name, error = %e, "Failed to create channel");
            }
        }
    }

    let mut windows_created = 0u32;
    for sw in &seed.silence_windows {
        let row = SilenceWindowRow {
            id: oxmon_common::id::next_id(),
            start_time: sw.start_time.clone(),
            end_time: sw.end_time.clone(),
            recurrence: sw.recurrence.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        match cert_store.insert_silence_window(&row) {
            Ok(_) => {
                windows_created += 1;
                tracing::info!(
                    start = %sw.start_time,
                    end = %sw.end_time,
                    "Silence window created"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to create silence window");
            }
        }
    }

    tracing::info!(
        channels_created,
        channels_skipped,
        recipients_set,
        windows_created,
        "init-channels completed"
    );
    Ok(())
}

async fn run_server(config_path: &str) -> Result<()> {
    let config = config::ServerConfig::load(config_path)?;

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
