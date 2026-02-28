use anyhow::Result;
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_common::proto::metric_service_server::MetricServiceServer;
use oxmon_notify::manager::NotificationManager;
use oxmon_notify::plugin::ChannelRegistry;
use oxmon_storage::engine::SqliteStorageEngine;
use oxmon_storage::StorageEngine;
use oxmon_storage::{AlertRuleRow, CertStore};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::time::{interval, Duration};
use tonic::transport::Server as TonicServer;
use tracing_subscriber::EnvFilter;

use oxmon_server::ai::scheduler::AIReportScheduler;
use oxmon_server::app;
use oxmon_server::cert::scheduler::CertCheckScheduler;
use oxmon_server::channel_seed;
use oxmon_server::cloud::scheduler::CloudCheckScheduler;
use oxmon_server::config::{self, SeedFile};
use oxmon_server::grpc;
use oxmon_server::rule_builder;
use oxmon_server::rule_seed;
use oxmon_server::runtime_seed;
use oxmon_server::state::{AgentRegistry, AppState};

#[allow(clippy::print_stderr)]
fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  oxmon-server [config.toml]                                     Start the server");
    eprintln!("  oxmon-server init-channels <config.toml> <seed.json>          Initialize channels from seed file");
    eprintln!("  oxmon-server init-rules <config.toml> <seed.json>             Initialize alert rules from seed file");
    eprintln!("  oxmon-server init-dictionaries <config.toml> [seed.json]      Initialize dictionaries (system defaults when seed omitted)");
    eprintln!("  oxmon-server init-configs <config.toml> <seed.json>           Initialize/update system configs (runtime settings, etc.)");
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| anyhow::anyhow!("Failed to install default CryptoProvider: {e:?}"))?;

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
            run_init_channels(config_path, seed_path).await
        }
        Some("init-rules") => {
            let config_path = args.get(2).ok_or_else(|| {
                print_usage();
                anyhow::anyhow!("init-rules requires <config.toml> and <seed.json> arguments")
            })?;
            let seed_path = args.get(3).ok_or_else(|| {
                print_usage();
                anyhow::anyhow!("init-rules requires <seed.json> argument")
            })?;
            run_init_rules(config_path, seed_path).await
        }
        Some("init-dictionaries") => {
            let config_path = args.get(2).ok_or_else(|| {
                print_usage();
                anyhow::anyhow!("init-dictionaries requires <config.toml> argument")
            })?;
            run_init_dictionaries(config_path, args.get(3).map(String::as_str)).await
        }
        Some("init-configs") => {
            let config_path = args.get(2).ok_or_else(|| {
                print_usage();
                anyhow::anyhow!("init-configs requires <config.toml> and <seed.json> arguments")
            })?;
            let seed_path = args.get(3).ok_or_else(|| {
                print_usage();
                anyhow::anyhow!("init-configs requires <seed.json> argument")
            })?;
            run_init_configs(config_path, seed_path).await
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
async fn run_init_channels(config_path: &str, seed_path: &str) -> Result<()> {
    use oxmon_storage::{NotificationChannelFilter, NotificationChannelRow, SilenceWindowRow};

    let config = config::ServerConfig::load(config_path)?;
    let db_url = config.database.connection_url();
    let cert_store = CertStore::new(&db_url, Path::new(&config.database.data_dir)).await?;

    let seed_content = std::fs::read_to_string(seed_path)
        .map_err(|e| anyhow::anyhow!("Failed to read seed file '{}': {}", seed_path, e))?;
    let seed: SeedFile = serde_json::from_str(&seed_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse seed file '{}': {}", seed_path, e))?;

    let mut channels_created = 0u32;
    let mut channels_skipped = 0u32;
    let mut recipients_set = 0u32;

    // List existing channel names for dedup
    let existing = cert_store
        .list_notification_channels(
            &NotificationChannelFilter {
                name_contains: None,
                channel_type_eq: None,
                enabled_eq: None,
                min_severity_eq: None,
            },
            10000,
            0,
        )
        .await?;
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

        match cert_store.insert_notification_channel(&row).await {
            Ok(inserted) => {
                tracing::info!(name = %ch.name, id = %inserted.id, "Channel created");
                channels_created += 1;

                if !ch.recipients.is_empty() {
                    match cert_store
                        .set_channel_recipients(&inserted.id, &ch.recipients)
                        .await
                    {
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
        match cert_store.insert_silence_window(&row).await {
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

/// Initialize alert rules from a JSON seed file.
async fn run_init_rules(config_path: &str, seed_path: &str) -> Result<()> {
    let config = config::ServerConfig::load(config_path)?;
    let db_url = config.database.connection_url();
    let cert_store = CertStore::new(&db_url, Path::new(&config.database.data_dir)).await?;

    let seed_content = std::fs::read_to_string(seed_path)
        .map_err(|e| anyhow::anyhow!("Failed to read seed file '{}': {}", seed_path, e))?;
    let seed: config::RulesSeedFile = serde_json::from_str(&seed_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse seed file '{}': {}", seed_path, e))?;

    // List existing rule names for dedup
    let existing = cert_store.list_alert_rules(None, None, 10000, 0).await?;
    let existing_names: std::collections::HashSet<String> =
        existing.iter().map(|r| r.name.clone()).collect();

    let mut created = 0u32;
    let mut skipped = 0u32;

    for r in &seed.rules {
        if existing_names.contains(&r.name) {
            tracing::warn!(name = %r.name, "Alert rule already exists, skipping");
            skipped += 1;
            continue;
        }

        let row = AlertRuleRow {
            id: oxmon_common::id::next_id(),
            name: r.name.clone(),
            rule_type: r.rule_type.clone(),
            metric: r.metric.clone(),
            agent_pattern: r.agent_pattern.clone(),
            severity: r.severity.clone(),
            enabled: r.enabled,
            config_json: r.config.to_string(),
            silence_secs: r.silence_secs as i64,
            source: "seed".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        match cert_store.insert_alert_rule(&row).await {
            Ok(inserted) => {
                tracing::info!(name = %r.name, id = %inserted.id, "Alert rule created");
                created += 1;
            }
            Err(e) => {
                tracing::error!(name = %r.name, error = %e, "Failed to create alert rule");
            }
        }
    }

    tracing::info!(created, skipped, "init-rules completed");
    Ok(())
}

/// Initialize dictionaries.
/// - With `seed_path`: import dictionaries from JSON seed file
/// - Without `seed_path`: sync built-in system dictionaries
async fn run_init_dictionaries(config_path: &str, seed_path: Option<&str>) -> Result<()> {
    let config = config::ServerConfig::load(config_path)?;
    let db_url = config.database.connection_url();
    let cert_store = CertStore::new(&db_url, Path::new(&config.database.data_dir)).await?;
    if let Some(path) = seed_path {
        oxmon_server::dictionary_seed::init_from_seed_file(&cert_store, path).await?;
    } else {
        oxmon_server::dictionary_seed::init_default_dictionaries(&cert_store).await?;
    }
    Ok(())
}

/// Initialize system configs from a JSON seed file.
/// If a config already exists, it will be updated with the seed data.
async fn run_init_configs(config_path: &str, seed_path: &str) -> Result<()> {
    use oxmon_storage::SystemConfigRow;

    let config = config::ServerConfig::load(config_path)?;
    let db_url = config.database.connection_url();
    let cert_store = CertStore::new(&db_url, Path::new(&config.database.data_dir)).await?;

    let seed_content = std::fs::read_to_string(seed_path)
        .map_err(|e| anyhow::anyhow!("Failed to read seed file '{}': {}", seed_path, e))?;
    let seed: config::SystemConfigsSeedFile = serde_json::from_str(&seed_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse seed file '{}': {}", seed_path, e))?;

    // List existing configs by key
    let existing = cert_store.list_system_configs(None, None, 10000, 0).await?;
    let mut existing_map: std::collections::HashMap<String, SystemConfigRow> = existing
        .into_iter()
        .map(|c| (c.config_key.clone(), c))
        .collect();

    let mut created = 0u32;
    let mut updated = 0u32;

    for sc in &seed.configs {
        if let Some(existing_row) = existing_map.remove(&sc.config_key) {
            // Update existing config
            let config_json_str = sc.config.to_string();
            match cert_store
                .update_system_config(
                    &existing_row.id,
                    sc.description.as_deref(),
                    Some(sc.enabled),
                    Some(config_json_str.as_str()),
                )
                .await
            {
                Ok(_) => {
                    tracing::info!(
                        config_key = %sc.config_key,
                        id = %existing_row.id,
                        "System config updated"
                    );
                    updated += 1;
                }
                Err(e) => {
                    tracing::error!(
                        config_key = %sc.config_key,
                        error = %e,
                        "Failed to update system config"
                    );
                }
            }
        } else {
            // Create new config
            let row = SystemConfigRow {
                id: oxmon_common::id::next_id(),
                config_key: sc.config_key.clone(),
                config_type: sc.config_type.clone(),
                provider: sc.provider.clone(),
                display_name: sc.display_name.clone(),
                description: sc.description.clone(),
                config_json: sc.config.to_string(),
                enabled: sc.enabled,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            match cert_store.insert_system_config(&row).await {
                Ok(inserted) => {
                    tracing::info!(
                        config_key = %sc.config_key,
                        id = %inserted.id,
                        "System config created"
                    );
                    created += 1;
                }
                Err(e) => {
                    tracing::error!(
                        config_key = %sc.config_key,
                        error = %e,
                        "Failed to create system config"
                    );
                }
            }
        }
    }

    tracing::info!(created, updated, "init-configs completed");
    Ok(())
}

/// Initialize cloud accounts from a JSON seed file.
async fn run_server(config_path: &str) -> Result<()> {
    let config = config::ServerConfig::load(config_path)?;

    tracing::info!(
        grpc_port = config.grpc_port,
        http_port = config.http_port,
        data_dir = %config.database.data_dir,
        db = %config.database.redacted_url(),
        "oxmon-server starting"
    );

    // Build components
    let storage = Arc::new(SqliteStorageEngine::new(Path::new(
        &config.database.data_dir,
    ))?);
    let db_url = config.database.connection_url();
    let cert_store = Arc::new(CertStore::new(&db_url, Path::new(&config.database.data_dir)).await?);
    let agent_registry = Arc::new(Mutex::new(AgentRegistry::new(
        config.agent_collection_interval_secs,
    )));

    // Sync built-in system dictionaries first so other seeds can depend on dictionary metadata.
    if let Err(e) = oxmon_server::dictionary_seed::init_default_dictionaries(&cert_store).await {
        tracing::error!(error = %e, "Failed to initialize default system dictionaries");
    }

    // Seed default alert rules (only when DB has none)
    if let Err(e) = rule_seed::init_default_rules(&cert_store).await {
        tracing::error!(error = %e, "Failed to initialize default alert rules");
    }

    // Load alert engine from DB
    let alert_engine = Arc::new(Mutex::new(AlertEngine::new(vec![])));
    if let Err(e) = rule_builder::reload_alert_engine(&cert_store, &alert_engine).await {
        tracing::error!(error = %e, "Failed to load alert rules from DB");
    }

    // Seed default notification channels (only when DB has none, all disabled)
    if let Err(e) = channel_seed::init_default_channels(&cert_store).await {
        tracing::error!(error = %e, "Failed to initialize default notification channels");
    }

    // Seed default runtime settings (notification aggregation window, log retention days)
    if let Err(e) = runtime_seed::init_default_runtime_settings(&cert_store).await {
        tracing::error!(error = %e, "Failed to initialize default runtime settings");
    }

    // Build notification manager backed by DB
    let registry = ChannelRegistry::default();
    let aggregation_window_secs = cert_store
        .get_runtime_setting_u64("notification_aggregation_window", 60)
        .await;
    let notifier = Arc::new(NotificationManager::new(
        registry,
        cert_store.clone(),
        aggregation_window_secs,
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

    // Initialize password encryptor (RSA key pair for login/change-password)
    let password_encryptor = Arc::new(oxmon_storage::auth::PasswordEncryptor::load_or_create(
        Path::new(&config.database.data_dir),
    )?);

    // Default admin account: create if users table is empty
    match cert_store.count_users().await {
        Ok(0) => {
            let password_hash = oxmon_storage::auth::hash_token(&config.auth.default_password)?;
            match cert_store
                .create_user(&config.auth.default_username, &password_hash)
                .await
            {
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

    // One-time self-heal on startup: backfill monitored domains from existing certificate details.
    if config.cert_check.auto_backfill_domains_on_startup {
        match cert_store
            .sync_missing_monitored_domains_from_certificate_details()
            .await
        {
            Ok(inserted) => {
                tracing::info!(
                    inserted,
                    "Startup backfill of monitored domains from existing certificate details finished"
                );
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed to backfill monitored domains from certificate details on startup"
                );
            }
        }
    } else {
        tracing::info!("Startup backfill of monitored domains from certificate details disabled");
    }

    let state = AppState {
        storage: storage.clone(),
        alert_engine,
        notifier: notifier.clone(),
        agent_registry,
        cert_store: cert_store.clone(),
        connect_timeout_secs: config.cert_check.connect_timeout_secs,
        start_time: Utc::now(),
        jwt_secret,
        token_expire_secs: config.auth.token_expire_secs,
        password_encryptor,
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
    let http_server = axum::serve(
        http_listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );

    // Periodic cleanup task
    let retention_days = config.retention_days;
    let cleanup_storage = storage.clone();
    let cleanup_cert_store = cert_store.clone();
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
            // Read log_retention_days from DB each time to allow dynamic updates
            let log_retention_days = cleanup_cert_store
                .get_runtime_setting_u32("notification_log_retention", 30)
                .await;
            match cleanup_cert_store
                .cleanup_notification_logs(log_retention_days)
                .await
            {
                Ok(removed) if removed > 0 => {
                    tracing::info!(removed, "Cleaned up expired notification logs")
                }
                Err(e) => tracing::error!(error = %e, "Notification log cleanup failed"),
                _ => {}
            }
        }
    });

    // Cert check scheduler
    let cert_check_handle = if config.cert_check.enabled {
        let scheduler = CertCheckScheduler::new(
            cert_store.clone(),
            storage.clone(),
            state.alert_engine.clone(),
            notifier.clone(),
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

    // Cloud metrics scheduler
    let cloud_check_handle = if config.cloud_check.enabled {
        let scheduler = CloudCheckScheduler::new(
            cert_store.clone(),
            storage.clone(),
            state.alert_engine.clone(),
            notifier.clone(),
            config.cloud_check.default_account_collection_interval_secs,
            config.cloud_check.tick_secs,
            config.cloud_check.max_concurrent,
        );
        Some(tokio::spawn(async move {
            scheduler.run().await;
        }))
    } else {
        tracing::info!("Cloud metrics scheduler disabled");
        None
    };

    // AI report scheduler
    let ai_check_handle = if config.ai_check.enabled {
        let scheduler = Arc::new(AIReportScheduler::new(
            storage.clone(),
            cert_store.clone(),
            notifier.clone(),
            Duration::from_secs(config.ai_check.tick_secs),
            config.ai_check.history_days,
        ));
        Some(tokio::spawn(async move {
            scheduler.start().await;
        }))
    } else {
        tracing::info!("AI report scheduler disabled");
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
    if let Some(h) = cloud_check_handle {
        h.abort();
    }
    if let Some(h) = ai_check_handle {
        h.abort();
    }
    tracing::info!("Server stopped");

    Ok(())
}
