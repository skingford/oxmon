mod api;
mod auth;
mod cert;
mod config;
mod grpc;
mod openapi;
mod state;

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
use oxmon_notify::manager::{NotificationManager, SilenceWindow};
use oxmon_notify::plugin::ChannelRegistry;
use oxmon_notify::routing::ChannelRoute;
use oxmon_notify::NotificationChannel;
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
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use tower_http::cors::{Any, CorsLayer};
use axum::middleware;

use crate::state::{AgentRegistry, AppState};

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

fn build_notification_channels(
    cfg: &[config::ChannelConfig],
) -> (Vec<Box<dyn NotificationChannel>>, Vec<ChannelRoute>) {
    let registry = ChannelRegistry::default();
    let mut channels: Vec<Box<dyn NotificationChannel>> = Vec::new();
    let mut routes: Vec<ChannelRoute> = Vec::new();

    for ch in cfg {
        let severity: Severity = ch.min_severity.parse().unwrap_or(Severity::Info);
        match registry.create_channel(&ch.channel_type, &ch.plugin_config) {
            Ok(channel) => {
                let idx = channels.len();
                channels.push(channel);
                routes.push(ChannelRoute {
                    min_severity: severity,
                    channel_index: idx,
                });
            }
            Err(e) => {
                tracing::error!(
                    channel_type = %ch.channel_type,
                    error = %e,
                    "Failed to create notification channel"
                );
            }
        }
    }

    (channels, routes)
}

fn build_silence_windows(cfg: &[config::SilenceWindowConfig]) -> Vec<SilenceWindow> {
    cfg.iter()
        .filter_map(|sw| {
            let start = chrono::NaiveTime::parse_from_str(&sw.start_time, "%H:%M").ok()?;
            let end = chrono::NaiveTime::parse_from_str(&sw.end_time, "%H:%M").ok()?;
            Some(SilenceWindow {
                start,
                end,
                recurrence: sw.recurrence.clone(),
            })
        })
        .collect()
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
    let (channels, routes) = build_notification_channels(&config.notification.channels);
    let silence_windows = build_silence_windows(&config.notification.silence_windows);
    let notifier = Arc::new(NotificationManager::new(
        channels,
        routes,
        silence_windows,
        config.notification.aggregation_window_secs,
    ));
    let agent_registry = Arc::new(Mutex::new(AgentRegistry::new(30)));
    let cert_store = Arc::new(CertStore::new(Path::new(&config.data_dir))?);

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
            tracing::info!(count, "Users table already has accounts, skipping default admin creation");
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
    };

    // gRPC server
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", config.grpc_port).parse()?;
    let grpc_service = MetricServiceServer::new(
        grpc::MetricServiceImpl::new(state.clone(), config.require_agent_auth)
    );
    let grpc_server = TonicServer::builder()
        .add_service(grpc_service)
        .serve(grpc_addr);

    // HTTP/REST server
    let http_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse()?;

    #[derive(OpenApi)]
    #[openapi(
        info(
            title = "oxmon API",
            description = "oxmon 服务器监控 REST API",
        ),
        tags(
            (name = "Health", description = "服务健康检查"),
            (name = "Auth", description = "认证鉴权"),
            (name = "Agents", description = "Agent 管理"),
            (name = "Metrics", description = "指标查询"),
            (name = "Alerts", description = "告警规则与历史"),
            (name = "Certificates", description = "证书监控")
        ),
        modifiers(&SecurityAddon)
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl utoipa::Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            if let Some(components) = openapi.components.as_mut() {
                components.add_security_scheme(
                    "bearer_auth",
                    utoipa::openapi::security::SecurityScheme::Http(
                        utoipa::openapi::security::Http::new(
                            utoipa::openapi::security::HttpAuthScheme::Bearer,
                        ),
                    ),
                );
            }
        }
    }

    // Public routes (no auth required): health + login
    let (public_router, public_spec) = api::public_routes()
        .split_for_parts();

    // Login route
    let (login_router, login_spec) = api::auth_routes()
        .split_for_parts();

    // Protected routes (JWT auth required)
    let (protected_router, protected_spec) = api::protected_routes()
        .split_for_parts();

    let (cert_router, cert_spec) = cert::api::cert_routes()
        .split_for_parts();

    let mut merged_spec = ApiDoc::openapi();
    merged_spec.merge(public_spec);
    merged_spec.merge(login_spec);
    merged_spec.merge(protected_spec);
    merged_spec.merge(cert_spec);
    let spec = Arc::new(merged_spec.clone());

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = public_router
        .merge(login_router)
        .merge(
            protected_router
                .merge(cert_router)
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth::jwt_auth_middleware,
                ))
        )
        .with_state(state.clone())
        .merge(SwaggerUi::new("/docs").url("/v1/openapi.json", merged_spec))
        .merge(openapi::yaml_route(spec))
        .layer(cors);
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
        let scheduler = cert::scheduler::CertCheckScheduler::new(
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
