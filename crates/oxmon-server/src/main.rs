mod api;
mod cert;
mod config;
mod grpc;
mod openapi;
mod state;

use anyhow::Result;
use chrono::Utc;
use oxmon_alert::engine::AlertEngine;
use oxmon_alert::rules::rate_of_change::RateOfChangeRule;
use oxmon_alert::rules::threshold::{CompareOp, ThresholdRule};
use oxmon_alert::rules::trend_prediction::TrendPredictionRule;
use oxmon_alert::AlertRule;
use oxmon_common::proto::metric_service_server::MetricServiceServer;
use oxmon_common::types::Severity;
use oxmon_notify::channels::email::EmailChannel;
use oxmon_notify::channels::sms::SmsChannel;
use oxmon_notify::channels::webhook::WebhookChannel;
use oxmon_notify::manager::{NotificationManager, SilenceWindow};
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
                    if let Some(op) = CompareOp::from_str(op_str) {
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
            other => tracing::warn!(rule_type = other, "Unknown alert rule type"),
        }
    }
    rules
}

fn build_notification_channels(
    cfg: &[config::ChannelConfig],
) -> (Vec<Box<dyn NotificationChannel>>, Vec<ChannelRoute>) {
    let mut channels: Vec<Box<dyn NotificationChannel>> = Vec::new();
    let mut routes: Vec<ChannelRoute> = Vec::new();

    for (i, ch) in cfg.iter().enumerate() {
        let severity: Severity = ch.min_severity.parse().unwrap_or(Severity::Info);
        match ch.channel_type.as_str() {
            "email" => {
                if let (Some(host), Some(port), Some(from), Some(recipients)) =
                    (&ch.smtp_host, ch.smtp_port, &ch.from, &ch.recipients)
                {
                    match EmailChannel::new(
                        host,
                        port,
                        ch.smtp_username.as_deref(),
                        ch.smtp_password.as_deref(),
                        from,
                        recipients.clone(),
                    ) {
                        Ok(email) => {
                            channels.push(Box::new(email));
                            routes.push(ChannelRoute {
                                min_severity: severity,
                                channel_index: i,
                            });
                        }
                        Err(e) => tracing::error!(error = %e, "Failed to create email channel"),
                    }
                }
            }
            "webhook" => {
                if let Some(url) = &ch.url {
                    channels.push(Box::new(WebhookChannel::new(url, ch.body_template.clone())));
                    routes.push(ChannelRoute {
                        min_severity: severity,
                        channel_index: i,
                    });
                }
            }
            "sms" => {
                if let (Some(gw), Some(key), Some(phones)) =
                    (&ch.gateway_url, &ch.api_key, &ch.phone_numbers)
                {
                    channels.push(Box::new(SmsChannel::new(gw, key, phones.clone())));
                    routes.push(ChannelRoute {
                        min_severity: severity,
                        channel_index: i,
                    });
                }
            }
            other => tracing::warn!(channel_type = other, "Unknown notification channel type"),
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

    let state = AppState {
        storage: storage.clone(),
        alert_engine,
        notifier,
        agent_registry,
        cert_store: cert_store.clone(),
        connect_timeout_secs: config.cert_check.connect_timeout_secs,
        start_time: Utc::now(),
    };

    // gRPC server
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", config.grpc_port).parse()?;
    let grpc_service = MetricServiceServer::new(grpc::MetricServiceImpl::new(state.clone()));
    let grpc_server = TonicServer::builder()
        .add_service(grpc_service)
        .serve(grpc_addr);

    // HTTP/REST server
    let http_addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse()?;
    let app = api::router(state.clone())
        .merge(cert::api::cert_routes().with_state(state.clone()))
        .merge(openapi::openapi_routes().with_state(state.clone()));
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
