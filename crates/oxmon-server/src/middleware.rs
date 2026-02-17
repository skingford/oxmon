use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderName, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use crate::api::error_response;
use crate::logging::TraceId;
use crate::state::AppState;

/// Custom header name for application identification.
static OX_APP_ID_HEADER: HeaderName = HeaderName::from_static("ox-app-id");

/// Middleware that validates the `ox-app-id` request header.
///
/// When `require_app_id` is `true` in config, requests without a valid
/// `ox-app-id` header are rejected with 403 Forbidden.
/// When `require_app_id` is `false`, the middleware passes through all requests.
pub async fn app_id_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // If feature is disabled, pass through
    if !state.config.app_id.require_app_id {
        return next.run(req).await;
    }

    let trace_id = req
        .extensions()
        .get::<TraceId>()
        .map(|t| t.0.clone())
        .unwrap_or_default();

    // Extract ox-app-id header
    let app_id = req
        .headers()
        .get(&OX_APP_ID_HEADER)
        .and_then(|v| v.to_str().ok());

    match app_id {
        None => {
            tracing::warn!(
                trace_id = %trace_id,
                "Request rejected: missing ox-app-id header"
            );
            error_response(
                StatusCode::FORBIDDEN,
                &trace_id,
                "app_id_missing",
                "missing ox-app-id header",
            )
        }
        Some("") => {
            tracing::warn!(
                trace_id = %trace_id,
                "Request rejected: empty ox-app-id header"
            );
            error_response(
                StatusCode::FORBIDDEN,
                &trace_id,
                "app_id_missing",
                "ox-app-id header cannot be empty",
            )
        }
        Some(id) => {
            // If allowed_app_ids is empty, accept any non-empty value
            // If allowed_app_ids has entries, validate against the list
            if !state.config.app_id.allowed_app_ids.is_empty()
                && !state.config.app_id.allowed_app_ids.iter().any(|a| a == id)
            {
                tracing::warn!(
                    trace_id = %trace_id,
                    app_id = %id,
                    "Request rejected: invalid ox-app-id"
                );
                return error_response(
                    StatusCode::FORBIDDEN,
                    &trace_id,
                    "app_id_invalid",
                    "invalid ox-app-id",
                );
            }

            tracing::debug!(
                trace_id = %trace_id,
                app_id = %id,
                "ox-app-id validated"
            );
            next.run(req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppIdConfig, AuthConfig, CertCheckConfig, ServerConfig};
    use crate::state::{AgentRegistry, AppState};
    use axum::body::to_bytes;
    use axum::routing::get;
    use axum::Router;
    use chrono::Utc;
    use oxmon_alert::engine::AlertEngine;
    use oxmon_notify::manager::NotificationManager;
    use oxmon_notify::plugin::ChannelRegistry;
    use oxmon_storage::cert_store::CertStore;
    use oxmon_storage::engine::SqliteStorageEngine;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn build_mock_state(app_id_config: AppIdConfig) -> (AppState, TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(SqliteStorageEngine::new(temp_dir.path()).unwrap());
        let cert_store = Arc::new(CertStore::new(temp_dir.path()).unwrap());
        let alert_engine = Arc::new(Mutex::new(AlertEngine::new(vec![])));
        let notifier = Arc::new(NotificationManager::new(
            ChannelRegistry::default(),
            cert_store.clone(),
            0,
        ));
        let agent_registry = Arc::new(Mutex::new(AgentRegistry::new(10, cert_store.clone())));

        let config = ServerConfig {
            grpc_port: 9090,
            http_port: 8080,
            data_dir: temp_dir.path().to_string_lossy().to_string(),
            retention_days: 7,
            require_agent_auth: false,
            agent_collection_interval_secs: 10,
            cors_allowed_origins: Vec::new(),
            rate_limit_enabled: false,
            cert_check: CertCheckConfig::default(),
            auth: AuthConfig::default(),
            app_id: app_id_config,
        };

        let password_encryptor = Arc::new(
            oxmon_storage::auth::PasswordEncryptor::load_or_create(temp_dir.path()).unwrap(),
        );

        let state = AppState {
            storage,
            alert_engine,
            notifier,
            agent_registry,
            cert_store,
            connect_timeout_secs: 1,
            start_time: Utc::now(),
            jwt_secret: Arc::new("test-secret".to_string()),
            token_expire_secs: 3600,
            password_encryptor,
            config: Arc::new(config),
        };

        (state, temp_dir)
    }

    async fn test_handler() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("OK"))
            .unwrap()
    }

    fn build_test_app(state: AppState) -> Router {
        Router::new()
            .route("/test", get(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                app_id_middleware,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_feature_disabled_passes_through() {
        let (state, _temp) = build_mock_state(AppIdConfig {
            require_app_id: false,
            allowed_app_ids: vec![],
        });
        let app = build_test_app(state);

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn test_missing_header_returns_403() {
        let (state, _temp) = build_mock_state(AppIdConfig {
            require_app_id: true,
            allowed_app_ids: vec![],
        });
        let app = build_test_app(state);

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["err_code"], 1008);
    }

    #[tokio::test]
    async fn test_empty_header_returns_403() {
        let (state, _temp) = build_mock_state(AppIdConfig {
            require_app_id: true,
            allowed_app_ids: vec![],
        });
        let app = build_test_app(state);

        let req = Request::builder()
            .uri("/test")
            .header("ox-app-id", "")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["err_code"], 1008);
    }

    #[tokio::test]
    async fn test_valid_header_with_empty_allowed_list_passes() {
        let (state, _temp) = build_mock_state(AppIdConfig {
            require_app_id: true,
            allowed_app_ids: vec![], // Empty list = accept any non-empty value
        });
        let app = build_test_app(state);

        let req = Request::builder()
            .uri("/test")
            .header("ox-app-id", "any-app")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn test_valid_header_in_allowed_list_passes() {
        let (state, _temp) = build_mock_state(AppIdConfig {
            require_app_id: true,
            allowed_app_ids: vec!["web-console".to_string(), "mobile-app".to_string()],
        });
        let app = build_test_app(state);

        let req = Request::builder()
            .uri("/test")
            .header("ox-app-id", "web-console")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn test_invalid_header_not_in_allowed_list_returns_403() {
        let (state, _temp) = build_mock_state(AppIdConfig {
            require_app_id: true,
            allowed_app_ids: vec!["web-console".to_string(), "mobile-app".to_string()],
        });
        let app = build_test_app(state);

        let req = Request::builder()
            .uri("/test")
            .header("ox-app-id", "unknown-app")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["err_code"], 1009);
    }
}
