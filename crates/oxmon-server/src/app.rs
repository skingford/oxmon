use crate::state::AppState;
use crate::{api, auth, cert, logging, openapi};
use axum::middleware;
use axum::Router;
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

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
        (name = "Certificates", description = "证书监控"),
        (name = "Notifications", description = "通知渠道管理"),
        (name = "Dashboard", description = "仪表盘概览"),
        (name = "System", description = "系统管理"),
        (name = "Dictionaries", description = "系统字典管理"),
        (name = "Cloud", description = "云账户与云实例管理")
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            utoipa::openapi::security::SecurityScheme::Http(utoipa::openapi::security::Http::new(
                utoipa::openapi::security::HttpAuthScheme::Bearer,
            )),
        );
        components.add_security_scheme(
            "app_id_auth",
            utoipa::openapi::security::SecurityScheme::ApiKey(
                utoipa::openapi::security::ApiKey::Header(
                    utoipa::openapi::security::ApiKeyValue::new("ox-app-id"),
                ),
            ),
        );
    }
}

pub fn build_http_app(state: AppState) -> Router {
    let (public_router, public_spec) = api::public_routes().split_for_parts();
    let (login_router, login_spec) = api::auth_routes().split_for_parts();
    let (protected_router, protected_spec) = api::protected_routes().split_for_parts();
    let (cert_router, cert_spec) = cert::api::cert_routes().split_for_parts();

    let mut merged_spec = ApiDoc::openapi();
    merged_spec.merge(public_spec);
    merged_spec.merge(login_spec);
    merged_spec.merge(protected_spec);
    merged_spec.merge(cert_spec);
    let spec = Arc::new(merged_spec.clone());

    let cors = if state.config.cors_allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let origins: Vec<axum::http::HeaderValue> = state
            .config
            .cors_allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(Any)
            .allow_headers(Any)
    };

    let rate_limit_enabled = state.config.rate_limit_enabled;

    // Build the base router tree
    let login_branch = if rate_limit_enabled {
        let login_governor_conf = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(12)
                .burst_size(5)
                .finish()
                .expect("failed to build login rate limiter config"),
        );
        login_router.layer(GovernorLayer {
            config: login_governor_conf,
        })
    } else {
        login_router
    };

    let protected_branch = if rate_limit_enabled {
        let api_governor_conf = Arc::new(
            GovernorConfigBuilder::default()
                .per_second(1)
                .burst_size(60)
                .finish()
                .expect("failed to build API rate limiter config"),
        );
        protected_router
            .merge(cert_router)
            .layer(GovernorLayer {
                config: api_governor_conf,
            })
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth::jwt_auth_middleware,
            ))
    } else {
        protected_router
            .merge(cert_router)
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth::jwt_auth_middleware,
            ))
    };

    public_router
        .merge(login_branch)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::app_id_middleware,
        ))
        .merge(protected_branch)
        .with_state(state)
        .merge(SwaggerUi::new("/docs").url("/v1/openapi.json", merged_spec))
        .merge(openapi::yaml_route(spec))
        .layer(cors)
        .layer(middleware::from_fn(logging::request_logging))
}
