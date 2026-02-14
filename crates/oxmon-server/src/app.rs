use crate::state::AppState;
use crate::{api, auth, cert, logging, openapi};
use axum::middleware;
use axum::Router;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
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
        (name = "Dictionaries", description = "系统字典管理")
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

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    public_router
        .merge(login_router)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::app_id_middleware,
        ))
        .merge(
            protected_router
                .merge(cert_router)
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth::jwt_auth_middleware,
                )),
        )
        .with_state(state)
        .merge(SwaggerUi::new("/docs").url("/v1/openapi.json", merged_spec))
        .merge(openapi::yaml_route(spec))
        .layer(cors)
        .layer(middleware::from_fn(logging::request_logging))
}
