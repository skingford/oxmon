use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use utoipa::openapi::OpenApi;

pub fn yaml_route(spec: Arc<OpenApi>) -> Router {
    Router::new().route(
        "/v1/openapi.yaml",
        get(move || {
            let spec = spec.clone();
            async move { openapi_yaml(spec).await }
        }),
    )
}

async fn openapi_yaml(spec: Arc<OpenApi>) -> impl IntoResponse {
    match serde_yaml_neo::to_string(spec.as_ref()) {
        Ok(yaml) => (StatusCode::OK, [(header::CONTENT_TYPE, "text/yaml")], yaml).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to serialize YAML: {e}"),
        )
            .into_response(),
    }
}
