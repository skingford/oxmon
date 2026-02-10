mod common;

use common::{build_test_context, request_no_body};
use std::collections::{BTreeSet, HashSet};

#[tokio::test]
async fn openapi_paths_should_be_covered_by_test_matrix() {
    let ctx = build_test_context().expect("test context should build");
    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let paths = body["paths"]
        .as_object()
        .expect("openapi paths should be object");

    let mut exposed: BTreeSet<String> = BTreeSet::new();
    for (path, methods) in paths {
        let methods = methods.as_object().expect("path methods should be object");
        for method in methods.keys() {
            let method = method.to_ascii_uppercase();
            exposed.insert(format!("{method} {path}"));
        }
    }

    let covered: HashSet<String> = [
        "GET /v1/health",
        "POST /v1/auth/login",
        "POST /v1/auth/password",
        "GET /v1/agents",
        "GET /v1/agents/{id}/latest",
        "GET /v1/metrics",
        "GET /v1/alerts/rules",
        "GET /v1/alerts/history",
        "POST /v1/agents/whitelist",
        "GET /v1/agents/whitelist",
        "PUT /v1/agents/whitelist/{id}",
        "POST /v1/agents/whitelist/{id}/token",
        "DELETE /v1/agents/whitelist/{id}",
        "GET /v1/certificates",
        "GET /v1/certificates/{id}",
        "GET /v1/certificates/{id}/chain",
        "POST /v1/certs/domains",
        "POST /v1/certs/domains/batch",
        "GET /v1/certs/domains",
        "GET /v1/certs/domains/{id}",
        "PUT /v1/certs/domains/{id}",
        "DELETE /v1/certs/domains/{id}",
        "GET /v1/certs/status",
        "GET /v1/certs/status/{domain}",
        "POST /v1/certs/domains/{id}/check",
        "POST /v1/certs/check",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect();

    let missing: Vec<String> = exposed
        .into_iter()
        .filter(|route| {
            route.starts_with("GET /v1/")
                || route.starts_with("POST /v1/")
                || route.starts_with("PUT /v1/")
                || route.starts_with("DELETE /v1/")
        })
        .filter(|route| !route.starts_with("GET /v1/openapi"))
        .filter(|route| !covered.contains(route))
        .collect();

    assert!(
        missing.is_empty(),
        "missing endpoint coverage for: {missing:?}"
    );
}
