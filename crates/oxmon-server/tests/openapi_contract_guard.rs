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

#[tokio::test]
async fn openapi_list_query_params_should_be_optional() {
    let ctx = build_test_context().expect("test context should build");
    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let paths = body["paths"]
        .as_object()
        .expect("openapi paths should be object");

    let cases: &[(&str, &[&str])] = &[
        ("/v1/agents", &["limit", "offset"]),
        (
            "/v1/metrics",
            &[
                "agent_id__eq",
                "metric_name__eq",
                "timestamp__gte",
                "timestamp__lte",
                "limit",
                "offset",
            ],
        ),
        ("/v1/alerts/rules", &["limit", "offset"]),
        (
            "/v1/alerts/history",
            &[
                "agent_id__eq",
                "severity__eq",
                "timestamp__gte",
                "timestamp__lte",
                "limit",
                "offset",
            ],
        ),
        ("/v1/agents/whitelist", &["limit", "offset"]),
        (
            "/v1/certificates",
            &[
                "not_after__lte",
                "ip_address__contains",
                "issuer__contains",
                "limit",
                "offset",
            ],
        ),
        (
            "/v1/certs/domains",
            &["enabled__eq", "domain__contains", "limit", "offset"],
        ),
        ("/v1/certs/status", &["limit", "offset"]),
    ];

    for (path, names) in cases {
        let operation = paths
            .get(*path)
            .and_then(|item| item.get("get"))
            .unwrap_or_else(|| panic!("missing GET operation for path {path}"));
        let parameters = operation["parameters"]
            .as_array()
            .unwrap_or_else(|| panic!("missing parameters for GET {path}"));

        for name in *names {
            let parameter = parameters
                .iter()
                .find(|param| {
                    param["in"].as_str() == Some("query") && param["name"].as_str() == Some(*name)
                })
                .unwrap_or_else(|| panic!("missing query parameter {name} on GET {path}"));

            let required = parameter
                .get("required")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            assert!(
                !required,
                "query parameter {name} on GET {path} should be optional"
            );
        }
    }
}
