mod common;

use anyhow::{anyhow, Result};
use common::{build_test_context, request_no_body};
use std::collections::{BTreeSet, HashSet};

#[tokio::test]
async fn openapi_paths_should_be_covered_by_test_matrix() -> Result<()> {
    let ctx = build_test_context().await?;
    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let Some(paths) = body["paths"].as_object() else {
        return Err(anyhow!("openapi paths should be object"));
    };

    let mut exposed: BTreeSet<String> = BTreeSet::new();
    for (path, methods) in paths {
        let Some(methods) = methods.as_object() else {
            return Err(anyhow!("path methods should be object for {path}"));
        };
        for method in methods.keys() {
            let method = method.to_ascii_uppercase();
            exposed.insert(format!("{method} {path}"));
        }
    }

    let covered: HashSet<String> = [
        "GET /v1/health",
        "GET /v1/auth/public-key",
        "POST /v1/auth/login",
        "POST /v1/auth/password",
        "POST /v1/auth/logout",
        "GET /v1/agents",
        "GET /v1/agents/{id}",
        "PUT /v1/agents/{id}",
        "DELETE /v1/agents/{id}",
        "GET /v1/agents/{id}/latest",
        "GET /v1/agents/{id}/report-logs",
        "GET /v1/metrics",
        "GET /v1/alerts/rules",
        "GET /v1/alerts/history",
        "GET /v1/alerts/history/{id}",
        "POST /v1/agents/whitelist",
        "GET /v1/agents/whitelist",
        "GET /v1/agents/whitelist/{id}",
        "PUT /v1/agents/whitelist/{id}",
        "POST /v1/agents/whitelist/{id}/token",
        "DELETE /v1/agents/whitelist/{id}",
        "GET /v1/certificates",
        "GET /v1/certificates/{id}",
        "GET /v1/certificates/{id}/chain",
        "POST /v1/certs/domains",
        "POST /v1/certs/domains/batch",
        "GET /v1/certs/domains",
        "GET /v1/certs/domains/summary",
        "GET /v1/certs/domains/{id}",
        "PUT /v1/certs/domains/{id}",
        "DELETE /v1/certs/domains/{id}",
        "GET /v1/certs/status",
        "GET /v1/certs/status/{domain}",
        "POST /v1/certs/domains/{id}/check",
        "POST /v1/certs/check",
        // New endpoints: metrics discovery
        "GET /v1/metrics/names",
        "GET /v1/metrics/agents",
        "GET /v1/metrics/sources",
        "GET /v1/metrics/summary",
        // New endpoints: cert history & summary
        "GET /v1/certs/domains/{id}/history",
        "GET /v1/certs/domains/overview",
        "GET /v1/certs/domains/{id}/detail-view",
        "GET /v1/certs/summary",
        "GET /v1/certs/status/summary",
        // New endpoints: alert rules CRUD
        "POST /v1/alerts/rules",
        "GET /v1/alerts/rules/{id}",
        "GET /v1/alerts/rules/config",
        "PUT /v1/alerts/rules/{id}",
        "DELETE /v1/alerts/rules/{id}",
        "PUT /v1/alerts/rules/{id}/enable",
        // New endpoints: alert lifecycle
        "POST /v1/alerts/history/{id}/acknowledge",
        "POST /v1/alerts/history/{id}/resolve",
        "GET /v1/alerts/active",
        "GET /v1/alerts/summary",
        // New endpoints: notifications (merged channels endpoints)
        "GET /v1/notifications/channels",
        "POST /v1/notifications/channels",
        "GET /v1/notifications/channels/{id}",
        "PUT /v1/notifications/channels/{id}",
        "DELETE /v1/notifications/channels/{id}",
        "POST /v1/notifications/channels/{id}/test",
        "GET /v1/notifications/silence-windows",
        "POST /v1/notifications/silence-windows",
        "GET /v1/notifications/silence-windows/{id}",
        "PUT /v1/notifications/silence-windows/{id}",
        "DELETE /v1/notifications/silence-windows/{id}",
        // Notification logs
        "GET /v1/notifications/logs",
        "GET /v1/notifications/logs/{id}",
        "GET /v1/notifications/logs/summary",
        "POST /v1/notifications/test-cert-report",
        // New endpoints: dashboard
        "GET /v1/dashboard/overview",
        // New endpoints: system
        "GET /v1/system/config",
        "GET /v1/system/storage",
        "POST /v1/system/storage/cleanup",
        "POST /v1/system/certs/backfill-domains",
        // New endpoints: dictionaries
        "GET /v1/dictionaries/types",
        "POST /v1/dictionaries/types",
        "PUT /v1/dictionaries/types/{dict_type}",
        "DELETE /v1/dictionaries/types/{dict_type}",
        "GET /v1/dictionaries/types/all",
        "GET /v1/dictionaries/type/{dict_type}",
        "GET /v1/dictionaries/{id}",
        "POST /v1/dictionaries",
        "PUT /v1/dictionaries/{id}",
        "DELETE /v1/dictionaries/{id}",
        // New endpoints: system configs
        "GET /v1/system/configs",
        "GET /v1/system/configs/{id}",
        "POST /v1/system/configs",
        "PUT /v1/system/configs/{id}",
        "DELETE /v1/system/configs/{id}",
        // New endpoints: cloud monitoring
        "GET /v1/cloud/accounts",
        "POST /v1/cloud/accounts",
        "POST /v1/cloud/accounts/batch",
        "GET /v1/cloud/accounts/{id}",
        "PUT /v1/cloud/accounts/{id}",
        "DELETE /v1/cloud/accounts/{id}",
        "POST /v1/cloud/accounts/{id}/test",
        "POST /v1/cloud/accounts/{id}/diagnose",
        "POST /v1/cloud/accounts/{id}/collect",
        "GET /v1/cloud/instances",
        "GET /v1/cloud/instances/chart",
        "GET /v1/cloud/instances/{id}",
        "GET /v1/cloud/instances/{id}/metrics",
        "POST /v1/cloud/instances/ai-check",
        "GET /v1/cloud/instances/ai-check/jobs",
        "GET /v1/cloud/instances/ai-check/jobs/{id}",
        "POST /v1/cloud/instances/{id}/ai-check",
        // New endpoints: instance contacts
        "GET /v1/instance-contacts",
        "POST /v1/instance-contacts",
        "GET /v1/instance-contacts/{id}",
        "PUT /v1/instance-contacts/{id}",
        "DELETE /v1/instance-contacts/{id}",
        "GET /v1/instance-contacts/match/{agent_id}",
        // New endpoints: audit
        "GET /v1/audit/logs",
        "GET /v1/audit/logs/{id}",
        "GET /v1/audit/logs/security-summary",
        "GET /v1/audit/logs/security-summary/timeseries",
        // New endpoints: AI
        "GET /v1/ai/accounts",
        "POST /v1/ai/accounts",
        "GET /v1/ai/accounts/{id}",
        "PUT /v1/ai/accounts/{id}",
        "DELETE /v1/ai/accounts/{id}",
        "POST /v1/ai/accounts/{id}/trigger",
        "GET /v1/ai/reports",
        "GET /v1/ai/reports/{id}",
        "GET /v1/ai/reports/{id}/view",
        "GET /v1/ai/reports/{id}/instances",
        // New endpoints: admin
        "GET /v1/admin/users",
        "POST /v1/admin/users",
        "GET /v1/admin/users/{id}",
        "PUT /v1/admin/users/{id}",
        "DELETE /v1/admin/users/{id}",
        "POST /v1/admin/users/{id}/password",
        "GET /v1/admin/users/login-throttles",
        "POST /v1/admin/users/unlock-login-throttle",
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
    Ok(())
}

#[tokio::test]
async fn openapi_list_query_params_should_be_optional() -> Result<()> {
    let ctx = build_test_context().await?;
    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let Some(paths) = body["paths"].as_object() else {
        return Err(anyhow!("openapi paths should be object"));
    };

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
        (
            "/v1/notifications/logs",
            &[
                "channel_id",
                "channel_type",
                "status",
                "alert_event_id",
                "rule_id",
                "agent_id",
                "start_time",
                "end_time",
                "limit",
                "offset",
            ],
        ),
        (
            "/v1/notifications/logs/summary",
            &["channel_id", "channel_type", "start_time", "end_time"],
        ),
    ];

    for (path, names) in cases {
        let operation = paths
            .get(*path)
            .and_then(|item| item.get("get"))
            .ok_or_else(|| anyhow!("missing GET operation for path {path}"))?;
        let Some(parameters) = operation["parameters"].as_array() else {
            return Err(anyhow!("missing parameters for GET {path}"));
        };

        for name in *names {
            let parameter = parameters
                .iter()
                .find(|param| {
                    param["in"].as_str() == Some("query") && param["name"].as_str() == Some(*name)
                })
                .ok_or_else(|| anyhow!("missing query parameter {name} on GET {path}"))?;

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
    Ok(())
}

#[tokio::test]
async fn openapi_operation_tags_should_be_declared_in_root_tags() -> Result<()> {
    let ctx = build_test_context().await?;
    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let Some(root_tags) = body["tags"].as_array() else {
        return Err(anyhow!("openapi tags should be array"));
    };

    let declared: HashSet<&str> = root_tags
        .iter()
        .filter_map(|tag| tag["name"].as_str())
        .collect();

    let Some(paths) = body["paths"].as_object() else {
        return Err(anyhow!("openapi paths should be object"));
    };

    let mut missing: BTreeSet<String> = BTreeSet::new();
    for (path, methods) in paths {
        let Some(methods) = methods.as_object() else {
            return Err(anyhow!("path methods should be object for {path}"));
        };
        for (method, operation) in methods {
            let Some(tags) = operation["tags"].as_array() else {
                continue;
            };

            for tag in tags.iter().filter_map(serde_json::Value::as_str) {
                if !declared.contains(tag) {
                    missing.insert(format!(
                        "{} {} -> {}",
                        method.to_ascii_uppercase(),
                        path,
                        tag
                    ));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "operation tags missing root declarations: {missing:?}"
    );
    Ok(())
}

#[tokio::test]
async fn openapi_dashboard_overview_schema_should_include_cloud_summary_fields() -> Result<()> {
    let ctx = build_test_context().await?;
    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let Some(schemas) = body["components"]["schemas"].as_object() else {
        return Err(anyhow!("openapi components.schemas should be object"));
    };

    let dashboard = schemas
        .get("DashboardOverview")
        .ok_or_else(|| anyhow!("DashboardOverview schema should exist"))?;
    let Some(dashboard_props) = dashboard["properties"].as_object() else {
        return Err(anyhow!("DashboardOverview.properties should be object"));
    };
    assert!(
        dashboard_props.contains_key("cloud_summary"),
        "DashboardOverview should contain cloud_summary"
    );

    let cloud_summary = schemas
        .get("CloudSummary")
        .ok_or_else(|| anyhow!("CloudSummary schema should exist"))?;
    let Some(cloud_props) = cloud_summary["properties"].as_object() else {
        return Err(anyhow!("CloudSummary.properties should be object"));
    };

    for field in [
        "total_accounts",
        "enabled_accounts",
        "total_instances",
        "running_instances",
        "stopped_instances",
        "pending_instances",
        "error_instances",
        "unknown_instances",
    ] {
        assert!(
            cloud_props.contains_key(field),
            "CloudSummary should contain field {field}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn openapi_system_certs_backfill_domains_should_expose_optional_dry_run_query_param(
) -> Result<()> {
    let ctx = build_test_context().await?;
    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let operation = &body["paths"]["/v1/system/certs/backfill-domains"]["post"];
    let Some(parameters) = operation["parameters"].as_array() else {
        return Err(anyhow!(
            "POST /v1/system/certs/backfill-domains should expose parameters"
        ));
    };

    let dry_run = parameters
        .iter()
        .find(|param| {
            param["in"].as_str() == Some("query") && param["name"].as_str() == Some("dry_run")
        })
        .ok_or_else(|| anyhow!("dry_run query param should exist"))?;

    let required = dry_run
        .get("required")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    assert!(!required, "dry_run query param should be optional");

    let preview_limit = parameters
        .iter()
        .find(|param| {
            param["in"].as_str() == Some("query") && param["name"].as_str() == Some("preview_limit")
        })
        .ok_or_else(|| anyhow!("preview_limit query param should exist"))?;
    let required = preview_limit
        .get("required")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    assert!(!required, "preview_limit query param should be optional");
    Ok(())
}

#[tokio::test]
async fn openapi_system_certs_backfill_response_schema_should_include_domains_preview() -> Result<()>
{
    let ctx = build_test_context().await?;
    let (status, body, _) = request_no_body(&ctx.app, "GET", "/v1/openapi.json", None).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    let Some(schemas) = body["components"]["schemas"].as_object() else {
        return Err(anyhow!("openapi components.schemas should be object"));
    };

    let schema = schemas
        .get("CertDomainsBackfillResponse")
        .ok_or_else(|| anyhow!("CertDomainsBackfillResponse schema should exist"))?;
    let Some(props) = schema["properties"].as_object() else {
        return Err(anyhow!(
            "CertDomainsBackfillResponse.properties should be object"
        ));
    };

    for field in ["inserted_domains", "dry_run", "domains_preview"] {
        assert!(
            props.contains_key(field),
            "CertDomainsBackfillResponse should contain field {field}"
        );
    }
    Ok(())
}
