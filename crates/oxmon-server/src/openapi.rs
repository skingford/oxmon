// OpenAPI 3.0.3 spec for oxmon REST API
//
// Covered endpoints:
//   GET  /api/v1/health
//   GET  /api/v1/agents
//   GET  /api/v1/agents/{id}/latest
//   GET  /api/v1/metrics
//   GET  /api/v1/alerts/rules
//   GET  /api/v1/alerts/history
//   POST /api/v1/certs/domains
//   GET  /api/v1/certs/domains
//   POST /api/v1/certs/domains/batch
//   GET  /api/v1/certs/domains/{id}
//   PUT  /api/v1/certs/domains/{id}
//   DELETE /api/v1/certs/domains/{id}
//   POST /api/v1/certs/domains/{id}/check
//   POST /api/v1/certs/check
//   GET  /api/v1/certs/status
//   GET  /api/v1/certs/status/{domain}
//   GET  /api/v1/openapi.json
//   GET  /api/v1/openapi.yaml

use crate::state::AppState;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use std::sync::OnceLock;

static OPENAPI_SPEC: OnceLock<Value> = OnceLock::new();

fn get_spec() -> &'static Value {
    OPENAPI_SPEC.get_or_init(build_openapi_spec)
}

fn build_openapi_spec() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "oxmon API",
            "description": "oxmon server monitoring REST API",
            "version": env!("CARGO_PKG_VERSION")
        },
        "servers": [
            { "url": "/api/v1", "description": "API v1" }
        ],
        "paths": {
            "/api/v1/health": {
                "get": {
                    "tags": ["Health"],
                    "summary": "Get server health status",
                    "operationId": "getHealth",
                    "responses": {
                        "200": {
                            "description": "Server health info",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HealthResponse" } } }
                        }
                    }
                }
            },
            "/api/v1/agents": {
                "get": {
                    "tags": ["Agents"],
                    "summary": "List all registered agents",
                    "operationId": "listAgents",
                    "responses": {
                        "200": {
                            "description": "List of agents",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/AgentResponse" } } } }
                        }
                    }
                }
            },
            "/api/v1/agents/{id}/latest": {
                "get": {
                    "tags": ["Agents"],
                    "summary": "Get latest metrics for an agent",
                    "operationId": "getAgentLatest",
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Agent ID" }
                    ],
                    "responses": {
                        "200": {
                            "description": "Latest metric values",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/LatestMetric" } } } }
                        },
                        "404": { "$ref": "#/components/responses/NotFound" }
                    }
                }
            },
            "/api/v1/metrics": {
                "get": {
                    "tags": ["Metrics"],
                    "summary": "Query metric time series data",
                    "operationId": "queryMetrics",
                    "parameters": [
                        { "name": "agent", "in": "query", "required": true, "schema": { "type": "string" }, "description": "Agent ID" },
                        { "name": "metric", "in": "query", "required": true, "schema": { "type": "string" }, "description": "Metric name (e.g., cpu.usage, memory.used_percent)" },
                        { "name": "from", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" }, "description": "Start time (defaults to 1 hour before `to`)" },
                        { "name": "to", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" }, "description": "End time (defaults to now)" }
                    ],
                    "responses": {
                        "200": {
                            "description": "Metric data points",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/MetricPointResponse" } } } }
                        },
                        "400": { "$ref": "#/components/responses/BadRequest" }
                    }
                }
            },
            "/api/v1/alerts/rules": {
                "get": {
                    "tags": ["Alerts"],
                    "summary": "List all alert rules",
                    "operationId": "listAlertRules",
                    "responses": {
                        "200": {
                            "description": "List of alert rules",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/AlertRuleResponse" } } } }
                        }
                    }
                }
            },
            "/api/v1/alerts/history": {
                "get": {
                    "tags": ["Alerts"],
                    "summary": "Query alert event history",
                    "operationId": "queryAlertHistory",
                    "parameters": [
                        { "name": "from", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" }, "description": "Start time (defaults to 1 day ago)" },
                        { "name": "to", "in": "query", "required": false, "schema": { "type": "string", "format": "date-time" }, "description": "End time (defaults to now)" },
                        { "name": "severity", "in": "query", "required": false, "schema": { "type": "string", "enum": ["info", "warning", "critical"] }, "description": "Filter by severity" },
                        { "name": "agent", "in": "query", "required": false, "schema": { "type": "string" }, "description": "Filter by agent ID" },
                        { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "default": 100 }, "description": "Results per page" },
                        { "name": "offset", "in": "query", "required": false, "schema": { "type": "integer", "default": 0 }, "description": "Pagination offset" }
                    ],
                    "responses": {
                        "200": {
                            "description": "Alert events",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/AlertEventResponse" } } } }
                        }
                    }
                }
            },
            "/api/v1/certs/domains": {
                "get": {
                    "tags": ["Certificates"],
                    "summary": "List monitored domains",
                    "operationId": "listCertDomains",
                    "parameters": [
                        { "name": "enabled", "in": "query", "required": false, "schema": { "type": "boolean" }, "description": "Filter by enabled status" },
                        { "name": "search", "in": "query", "required": false, "schema": { "type": "string" }, "description": "Search by domain name" },
                        { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "default": 100 }, "description": "Results per page" },
                        { "name": "offset", "in": "query", "required": false, "schema": { "type": "integer", "default": 0 }, "description": "Pagination offset" }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of domains",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/CertDomain" } } } }
                        }
                    }
                },
                "post": {
                    "tags": ["Certificates"],
                    "summary": "Add a domain for certificate monitoring",
                    "operationId": "createCertDomain",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CreateDomainRequest" } } }
                    },
                    "responses": {
                        "201": {
                            "description": "Domain created",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CertDomain" } } }
                        },
                        "400": { "$ref": "#/components/responses/BadRequest" },
                        "409": { "$ref": "#/components/responses/Conflict" }
                    }
                }
            },
            "/api/v1/certs/domains/batch": {
                "post": {
                    "tags": ["Certificates"],
                    "summary": "Batch add domains for certificate monitoring",
                    "operationId": "createCertDomainsBatch",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/BatchCreateDomainsRequest" } } }
                    },
                    "responses": {
                        "201": {
                            "description": "Domains created",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/CertDomain" } } } }
                        },
                        "400": { "$ref": "#/components/responses/BadRequest" },
                        "409": { "$ref": "#/components/responses/Conflict" }
                    }
                }
            },
            "/api/v1/certs/domains/{id}": {
                "get": {
                    "tags": ["Certificates"],
                    "summary": "Get a monitored domain by ID",
                    "operationId": "getCertDomain",
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Domain ID" }
                    ],
                    "responses": {
                        "200": {
                            "description": "Domain details",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CertDomain" } } }
                        },
                        "404": { "$ref": "#/components/responses/NotFound" }
                    }
                },
                "put": {
                    "tags": ["Certificates"],
                    "summary": "Update a monitored domain",
                    "operationId": "updateCertDomain",
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Domain ID" }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/UpdateDomainRequest" } } }
                    },
                    "responses": {
                        "200": {
                            "description": "Domain updated",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CertDomain" } } }
                        },
                        "400": { "$ref": "#/components/responses/BadRequest" },
                        "404": { "$ref": "#/components/responses/NotFound" }
                    }
                },
                "delete": {
                    "tags": ["Certificates"],
                    "summary": "Delete a monitored domain",
                    "operationId": "deleteCertDomain",
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Domain ID" }
                    ],
                    "responses": {
                        "204": { "description": "Domain deleted" },
                        "404": { "$ref": "#/components/responses/NotFound" }
                    }
                }
            },
            "/api/v1/certs/domains/{id}/check": {
                "post": {
                    "tags": ["Certificates"],
                    "summary": "Manually trigger certificate check for a domain",
                    "operationId": "checkCertDomain",
                    "parameters": [
                        { "name": "id", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Domain ID" }
                    ],
                    "responses": {
                        "200": {
                            "description": "Certificate check result",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CertCheckResult" } } }
                        },
                        "404": { "$ref": "#/components/responses/NotFound" }
                    }
                }
            },
            "/api/v1/certs/check": {
                "post": {
                    "tags": ["Certificates"],
                    "summary": "Manually trigger certificate check for all enabled domains",
                    "operationId": "checkAllCertDomains",
                    "responses": {
                        "200": {
                            "description": "Certificate check results for all domains",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/CertCheckResult" } } } }
                        }
                    }
                }
            },
            "/api/v1/certs/status": {
                "get": {
                    "tags": ["Certificates"],
                    "summary": "Get latest certificate check results for all domains",
                    "operationId": "getCertStatusAll",
                    "responses": {
                        "200": {
                            "description": "Latest check results",
                            "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/CertCheckResult" } } } }
                        }
                    }
                }
            },
            "/api/v1/certs/status/{domain}": {
                "get": {
                    "tags": ["Certificates"],
                    "summary": "Get latest certificate check result for a specific domain",
                    "operationId": "getCertStatusByDomain",
                    "parameters": [
                        { "name": "domain", "in": "path", "required": true, "schema": { "type": "string" }, "description": "Domain name" }
                    ],
                    "responses": {
                        "200": {
                            "description": "Latest check result",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CertCheckResult" } } }
                        },
                        "404": { "$ref": "#/components/responses/NotFound" }
                    }
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "tags": ["Documentation"],
                    "summary": "Get OpenAPI spec in JSON format",
                    "operationId": "getOpenApiJson",
                    "responses": {
                        "200": {
                            "description": "OpenAPI 3.0.3 specification",
                            "content": { "application/json": { "schema": { "type": "object" } } }
                        }
                    }
                }
            },
            "/api/v1/openapi.yaml": {
                "get": {
                    "tags": ["Documentation"],
                    "summary": "Get OpenAPI spec in YAML format",
                    "operationId": "getOpenApiYaml",
                    "responses": {
                        "200": {
                            "description": "OpenAPI 3.0.3 specification",
                            "content": { "text/yaml": { "schema": { "type": "object" } } }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "ApiError": {
                    "type": "object",
                    "required": ["error", "code"],
                    "properties": {
                        "error": { "type": "string", "description": "Error message" },
                        "code": { "type": "string", "description": "Error code (e.g., not_found, invalid_domain)" }
                    }
                },
                "HealthResponse": {
                    "type": "object",
                    "required": ["version", "uptime_secs", "agent_count", "storage_status"],
                    "properties": {
                        "version": { "type": "string" },
                        "uptime_secs": { "type": "integer", "format": "int64" },
                        "agent_count": { "type": "integer" },
                        "storage_status": { "type": "string" }
                    }
                },
                "AgentResponse": {
                    "type": "object",
                    "required": ["agent_id", "last_seen", "status"],
                    "properties": {
                        "agent_id": { "type": "string" },
                        "last_seen": { "type": "string", "format": "date-time" },
                        "status": { "type": "string", "enum": ["active", "inactive"] }
                    }
                },
                "LatestMetric": {
                    "type": "object",
                    "required": ["metric_name", "value", "timestamp"],
                    "properties": {
                        "metric_name": { "type": "string" },
                        "value": { "type": "number", "format": "double" },
                        "timestamp": { "type": "string", "format": "date-time" }
                    }
                },
                "MetricPointResponse": {
                    "type": "object",
                    "required": ["timestamp", "value"],
                    "properties": {
                        "timestamp": { "type": "string", "format": "date-time" },
                        "value": { "type": "number", "format": "double" }
                    }
                },
                "AlertRuleResponse": {
                    "type": "object",
                    "required": ["id", "metric", "agent_pattern", "severity"],
                    "properties": {
                        "id": { "type": "string" },
                        "metric": { "type": "string" },
                        "agent_pattern": { "type": "string" },
                        "severity": { "type": "string", "enum": ["info", "warning", "critical"] }
                    }
                },
                "AlertEventResponse": {
                    "type": "object",
                    "required": ["id", "rule_id", "agent_id", "metric_name", "severity", "message", "value", "threshold", "timestamp"],
                    "properties": {
                        "id": { "type": "string" },
                        "rule_id": { "type": "string" },
                        "agent_id": { "type": "string" },
                        "metric_name": { "type": "string" },
                        "severity": { "type": "string", "enum": ["info", "warning", "critical"] },
                        "message": { "type": "string" },
                        "value": { "type": "number", "format": "double" },
                        "threshold": { "type": "number", "format": "double" },
                        "timestamp": { "type": "string", "format": "date-time" },
                        "predicted_breach": { "type": "string", "format": "date-time", "nullable": true }
                    }
                },
                "CertDomain": {
                    "type": "object",
                    "required": ["id", "domain", "port", "enabled", "created_at", "updated_at"],
                    "properties": {
                        "id": { "type": "string" },
                        "domain": { "type": "string" },
                        "port": { "type": "integer" },
                        "enabled": { "type": "boolean" },
                        "check_interval_secs": { "type": "integer", "format": "int64", "nullable": true },
                        "note": { "type": "string", "nullable": true },
                        "last_checked_at": { "type": "string", "format": "date-time", "nullable": true },
                        "created_at": { "type": "string", "format": "date-time" },
                        "updated_at": { "type": "string", "format": "date-time" }
                    }
                },
                "CertCheckResult": {
                    "type": "object",
                    "required": ["id", "domain_id", "domain", "is_valid", "chain_valid", "checked_at"],
                    "properties": {
                        "id": { "type": "string" },
                        "domain_id": { "type": "string" },
                        "domain": { "type": "string" },
                        "is_valid": { "type": "boolean" },
                        "chain_valid": { "type": "boolean" },
                        "not_before": { "type": "string", "format": "date-time", "nullable": true },
                        "not_after": { "type": "string", "format": "date-time", "nullable": true },
                        "days_until_expiry": { "type": "integer", "format": "int64", "nullable": true },
                        "issuer": { "type": "string", "nullable": true },
                        "subject": { "type": "string", "nullable": true },
                        "san_list": { "type": "array", "items": { "type": "string" }, "nullable": true },
                        "error": { "type": "string", "nullable": true },
                        "checked_at": { "type": "string", "format": "date-time" }
                    }
                },
                "CreateDomainRequest": {
                    "type": "object",
                    "required": ["domain"],
                    "properties": {
                        "domain": { "type": "string", "description": "Domain name to monitor" },
                        "port": { "type": "integer", "description": "Port (1-65535, defaults to 443)", "default": 443 },
                        "check_interval_secs": { "type": "integer", "format": "int64", "description": "Custom check interval in seconds" },
                        "note": { "type": "string", "description": "Optional note" }
                    }
                },
                "UpdateDomainRequest": {
                    "type": "object",
                    "properties": {
                        "port": { "type": "integer", "description": "Port (1-65535)" },
                        "enabled": { "type": "boolean", "description": "Enable/disable monitoring" },
                        "check_interval_secs": { "type": "integer", "format": "int64", "nullable": true, "description": "Custom check interval (null to use default)" },
                        "note": { "type": "string", "description": "Optional note" }
                    }
                },
                "BatchCreateDomainsRequest": {
                    "type": "object",
                    "required": ["domains"],
                    "properties": {
                        "domains": { "type": "array", "items": { "$ref": "#/components/schemas/CreateDomainRequest" }, "description": "List of domains to add" }
                    }
                }
            },
            "responses": {
                "BadRequest": {
                    "description": "Bad request",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } }
                },
                "NotFound": {
                    "description": "Resource not found",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } }
                },
                "Conflict": {
                    "description": "Resource already exists",
                    "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } }
                }
            }
        }
    })
}

async fn openapi_json() -> impl IntoResponse {
    axum::Json(get_spec().clone())
}

async fn openapi_yaml() -> impl IntoResponse {
    match serde_yaml::to_string(get_spec()) {
        Ok(yaml) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/yaml")],
            yaml,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to serialize YAML: {e}"),
        )
            .into_response(),
    }
}

pub fn openapi_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/openapi.json", get(openapi_json))
        .route("/api/v1/openapi.yaml", get(openapi_yaml))
}
