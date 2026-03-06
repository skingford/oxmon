use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use oxmon_common::id::next_id;
use oxmon_storage::AuditLogRow;
use std::net::SocketAddr;

use crate::auth::Claims;
use crate::logging::TraceId;
use crate::state::AppState;

/// 将 HTTP 方法映射为审计动作
fn method_to_action(method: &str) -> Option<&'static str> {
    match method {
        "POST" => Some("CREATE"),
        "PUT" | "PATCH" => Some("UPDATE"),
        "DELETE" => Some("DELETE"),
        _ => None,
    }
}

/// 从路径中解析资源类型和资源 ID
///
/// 示例：
/// - `/v1/alerts/rules`      → ("alerts", None)
/// - `/v1/alerts/rules/123`  → ("alerts", Some("123"))
/// - `/v1/notifications/channels/456/recipients` → ("notifications", Some("456"))
fn parse_resource(path: &str) -> (String, Option<String>) {
    // 去掉 /v1/ 前缀，取第一段为资源类型
    let stripped = path.strip_prefix("/v1/").unwrap_or(path);
    let parts: Vec<&str> = stripped.splitn(3, '/').collect();
    let resource_type = parts.first().copied().unwrap_or("unknown").to_string();
    // 第二段（如果是 ID 格式）作为 resource_id
    let resource_id = parts.get(1).and_then(|s| {
        // 简单判断：不为空且不是纯字母词（如 "rules"、"channels" 等子路径）
        // 如果包含数字或是 UUID 格式则认为是 ID
        if !s.is_empty() && (s.chars().any(|c| c.is_ascii_digit()) || s.contains('-')) {
            Some(s.to_string())
        } else {
            None
        }
    });
    (resource_type, resource_id)
}

fn first_non_empty_csv_value(raw: &str) -> Option<String> {
    raw.split(',')
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn ip_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(first_non_empty_csv_value)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            // RFC 7239: Forwarded: for=203.0.113.43;proto=http;by=...
            // 这里只提取第一个 for= 值，尽量兼容代理链。
            headers
                .get("forwarded")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    s.split(';').find_map(|part| {
                        let kv = part.trim();
                        let value = kv.strip_prefix("for=")?;
                        let value = value
                            .trim()
                            .trim_matches('"')
                            .trim_matches('[')
                            .trim_matches(']');
                        if value.is_empty() {
                            None
                        } else {
                            Some(value.to_string())
                        }
                    })
                })
        })
}

fn extract_source_ip(req: &Request<Body>) -> Option<String> {
    ip_from_headers(req.headers()).or_else(|| {
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
    })
}

/// 审计日志中间件
///
/// 仅记录写操作（POST/PUT/PATCH/DELETE）。
/// 依赖 JWT 中间件已将 `Claims` 注入到请求扩展中。
pub async fn audit_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();

    // 只审计写操作
    let action = match method_to_action(&method) {
        Some(a) => a,
        None => return next.run(req).await,
    };

    let path = req.uri().path().to_string();

    // 跳过审计自身接口（避免死循环）
    if path.starts_with("/v1/audit/") {
        return next.run(req).await;
    }

    // 提取上下文信息
    let claims = req.extensions().get::<Claims>().cloned();
    let trace_id = req.extensions().get::<TraceId>().map(|t| t.0.clone());

    let ip_address = extract_source_ip(&req);

    let user_agent = req
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let start = std::time::Instant::now();
    let response = next.run(req).await;
    let duration_ms = start.elapsed().as_millis() as i64;
    let status_code = response.status().as_u16() as i32;

    // 只有当请求携带有效 JWT 时才写审计日志
    if let Some(claims) = claims {
        let (resource_type, resource_id) = parse_resource(&path);
        let id = next_id();
        let created_at = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let row = AuditLogRow {
            id,
            user_id: claims.sub.clone(),
            username: claims.username,
            action: action.to_string(),
            resource_type,
            resource_id,
            method,
            path,
            status_code,
            ip_address,
            user_agent,
            trace_id,
            request_body: None,
            duration_ms,
            created_at,
        };

        let store = state.cert_store.clone();
        tokio::spawn(async move {
            if let Err(e) = store.insert_audit_log(row).await {
                tracing::warn!(error = %e, "Failed to write audit log");
            }
        });
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ip_prefers_first_xff_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.10, 10.0.0.2".parse().expect("valid header"),
        );
        let ip = ip_from_headers(&headers);
        assert_eq!(ip.as_deref(), Some("198.51.100.10"));
    }

    #[test]
    fn extract_ip_falls_back_to_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.7".parse().expect("valid header"));
        let ip = ip_from_headers(&headers);
        assert_eq!(ip.as_deref(), Some("203.0.113.7"));
    }
}
