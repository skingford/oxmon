use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use chrono::Utc;
use oxmon_common::id::next_id;
use oxmon_storage::AuditLogRow;
use serde_json::{Map, Value};
use std::net::SocketAddr;

use crate::auth::Claims;
use crate::logging::TraceId;
use crate::state::AppState;

const MAX_AUDIT_TEXT_CHARS: usize = 4096;
const MAX_AUDIT_BINARY_BYTES: usize = 2048;

/// 将 HTTP 方法映射为审计动作
fn method_to_action(method: &str) -> Option<&'static str> {
    match method {
        "POST" => Some("CREATE"),
        "PUT" | "PATCH" => Some("UPDATE"),
        "DELETE" => Some("DELETE"),
        _ => None,
    }
}

fn is_reserved_resource_segment(segment: &str) -> bool {
    matches!(
        segment,
        "rules"
            | "channels"
            | "recipients"
            | "configs"
            | "types"
            | "items"
            | "accounts"
            | "instances"
            | "logs"
            | "summary"
            | "metrics"
            | "chart"
            | "batch"
            | "trigger"
            | "test"
            | "domains"
            | "certs"
            | "reports"
            | "health"
            | "overview"
    )
}

fn normalize_segment(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut normalized = String::with_capacity(trimmed.len().min(128));
    let mut prev_dash = false;

    for ch in trimmed.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() || matches!(lower, '-' | '_' | ':' | '.') {
            normalized.push(lower);
            prev_dash = false;
        } else if !prev_dash {
            normalized.push('-');
            prev_dash = true;
        }

        if normalized.len() >= 128 {
            break;
        }
    }

    while normalized.ends_with('-') || normalized.ends_with('_') {
        normalized.pop();
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn looks_like_resource_id(segment: &str) -> bool {
    if segment.is_empty() || is_reserved_resource_segment(segment) {
        return false;
    }

    // 数字、分隔符或较长 token 都可作为 ID 候选。
    segment
        .chars()
        .any(|c| c.is_ascii_digit() || matches!(c, '-' | '_' | ':' | '.'))
        || segment.len() >= 8
}

/// 从路径中解析资源类型和资源 ID
///
/// 示例：
/// - `/v1/alerts/rules`      → ("alerts", None)
/// - `/v1/alerts/rules/123`  → ("alerts", Some("123"))
/// - `/v1/notifications/channels/456/recipients` → ("notifications", Some("456"))
fn parse_resource(method: &str, path: &str) -> (String, Option<String>) {
    let stripped = path.strip_prefix("/v1/").unwrap_or(path);
    let parts: Vec<&str> = stripped.split('/').filter(|s| !s.is_empty()).collect();
    let resource_type = parts
        .first()
        .and_then(|s| normalize_segment(s))
        .unwrap_or_else(|| "unknown".to_string());

    if parts.len() <= 1 {
        return (resource_type, None);
    }

    let mut resource_id = None;
    for (idx, part) in parts.iter().enumerate().skip(1) {
        let Some(candidate) = normalize_segment(part) else {
            continue;
        };

        let is_tail = idx == parts.len() - 1;
        let next_is_action = parts
            .get(idx + 1)
            .map(|next| {
                matches!(
                    *next,
                    "trigger" | "test" | "check" | "verify" | "reset-password" | "retry"
                )
            })
            .unwrap_or(false);

        let should_use = if matches!(method, "PUT" | "PATCH" | "DELETE") && is_tail {
            !is_reserved_resource_segment(candidate.as_str())
        } else {
            looks_like_resource_id(candidate.as_str()) || next_is_action
        };

        if should_use {
            resource_id = Some(candidate);
        }
    }

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

fn truncate_utf8(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let mut out = String::with_capacity(max_chars + 3);
    out.extend(text.chars().take(max_chars));
    out.push_str("...");
    out
}

fn parse_query_params(raw: Option<&str>) -> Value {
    let Some(raw) = raw else {
        return Value::Null;
    };
    if raw.trim().is_empty() {
        return Value::Null;
    }

    let mut obj = Map::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }

        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if k.is_empty() {
            continue;
        }

        let value = Value::String(v.to_string());
        if let Some(existing) = obj.get_mut(k) {
            match existing {
                Value::Array(arr) => arr.push(value),
                _ => {
                    let old = existing.take();
                    *existing = Value::Array(vec![old, value]);
                }
            }
        } else {
            obj.insert(k.to_string(), value);
        }
    }

    if obj.is_empty() {
        Value::Null
    } else {
        Value::Object(obj)
    }
}

fn should_mask_password_field(path: &str) -> bool {
    matches!(path, "/v1/auth/login" | "/v1/auth/password")
}

fn mask_password_fields(path: &str, body: Value) -> Value {
    if !should_mask_password_field(path) {
        return body;
    }

    let Value::Object(mut obj) = body else {
        return body;
    };

    for key in [
        "password",
        "encrypted_password",
        "current_password",
        "new_password",
        "encrypted_current_password",
        "encrypted_new_password",
    ] {
        if let Some(value) = obj.get_mut(key) {
            *value = Value::String("***".to_string());
        }
    }

    Value::Object(obj)
}

fn serialize_body(path: &str, content_type: Option<&str>, body: &[u8]) -> Value {
    if body.is_empty() {
        return Value::Null;
    }

    let is_json = content_type
        .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
        .unwrap_or(false);

    if is_json {
        if let Ok(json) = serde_json::from_slice::<Value>(body) {
            return mask_password_fields(path, json);
        }
    }

    if let Ok(text) = std::str::from_utf8(body) {
        if is_json {
            return serde_json::json!({
                "_raw": truncate_utf8(text, MAX_AUDIT_TEXT_CHARS),
                "_fallback": "invalid_json"
            });
        }
        return Value::String(truncate_utf8(text, MAX_AUDIT_TEXT_CHARS));
    }

    let truncated = body.len() > MAX_AUDIT_BINARY_BYTES;
    let slice = if truncated {
        &body[..MAX_AUDIT_BINARY_BYTES]
    } else {
        body
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(slice);
    serde_json::json!({
        "_base64": encoded,
        "_len": body.len(),
        "_truncated": truncated,
        "_fallback": "non_utf8"
    })
}

fn build_audit_request_params(
    method: &str,
    path: &str,
    query: Option<&str>,
    content_type: Option<&str>,
    body: Option<&[u8]>,
    capture_state: &str,
) -> String {
    let payload = serde_json::json!({
        "method": method,
        "path": path,
        "query": parse_query_params(query),
        "body": body.map(|b| serialize_body(path, content_type, b)).unwrap_or_else(|| serde_json::json!({
            "_fallback": capture_state
        })),
        "meta": {
            "capture": capture_state,
            "content_type": content_type
        }
    });

    serde_json::to_string(&payload).unwrap_or_else(|_| {
        "{\"body\":{\"_fallback\":\"serialize_error\"},\"meta\":{\"capture\":\"serialize_error\"}}"
            .to_string()
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

    let query_raw = req.uri().query().map(|q| q.to_string());
    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let ip_address = extract_source_ip(&req);

    let user_agent = req
        .headers()
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let (req, request_params, capture_state) = {
        let (parts, body) = req.into_parts();
        match axum::body::to_bytes(body, 1024 * 1024).await {
            Ok(bytes) if bytes.is_empty() => {
                let req = Request::from_parts(parts, Body::from(bytes));
                let params = build_audit_request_params(
                    &method,
                    &path,
                    query_raw.as_deref(),
                    content_type.as_deref(),
                    Some(&[]),
                    "empty",
                );
                (req, params, "empty")
            }
            Ok(bytes) => {
                let params = build_audit_request_params(
                    &method,
                    &path,
                    query_raw.as_deref(),
                    content_type.as_deref(),
                    Some(bytes.as_ref()),
                    "ok",
                );
                let req = Request::from_parts(parts, Body::from(bytes));
                (req, params, "ok")
            }
            Err(_) => {
                // 无法读取 body 时，继续请求但保留回退信息。
                let req = Request::from_parts(parts, Body::empty());
                let params = build_audit_request_params(
                    &method,
                    &path,
                    query_raw.as_deref(),
                    content_type.as_deref(),
                    None,
                    "unreadable",
                );
                (req, params, "unreadable")
            }
        }
    };

    let start = std::time::Instant::now();
    let response = next.run(req).await;
    let duration_ms = start.elapsed().as_millis() as i64;
    let status_code = response.status().as_u16() as i32;

    // 只有当请求携带有效 JWT 时才写审计日志
    if let Some(claims) = claims {
        let (resource_type, resource_id) = parse_resource(&method, &path);
        let id = next_id();
        let created_at = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let row = AuditLogRow {
            id,
            user_id: claims.sub,
            username: claims.username,
            action: action.to_string(),
            resource_type,
            resource_id,
            method,
            path,
            status_code,
            ip_address,
            user_agent,
            trace_id: trace_id.clone(),
            request_body: Some(request_params),
            duration_ms,
            created_at,
        };

        let store = state.cert_store.clone();
        tokio::spawn(async move {
            if let Err(e) = store.insert_audit_log(row).await {
                tracing::warn!(error = %e, capture = %capture_state, "Failed to write audit log");
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

    #[test]
    fn parse_resource_handles_alpha_update_id() {
        let (rt, rid) = parse_resource("PUT", "/v1/system/configs/nonexistent");
        assert_eq!(rt, "system");
        assert_eq!(rid.as_deref(), Some("nonexistent"));
    }

    #[test]
    fn parse_resource_skips_collection_post() {
        let (rt, rid) = parse_resource("POST", "/v1/alerts/rules");
        assert_eq!(rt, "alerts");
        assert_eq!(rid, None);
    }

    #[test]
    fn parse_resource_extracts_id_before_action() {
        let (rt, rid) = parse_resource("POST", "/v1/notifications/channels/channel_alpha/test");
        assert_eq!(rt, "notifications");
        assert_eq!(rid.as_deref(), Some("channel_alpha"));
    }

    #[test]
    fn request_params_fallback_for_empty() {
        let payload = build_audit_request_params(
            "DELETE",
            "/v1/system/configs/abc",
            None,
            None,
            Some(&[]),
            "empty",
        );
        let v: Value = serde_json::from_str(&payload).expect("valid json");
        assert_eq!(v["meta"]["capture"], "empty");
        assert!(v["body"].is_null());
    }

    #[test]
    fn request_params_fallback_for_non_utf8() {
        let payload = build_audit_request_params(
            "POST",
            "/v1/x",
            Some("a=1&b=2"),
            Some("application/octet-stream"),
            Some(&[0xFF, 0x00, 0x7F]),
            "ok",
        );
        let v: Value = serde_json::from_str(&payload).expect("valid json");
        assert_eq!(v["meta"]["capture"], "ok");
        assert_eq!(v["query"]["a"], "1");
        assert_eq!(v["body"]["_fallback"], "non_utf8");
    }

    #[test]
    fn request_params_masks_login_encrypted_password() {
        let payload = build_audit_request_params(
            "POST",
            "/v1/auth/login",
            None,
            Some("application/json"),
            Some(br#"{"username":"admin","encrypted_password":"secret-cipher"}"#),
            "ok",
        );
        let v: Value = serde_json::from_str(&payload).expect("valid json");
        assert_eq!(v["body"]["username"], "admin");
        assert_eq!(v["body"]["encrypted_password"], "***");
    }

    #[test]
    fn request_params_masks_change_password_fields() {
        let payload = build_audit_request_params(
            "POST",
            "/v1/auth/password",
            None,
            Some("application/json"),
            Some(
                br#"{"encrypted_current_password":"old-cipher","encrypted_new_password":"new-cipher"}"#,
            ),
            "ok",
        );
        let v: Value = serde_json::from_str(&payload).expect("valid json");
        assert_eq!(v["body"]["encrypted_current_password"], "***");
        assert_eq!(v["body"]["encrypted_new_password"], "***");
    }
}
