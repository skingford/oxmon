use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue},
    middleware::Next,
    response::Response,
};
use rand::Rng;
use std::fmt::Write;
use std::time::Instant;

/// Newtype wrapper for trace IDs stored in request extensions.
///
/// Using a dedicated type instead of bare `String` prevents conflicts
/// with other extensions and avoids silent 500 errors when the
/// extension is missing.
#[derive(Clone)]
pub struct TraceId(pub String);

impl std::ops::Deref for TraceId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

/// Generate a 16-character hex trace ID (8 random bytes).
fn generate_trace_id() -> String {
    let bytes: [u8; 8] = rand::thread_rng().gen();
    let mut s = String::with_capacity(16);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Maximum number of characters to log from request/response body.
const MAX_BODY_LOG_CHARS: usize = 200;

/// Truncate a UTF-8 string to at most `max` bytes, snapping to the nearest
/// char boundary so we never split a multi-byte character.
fn truncate_body(bytes: &[u8], max: usize) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.len() > max => {
            // Walk backward from `max` to find a valid char boundary
            let mut end = max;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &s[..end])
        }
        Ok(s) => s.to_string(),
        Err(_) => "<non-utf8 body>".to_string(),
    }
}

/// Format elapsed time as a human-readable string.
fn format_elapsed(elapsed_us: u128) -> String {
    if elapsed_us < 1000 {
        format!("{elapsed_us}µs")
    } else if elapsed_us < 1_000_000 {
        format!("{}ms", elapsed_us / 1000)
    } else {
        format!("{:.1}s", elapsed_us as f64 / 1_000_000.0)
    }
}

/// Request/response logging middleware.
pub async fn request_logging(mut req: Request, next: Next) -> Response {
    let trace_id = generate_trace_id();

    // Insert trace_id into request extensions for handlers to access
    req.extensions_mut().insert(TraceId(trace_id.clone()));

    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    // Skip logging for Swagger UI static assets
    if path.starts_with("/docs") {
        return next.run(req).await;
    }

    let query = uri.query().unwrap_or("");
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let app_id = req
        .headers()
        .get("ox-app-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // Sensitive paths: never log request/response bodies for these
    let is_sensitive = path.starts_with("/v1/auth/") || path.starts_with("/v1/agents/whitelist");

    // Read request body for logging (POST/PUT/PATCH), but skip sensitive endpoints
    let has_body = !is_sensitive && matches!(method.as_str(), "POST" | "PUT" | "PATCH");
    let (req, req_body_snippet) = if has_body {
        let (parts, body) = req.into_parts();
        let body_bytes = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .unwrap_or_default();
        let snippet = if body_bytes.is_empty() {
            String::new()
        } else {
            truncate_body(&body_bytes, MAX_BODY_LOG_CHARS)
        };
        let req = Request::from_parts(parts, Body::from(body_bytes));
        (req, snippet)
    } else {
        (req, String::new())
    };

    let url = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };

    // Log request
    if req_body_snippet.is_empty() {
        tracing::info!(
            trace_id = %trace_id,
            method = %method,
            path = %url,
            app_id = %app_id,
            ua = %user_agent,
            "--> request"
        );
    } else {
        tracing::info!(
            trace_id = %trace_id,
            method = %method,
            path = %url,
            app_id = %app_id,
            body = %req_body_snippet,
            ua = %user_agent,
            "--> request"
        );
    }

    let start = Instant::now();

    // Execute the handler
    let response = next.run(req).await;

    let elapsed = format_elapsed(start.elapsed().as_micros());
    let status = response.status();

    // Collect response body for logging
    let (parts, body) = response.into_parts();

    let is_json = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();

    let body_snippet = if !is_sensitive && is_json && !body_bytes.is_empty() {
        truncate_body(&body_bytes, MAX_BODY_LOG_CHARS)
    } else {
        String::new()
    };

    // Log response with appropriate level based on status code
    let status_code = status.as_u16();
    if status.is_server_error() {
        tracing::error!(
            trace_id = %trace_id,
            status = status_code,
            elapsed = %elapsed,
            body = %body_snippet,
            "<-- response"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            trace_id = %trace_id,
            status = status_code,
            elapsed = %elapsed,
            body = %body_snippet,
            "<-- response"
        );
    } else if body_snippet.is_empty() {
        tracing::info!(
            trace_id = %trace_id,
            status = status_code,
            elapsed = %elapsed,
            "<-- response"
        );
    } else {
        tracing::info!(
            trace_id = %trace_id,
            status = status_code,
            elapsed = %elapsed,
            body = %body_snippet,
            "<-- response"
        );
    }

    // Rebuild response with X-Trace-Id header
    let mut response = Response::from_parts(parts, Body::from(body_bytes));
    if let Ok(val) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert("X-Trace-Id", val);
    }

    response
}
