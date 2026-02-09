use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue},
    middleware::Next,
    response::Response,
};
use chrono::{FixedOffset, Utc};
use rand::Rng;
use std::fmt::Write;
use std::time::Instant;

/// Generate a 16-character hex trace ID (8 random bytes).
fn generate_trace_id() -> String {
    let bytes: [u8; 8] = rand::thread_rng().gen();
    let mut s = String::with_capacity(16);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ANSI color codes
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const GRAY: &str = "\x1b[90m";
const RESET: &str = "\x1b[0m";

/// Maximum number of characters to log from response body.
const MAX_BODY_LOG_CHARS: usize = 200;

/// Request/response logging middleware.
pub async fn request_logging(req: Request, next: Next) -> Response {
    let trace_id = generate_trace_id();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    // Skip logging for Swagger UI static assets
    if path.starts_with("/docs") {
        return next.run(req).await;
    }

    let query = uri.query().unwrap_or("");
    let tz = FixedOffset::east_opt(8 * 3600).unwrap();
    let now = Utc::now().with_timezone(&tz).format("%Y-%m-%d %H:%M:%S");
    let start = Instant::now();

    // Log request
    if query.is_empty() {
        println!("{GRAY}{now}{RESET} {CYAN}-->{RESET} [{trace_id}] {method} {path}");
    } else {
        println!("{GRAY}{now}{RESET} {CYAN}-->{RESET} [{trace_id}] {method} {path}?{query}");
    }

    // Execute the handler
    let response = next.run(req).await;

    let elapsed_us = start.elapsed().as_micros();
    let elapsed = if elapsed_us < 1000 {
        format!("{elapsed_us}µs")
    } else {
        format!("{}ms", elapsed_us / 1000)
    };
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

    let body_snippet = if is_json {
        match std::str::from_utf8(&body_bytes) {
            Ok(s) if s.len() > MAX_BODY_LOG_CHARS => {
                format!("{}...", &s[..MAX_BODY_LOG_CHARS])
            }
            Ok(s) => s.to_string(),
            Err(_) => "<non-utf8 body>".to_string(),
        }
    } else {
        String::new()
    };

    // Pick color based on status code
    let status_color = if status.is_success() {
        GREEN
    } else if status.is_client_error() {
        YELLOW
    } else {
        RED
    };

    let tz = FixedOffset::east_opt(8 * 3600).unwrap();
    let now = Utc::now().with_timezone(&tz).format("%Y-%m-%d %H:%M:%S");

    // Log response
    if body_snippet.is_empty() {
        println!(
            "{GRAY}{now}{RESET} {status_color}<--{RESET} [{trace_id}] {status} {GRAY}{elapsed}{RESET}"
        );
    } else {
        println!(
            "{GRAY}{now}{RESET} {status_color}<--{RESET} [{trace_id}] {status} {GRAY}{elapsed}{RESET} {body_snippet}"
        );
    }

    // Rebuild response with X-Trace-Id header
    let mut response = Response::from_parts(parts, Body::from(body_bytes));
    if let Ok(val) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert("X-Trace-Id", val);
    }

    response
}
