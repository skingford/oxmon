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

fn now_str() -> String {
    let tz = FixedOffset::east_opt(8 * 3600).unwrap();
    Utc::now()
        .with_timezone(&tz)
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string()
}

// ANSI color codes
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const MAGENTA: &str = "\x1b[35m";
const BLUE: &str = "\x1b[34m";
const GRAY: &str = "\x1b[90m";
const RESET: &str = "\x1b[0m";

/// Color HTTP method: GET=green, POST=cyan, PUT=yellow, DELETE=red, PATCH=magenta, others=blue.
fn method_color(method: &axum::http::Method) -> &'static str {
    match method.as_str() {
        "GET" => GREEN,
        "POST" => CYAN,
        "PUT" => YELLOW,
        "DELETE" => RED,
        "PATCH" => MAGENTA,
        _ => BLUE,
    }
}

/// Maximum number of characters to log from request/response body.
const MAX_BODY_LOG_CHARS: usize = 200;

/// Truncate a UTF-8 string to at most `max` characters, appending "..." if truncated.
fn truncate_body(bytes: &[u8], max: usize) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.len() > max => format!("{}...", &s[..max]),
        Ok(s) => s.to_string(),
        Err(_) => "<non-utf8 body>".to_string(),
    }
}

/// Format elapsed time with color: green <100ms, yellow 100ms-1s, red >1s.
fn format_elapsed(elapsed_us: u128) -> String {
    let (time_str, color) = if elapsed_us < 1000 {
        (format!("{elapsed_us}µs"), GREEN)
    } else if elapsed_us < 100_000 {
        (format!("{}ms", elapsed_us / 1000), GREEN)
    } else if elapsed_us < 1_000_000 {
        (format!("{}ms", elapsed_us / 1000), YELLOW)
    } else {
        (format!("{:.1}s", elapsed_us as f64 / 1_000_000.0), RED)
    };
    format!("{color}{time_str}{RESET}")
}

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
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let mc = method_color(&method);

    // Sensitive paths: never log request/response bodies for these
    let is_sensitive = path.starts_with("/v1/auth/")
        || path.starts_with("/v1/agents/whitelist");

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

    let start = Instant::now();

    // Log request
    let url = if query.is_empty() {
        path.clone()
    } else {
        format!("{path}?{query}")
    };

    // Build request log params
    let mut params = String::new();
    if !req_body_snippet.is_empty() {
        let _ = write!(params, " {CYAN}body={RESET}{req_body_snippet}");
    }

    println!(
        "{GRAY}{}{RESET} {CYAN}-->{RESET} [{trace_id}] {mc}{method}{RESET} {url}{params} {GRAY}ua={user_agent}{RESET}",
        now_str()
    );

    // Execute the handler
    let response = next.run(req).await;

    let elapsed_us = start.elapsed().as_micros();
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

    // Status code color: green 2xx, yellow 4xx, red 5xx/others
    let status_color = if status.is_success() {
        GREEN
    } else if status.is_client_error() {
        YELLOW
    } else {
        RED
    };

    let elapsed_colored = format_elapsed(elapsed_us);
    let status_colored = format!("{status_color}{status}{RESET}");

    // Body color: gray for success, red for errors
    let body_color = if status.is_success() { GRAY } else { RED };

    // Log response
    if body_snippet.is_empty() {
        println!(
            "{GRAY}{}{RESET} {status_color}<--{RESET} [{trace_id}] {status_colored} {elapsed_colored}",
            now_str()
        );
    } else {
        println!(
            "{GRAY}{}{RESET} {status_color}<--{RESET} [{trace_id}] {status_colored} {elapsed_colored} {body_color}{body_snippet}{RESET}",
            now_str()
        );
    }

    // Rebuild response with X-Trace-Id header
    let mut response = Response::from_parts(parts, Body::from(body_bytes));
    if let Ok(val) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert("X-Trace-Id", val);
    }

    response
}
