//! Utility functions for notification channels

use serde_json::Value;

/// Maximum length for request/response body stored in database
pub const MAX_BODY_LENGTH: usize = 4000;

/// Truncate a string to the specified maximum length
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}... [truncated]", &s[..max_len])
    }
}

/// Redact sensitive fields from JSON configuration
///
/// Removes values for fields that commonly contain sensitive information:
/// - password, passwd, pwd
/// - token, access_token, refresh_token
/// - secret, client_secret, access_key_secret
/// - api_key, apikey
/// - credentials
pub fn redact_sensitive_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                let is_sensitive = key_lower.contains("password")
                    || key_lower.contains("passwd")
                    || key_lower.contains("pwd")
                    || key_lower.contains("token")
                    || key_lower.contains("secret")
                    || key_lower.contains("api_key")
                    || key_lower.contains("apikey")
                    || key_lower.contains("credentials");

                if is_sensitive {
                    redacted.insert(key.clone(), Value::String("***".to_string()));
                } else if val.is_object() || val.is_array() {
                    // Recursively redact nested objects/arrays
                    redacted.insert(key.clone(), redact_sensitive_json(val));
                } else {
                    redacted.insert(key.clone(), val.clone());
                }
            }
            Value::Object(redacted)
        }
        Value::Array(arr) => {
            let redacted: Vec<Value> = arr.iter().map(redact_sensitive_json).collect();
            Value::Array(redacted)
        }
        _ => value.clone(),
    }
}

/// Redact sensitive fields from a JSON string
pub fn redact_json_string(json_str: &str) -> String {
    match serde_json::from_str::<Value>(json_str) {
        Ok(value) => {
            let redacted = redact_sensitive_json(&value);
            serde_json::to_string(&redacted).unwrap_or_else(|_| json_str.to_string())
        }
        Err(_) => json_str.to_string(), // Return original if not valid JSON
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 5), "hello... [truncated]");
    }

    #[test]
    fn test_redact_sensitive_json() {
        let json = serde_json::json!({
            "username": "admin",
            "password": "secret123",
            "api_key": "abc123",
            "smtp_host": "smtp.example.com",
            "nested": {
                "access_token": "xyz789",
                "public_value": "visible"
            }
        });

        let redacted = redact_sensitive_json(&json);
        assert_eq!(redacted["username"], "admin");
        assert_eq!(redacted["password"], "***");
        assert_eq!(redacted["api_key"], "***");
        assert_eq!(redacted["smtp_host"], "smtp.example.com");
        assert_eq!(redacted["nested"]["access_token"], "***");
        assert_eq!(redacted["nested"]["public_value"], "visible");
    }

    #[test]
    fn test_redact_json_string() {
        let json_str = r#"{"username":"admin","password":"secret"}"#;
        let redacted = redact_json_string(json_str);
        assert!(redacted.contains("admin"));
        assert!(redacted.contains("***"));
        assert!(!redacted.contains("secret"));
    }
}
