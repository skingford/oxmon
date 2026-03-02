//! Utility functions for notification channels

/// Maximum length for request/response body stored in database
pub const MAX_BODY_LENGTH: usize = 4000;

/// Truncate a string to the specified maximum length (respects UTF-8 char boundaries)
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Walk backwards from max_len to find a valid UTF-8 char boundary
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}... [truncated]", &s[..end])
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
}
