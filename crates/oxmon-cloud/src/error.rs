/// Errors that can occur when interacting with a cloud provider API.
///
/// # Examples
///
/// ```rust
/// use oxmon_cloud::error::CloudProviderError;
///
/// let err = CloudProviderError::UnsupportedProvider("openstack".to_string());
/// assert!(err.to_string().contains("openstack"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum CloudProviderError {
    /// HTTP-level error: non-2xx status code from the cloud API.
    #[error("{provider} API HTTP error: status={status}, body={body}")]
    HttpError {
        provider: String,
        status: u16,
        body: String,
    },

    /// API returned a 2xx status but the response payload indicates a logical error.
    #[error("{provider} API error: code={code}, message={message}")]
    ApiResponseError {
        provider: String,
        code: String,
        message: String,
    },

    /// Request was throttled by the cloud provider. Callers may retry after backoff.
    #[error("{provider} API rate limited, retry after backoff")]
    RateLimited { provider: String },

    /// HMAC signing failed (invalid key length or algorithm mismatch).
    #[error("HMAC signing error: {0}")]
    HmacError(String),

    /// An underlying HTTP transport error from `reqwest`.
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    /// JSON serialization or deserialization failure.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// The requested cloud provider type is not registered.
    #[error("Unsupported cloud provider: {0}")]
    UnsupportedProvider(String),

    /// Account configuration is missing or invalid.
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Convenience type alias so callers can write `error::Result<T>`.
pub type Result<T> = std::result::Result<T, CloudProviderError>;
