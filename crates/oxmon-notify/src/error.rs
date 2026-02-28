/// Errors that can occur within the notification subsystem.
///
/// # Migration note
///
/// The `NotificationChannel` trait and plugin implementations currently return
/// `anyhow::Result` for backward compatibility. This module defines the target
/// error type for progressive migration. New channel implementations should return
/// `notify::error::Result<T>` where possible.
///
/// # Examples
///
/// ```rust
/// use oxmon_notify::error::NotifyError;
///
/// let err = NotifyError::InvalidConfig("missing smtp_host".to_string());
/// assert!(err.to_string().contains("smtp_host"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    /// Channel configuration is missing a required field or contains an invalid value.
    #[error("Notify: invalid channel configuration: {0}")]
    InvalidConfig(String),

    /// The channel type is not registered in the plugin registry.
    #[error("Notify: unknown channel type '{0}'")]
    UnknownChannelType(String),

    /// An HTTP request to an external notification endpoint failed.
    #[error("Notify: HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// SMTP transport error when sending email.
    #[error("Notify: SMTP error: {0}")]
    SmtpError(String),

    /// JSON serialization or deserialization failed (e.g. config_json parsing).
    #[error("Notify: JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// The external API returned a non-success response.
    #[error("Notify: API error from {service}: status={status}, body={body}")]
    ApiError {
        service: String,
        status: u16,
        body: String,
    },

    /// Rendering a notification template failed.
    #[error("Notify: template rendering error: {0}")]
    TemplateError(String),

    /// Generic notification error for cases not covered by other variants.
    #[error("Notify: {0}")]
    Other(String),
}

/// Convenience `Result` alias for notification operations.
pub type Result<T> = std::result::Result<T, NotifyError>;
