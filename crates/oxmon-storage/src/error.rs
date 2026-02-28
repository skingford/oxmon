/// Errors that can occur within the storage layer.
///
/// # Migration note
///
/// The `StorageEngine` trait and `CertStore` currently return `anyhow::Result` for
/// backward compatibility. This module defines the target error type to be used as the
/// codebase is progressively migrated away from `anyhow`. New code should return
/// `storage::error::Result<T>` where possible.
///
/// # Examples
///
/// ```rust
/// use oxmon_storage::error::StorageError;
///
/// let err = StorageError::NotFound {
///     entity: "alert_rule",
///     id: "rule-99".to_string(),
/// };
/// assert!(err.to_string().contains("alert_rule"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A required record was not found in the database.
    #[error("Storage: {entity} not found (id={id})")]
    NotFound { entity: &'static str, id: String },

    /// An insert operation did not return the newly created row, which should be
    /// unreachable under normal conditions.
    #[error("Storage: insert of {entity} succeeded but the row could not be read back")]
    InsertReadback { entity: &'static str },

    /// An underlying SQLite error.
    #[error("Storage: SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// JSON serialization or deserialization failure (e.g. config_json columns).
    #[error("Storage: JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The stored value is not a valid UTF-8 string.
    #[error("Storage: invalid UTF-8 in column '{column}': {source}")]
    InvalidUtf8 {
        column: &'static str,
        source: std::string::FromUtf8Error,
    },

    /// A column contained an unexpected SQLite value type.
    #[error("Storage: unexpected value type in column '{column}': expected {expected}")]
    UnexpectedColumnType {
        column: &'static str,
        expected: &'static str,
    },

    /// Generic storage error for cases not covered by other variants.
    #[error("Storage: {0}")]
    Other(String),
}

/// Convenience `Result` alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;
