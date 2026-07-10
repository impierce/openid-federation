//! Error types for OpenID Federation operations.

use thiserror::Error;

/// The main error type for OpenID Federation operations.
#[derive(Error, Debug)]
pub enum FederationError {
    /// JWT-related errors
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Serialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// URL parsing errors
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),

    /// HTTP request errors
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// Invalid subordinate statement
    #[error("Invalid subordinate statement: {0}")]
    InvalidSubordinateStatement(String),

    /// Trust chain validation error
    #[error("Trust chain validation error: {0}")]
    TrustChainValidation(String),

    /// Entity resolution error
    #[error("Entity resolution error: {0}")]
    EntityResolution(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid metadata
    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),

    /// Federation configuration error
    #[error("Federation configuration error: {0}")]
    Configuration(String),
}

/// Result type for OpenID Federation operations.
pub type FederationResult<T> = Result<T, FederationError>;
