//! Error types for OpenID Federation operations.

use std::error::Error as StdError;
use std::fmt;
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

    #[error("Invalid JWT header 'typ' claim: {0}")]
    InvalidJwtHeaderTyp(String),

    /// A [`Signer`](crate::Signer) failed to sign
    #[error("Signing error: {0}")]
    Signing(#[from] SignError),
}

/// An error from a [`Signer`](crate::Signer).
///
/// Signers live in memory, in HSMs and in cloud key management services, each with its own error
/// type; this wraps any of them.
#[derive(Debug)]
pub struct SignError(Box<dyn StdError + Send + Sync + 'static>);

impl SignError {
    /// Wraps `error`.
    pub fn new<E: StdError + Send + Sync + 'static>(error: E) -> Self {
        Self(Box::new(error))
    }

    /// Wraps a message.
    pub fn msg<M: fmt::Display>(message: M) -> Self {
        Self(message.to_string().into())
    }

    /// The wrapped error.
    pub fn inner(&self) -> &(dyn StdError + Send + Sync + 'static) {
        self.0.as_ref()
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl StdError for SignError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.0.source()
    }
}

/// Result type for OpenID Federation operations.
pub type FederationResult<T> = Result<T, FederationError>;
