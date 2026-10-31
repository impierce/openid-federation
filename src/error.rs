//! Error types for OpenID Federation operations.

use crate::ErrorResponse;
use std::error::Error as StdError;
use std::fmt;
use thiserror::Error;
use url::Url;

/// The main error type for OpenID Federation operations.
///
/// New variants are not breaking changes, so a `match` on it needs a wildcard arm.
#[derive(Error, Debug)]
#[non_exhaustive]
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

    /// A federation endpoint, or a configuration endpoint, answered with an HTTP status other than
    /// 2xx
    #[error("{0}")]
    Endpoint(Box<EndpointError>),
}

impl From<EndpointError> for FederationError {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(Box::new(error))
    }
}

/// An HTTP response with a status other than 2xx from a federation endpoint or a configuration
/// endpoint, see [`FederationError::Endpoint`].
///
/// Federation endpoints answer errors with the error response of OpenID Federation 1.0,
/// [Section 8.9](https://openid.net/specs/openid-federation-1_0.html#section-8.9).
///
/// Reference: OpenID Federation 1.0 - Section 8.9 Error Responses
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.9>)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointError {
    /// The URL that was requested.
    pub url: Url,
    /// The HTTP status code of the response.
    pub status: u16,
    /// The error response the body carried, or `None` when the body was not one.
    pub response: Option<ErrorResponse>,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} answered HTTP {}", self.url, self.status)?;
        match &self.response {
            Some(response) => write!(f, ": {response}"),
            None => Ok(()),
        }
    }
}

impl StdError for EndpointError {}

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
