//! What the federation endpoints answer: the response value every handler returns, and the error
//! response of OpenID Federation 1.0,
//! [Section 8.9](https://openid.net/specs/openid-federation-1_0.html#section-8.9).
//!
//! The crate depends on no web framework (ADR 0005). A handler returns an [`EndpointResponse`],
//! and the application turns its status, content type and body into the response of its own
//! framework.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// The content type of an [`ErrorResponse`] and of the other JSON responses of the federation
/// endpoints.
pub const JSON_CONTENT_TYPE: &str = "application/json";

/// What a federation endpoint handler answers: the HTTP status, the content type and the body.
///
/// An [`ErrorResponse`] converts into one with its recommended status and
/// [`JSON_CONTENT_TYPE`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndpointResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The value of the `Content-Type` header.
    pub content_type: String,
    /// The response body.
    pub body: String,
}

impl EndpointResponse {
    /// A response with the given status, content type and body.
    pub fn new(status: u16, content_type: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: content_type.into(),
            body: body.into(),
        }
    }
}

impl From<ErrorResponse> for EndpointResponse {
    fn from(error: ErrorResponse) -> Self {
        error.to_endpoint_response()
    }
}

/// An error code of a federation endpoint error response (Section 8.9).
///
/// The codes the specification uses are variants; any other code, such as one from the IANA
/// "OAuth Extensions Error Registry", is [`ErrorCode::Other`]. Parsing a code the specification
/// uses always yields its variant, never `Other`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `invalid_request`: the request is incomplete or does not comply with the specification.
    InvalidRequest,
    /// `server_error`: an unexpected condition prevented the server from fulfilling the request.
    ServerError,
    /// `temporarily_unavailable`: the server is overloaded or under maintenance.
    TemporarilyUnavailable,
    /// `invalid_client`: the client cannot be authorized or is not a valid participant of the
    /// federation.
    InvalidClient,
    /// `invalid_issuer`: the endpoint cannot serve the requested issuer.
    InvalidIssuer,
    /// `invalid_subject`: the endpoint cannot serve the requested subject.
    InvalidSubject,
    /// `invalid_trust_anchor`: the Trust Anchor cannot be found or used.
    InvalidTrustAnchor,
    /// `not_found`: the requested Entity Identifier cannot be found.
    NotFound,
    /// `invalid_trust_chain`: the Trust Chain cannot be validated.
    InvalidTrustChain,
    /// `invalid_metadata`: Metadata or Metadata Policy values are invalid or conflict.
    InvalidMetadata,
    /// `unsupported_parameter`: the server does not support the requested parameter.
    UnsupportedParameter,
    /// Any other error code, spelled as it is sent.
    Other(String),
}

impl ErrorCode {
    /// The code as it is spelled on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidClient => "invalid_client",
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidSubject => "invalid_subject",
            Self::InvalidTrustAnchor => "invalid_trust_anchor",
            Self::NotFound => "not_found",
            Self::InvalidTrustChain => "invalid_trust_chain",
            Self::InvalidMetadata => "invalid_metadata",
            Self::UnsupportedParameter => "unsupported_parameter",
            Self::Other(code) => code,
        }
    }

    /// The HTTP status code Section 8.9 recommends for this code.
    ///
    /// [`ErrorCode::Other`] has no recommended status and gets 400 (Bad Request); to answer with
    /// another status, build the [`EndpointResponse`] with
    /// [`ErrorResponse::to_endpoint_response_with_status`].
    pub fn status(&self) -> u16 {
        match self {
            Self::InvalidRequest
            | Self::InvalidTrustChain
            | Self::InvalidMetadata
            | Self::UnsupportedParameter
            | Self::Other(_) => 400,
            Self::InvalidClient => 401,
            Self::InvalidIssuer | Self::InvalidSubject | Self::InvalidTrustAnchor | Self::NotFound => 404,
            Self::ServerError => 500,
            Self::TemporarilyUnavailable => 503,
        }
    }
}

impl From<&str> for ErrorCode {
    fn from(code: &str) -> Self {
        match code {
            "invalid_request" => Self::InvalidRequest,
            "server_error" => Self::ServerError,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "invalid_client" => Self::InvalidClient,
            "invalid_issuer" => Self::InvalidIssuer,
            "invalid_subject" => Self::InvalidSubject,
            "invalid_trust_anchor" => Self::InvalidTrustAnchor,
            "not_found" => Self::NotFound,
            "invalid_trust_chain" => Self::InvalidTrustChain,
            "invalid_metadata" => Self::InvalidMetadata,
            "unsupported_parameter" => Self::UnsupportedParameter,
            other => Self::Other(other.to_string()),
        }
    }
}

impl From<String> for ErrorCode {
    fn from(code: String) -> Self {
        match Self::from(code.as_str()) {
            Self::Other(_) => Self::Other(code),
            known => known,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// The error response of a federation endpoint (Section 8.9): a JSON object with `error` and
/// `error_description`, served as [`JSON_CONTENT_TYPE`].
///
/// `error_description` is REQUIRED, so it is always serialized. A response that omits it still
/// parses, with an empty description, so a client keeps the error code of a server that leaves it
/// out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error code.
    pub error: ErrorCode,
    /// Human-readable text that helps a developer understand the error.
    #[serde(default)]
    pub error_description: String,
}

impl ErrorResponse {
    /// An error response with `error` and `error_description`.
    pub fn new(error: ErrorCode, error_description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: error_description.into(),
        }
    }

    /// The HTTP status Section 8.9 recommends for this error, see [`ErrorCode::status`].
    pub fn status(&self) -> u16 {
        self.error.status()
    }

    /// The JSON body of this error response.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "error": self.error.as_str(),
            "error_description": self.error_description,
        })
        .to_string()
    }

    /// This error as an endpoint response with its recommended status.
    pub fn to_endpoint_response(&self) -> EndpointResponse {
        self.to_endpoint_response_with_status(self.status())
    }

    /// This error as an endpoint response with `status`, such as 502 for a `server_error` caused
    /// by an upstream federation entity.
    pub fn to_endpoint_response_with_status(&self, status: u16) -> EndpointResponse {
        EndpointResponse::new(status, JSON_CONTENT_TYPE, self.to_json())
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.error_description.is_empty() {
            write!(f, "{}", self.error)
        } else {
            write!(f, "{}: {}", self.error, self.error_description)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODES: [(ErrorCode, &str, u16); 11] = [
        (ErrorCode::InvalidRequest, "invalid_request", 400),
        (ErrorCode::ServerError, "server_error", 500),
        (ErrorCode::TemporarilyUnavailable, "temporarily_unavailable", 503),
        (ErrorCode::InvalidClient, "invalid_client", 401),
        (ErrorCode::InvalidIssuer, "invalid_issuer", 404),
        (ErrorCode::InvalidSubject, "invalid_subject", 404),
        (ErrorCode::InvalidTrustAnchor, "invalid_trust_anchor", 404),
        (ErrorCode::NotFound, "not_found", 404),
        (ErrorCode::InvalidTrustChain, "invalid_trust_chain", 400),
        (ErrorCode::InvalidMetadata, "invalid_metadata", 400),
        (ErrorCode::UnsupportedParameter, "unsupported_parameter", 400),
    ];

    #[test]
    fn every_code_has_its_spelling_and_status() {
        for (code, spelling, status) in CODES {
            assert_eq!(code.as_str(), spelling);
            assert_eq!(code.to_string(), spelling);
            assert_eq!(code.status(), status, "{spelling}");
            assert_eq!(serde_json::to_value(&code).unwrap(), serde_json::json!(spelling));
            assert_eq!(serde_json::from_value::<ErrorCode>(spelling.into()).unwrap(), code);
            assert_eq!(ErrorCode::from(spelling.to_string()), code);
        }
    }

    #[test]
    fn other_codes_keep_their_spelling() {
        let code: ErrorCode = serde_json::from_str("\"access_denied\"").unwrap();
        assert_eq!(code, ErrorCode::Other("access_denied".to_string()));
        assert_eq!(serde_json::to_string(&code).unwrap(), "\"access_denied\"");
        assert_eq!(code.status(), 400);
    }

    #[test]
    fn error_response_becomes_a_json_endpoint_response() {
        let error = ErrorResponse::new(ErrorCode::NotFound, "Unknown subject https://op.example.org");
        let response = EndpointResponse::from(error.clone());

        assert_eq!(response.status, 404);
        assert_eq!(response.content_type, "application/json");
        let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "error": "not_found",
                "error_description": "Unknown subject https://op.example.org",
            })
        );
        assert_eq!(serde_json::from_str::<ErrorResponse>(&response.body).unwrap(), error);

        let response = error.to_endpoint_response_with_status(502);
        assert_eq!(response.status, 502);
    }

    #[test]
    fn error_response_without_description_still_parses() {
        let error: ErrorResponse = serde_json::from_str(r#"{"error":"invalid_client"}"#).unwrap();
        assert_eq!(error, ErrorResponse::new(ErrorCode::InvalidClient, ""));
        assert_eq!(error.to_string(), "invalid_client");
        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::json!({ "error": "invalid_client", "error_description": "" })
        );
    }
}
