//! The Trust Mark endpoint: a Trust Mark Issuer hands out there the Trust Marks it issued
//! (OpenID Federation 1.0, Section 8.6).

use super::{
    entity_id_parameter, required_parameter, EndpointRequest, EndpointResponse, ErrorCode, ErrorResponse,
    TRUST_MARK_CONTENT_TYPE,
};
use crate::{FederationResult, TrustMarkStatus, TrustMarkStore};
use chrono::Utc;
use std::fmt;
use std::sync::Arc;

/// Serves the Trust Marks in a [`TrustMarkStore`] to their subjects.
///
/// A request is a `GET` with the parameters in the query, or a `POST` with them in the body when
/// client authentication is used (Section 8.6.1). Authenticating the client, and deciding whether
/// a client other than the subject may fetch its Trust Mark, is the application's concern: it
/// checks the request before calling the handler. Unknown parameters are ignored (Section 8).
///
/// | Request                                                  | Response                                                    |
/// | -------------------------------------------------------- | ----------------------------------------------------------- |
/// | `sub` holds an active Trust Mark of `trust_mark_type`    | `200`, [`TRUST_MARK_CONTENT_TYPE`], the Trust Mark JWT       |
/// | `sub` holds none: never issued, revoked or expired       | `404 not_found`                                             |
/// | `trust_mark_type` or `sub` missing or repeated; `sub` not an Entity Identifier | `400 invalid_request`                 |
/// | the store fails                                          | `500 server_error`                                          |
///
/// A Trust Mark is active while it is neither revoked nor expired and its `iat` is at most 60
/// seconds ahead, the clock skew allowed, see
/// [`IssuedTrustMark::status_at`](crate::IssuedTrustMark::status_at). When the subject holds
/// several active Trust Marks of the type, the endpoint serves the one issued last, by `iat`. The
/// records the store returns are checked against the request, so a store that answers too broadly
/// does not hand out the Trust Mark of another entity or type.
///
/// Reference: OpenID Federation 1.0 - Section 8.6 Trust Mark Endpoint
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.6>)
pub struct TrustMarkEndpoint {
    trust_marks: Arc<dyn TrustMarkStore>,
}

impl TrustMarkEndpoint {
    /// An endpoint that serves the Trust Marks in `trust_marks`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.6 Trust Mark Endpoint
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.6>)
    pub fn new(trust_marks: Arc<dyn TrustMarkStore>) -> Self {
        Self { trust_marks }
    }

    /// Answers a Trust Mark request, see the table on [`TrustMarkEndpoint`].
    ///
    /// A `server_error` response does not say why. Call [`try_handle`](Self::try_handle) to
    /// learn it.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.6.2 Trust Mark Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.6.2>)
    pub async fn handle(&self, request: &EndpointRequest) -> EndpointResponse {
        self.try_handle(request).await.unwrap_or_else(|_| {
            ErrorResponse::new(ErrorCode::ServerError, "the Trust Mark could not be served").to_endpoint_response()
        })
    }

    /// Like [`handle`](Self::handle), but returns why the Trust Mark could not be served instead
    /// of the `server_error` response. Errors in the request are still answered with their error
    /// response.
    ///
    /// # Errors
    ///
    /// [`FederationError::Store`](crate::FederationError::Store) when the store fails.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.6.2 Trust Mark Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.6.2>)
    pub async fn try_handle(&self, request: &EndpointRequest) -> FederationResult<EndpointResponse> {
        let (trust_mark_type, sub) = match (
            required_parameter(request, "trust_mark_type"),
            entity_id_parameter(request, "sub"),
        ) {
            (Ok(trust_mark_type), Ok(Some(sub))) => (trust_mark_type, sub),
            (Ok(_), Ok(None)) => {
                return Ok(
                    ErrorResponse::new(ErrorCode::InvalidRequest, "the sub parameter is required")
                        .to_endpoint_response(),
                )
            }
            (Err(error), _) | (_, Err(error)) => return Ok(error.to_endpoint_response()),
        };

        let now = Utc::now().timestamp();
        let issued = self.trust_marks.trust_marks(Some(trust_mark_type), Some(&sub)).await?;
        let latest = issued
            .iter()
            .filter(|issued| {
                issued.claims.trust_mark_type == trust_mark_type
                    && issued.claims.sub == sub
                    && issued.status_at(now) == TrustMarkStatus::Active
            })
            // The JWT breaks a tie, so that the same store gives the same response.
            .max_by(|a, b| a.claims.iat.cmp(&b.claims.iat).then_with(|| a.jwt.cmp(&b.jwt)));

        Ok(match latest {
            Some(issued) => EndpointResponse::new(200, TRUST_MARK_CONTENT_TYPE, issued.jwt.as_str()),
            None => ErrorResponse::new(
                ErrorCode::NotFound,
                format!("{sub} has no active Trust Mark of type {trust_mark_type}"),
            )
            .to_endpoint_response(),
        })
    }
}

impl fmt::Debug for TrustMarkEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustMarkEndpoint").finish_non_exhaustive()
    }
}
