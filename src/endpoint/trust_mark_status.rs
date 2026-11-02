//! The Trust Mark Status endpoint: a Trust Mark Issuer reports there whether a Trust Mark it
//! issued is still active (OpenID Federation 1.0, Section 8.4).

use super::{
    EndpointRequest, EndpointResponse, ErrorCode, ErrorResponse, HttpMethod, TRUST_MARK_STATUS_RESPONSE_CONTENT_TYPE,
};
use crate::store::trust_mark_claims;
use crate::{
    EntityId, FederationError, FederationResult, Signer, TrustMarkStatus, TrustMarkStatusResponse, TrustMarkStore,
};
use chrono::Utc;
use std::fmt;
use std::sync::Arc;

/// Reports the status of the Trust Marks in a [`TrustMarkStore`], as a
/// `trust-mark-status-response+jwt` signed with a key of the Trust Mark Issuer.
///
/// A request is a `POST` with the `trust_mark` parameter in its form body (Section 8.4.1).
/// Authenticating the client, when the federation uses it, is the application's concern: it
/// checks the request before calling the handler, which ignores every parameter but
/// `trust_mark` (Section 8).
///
/// | Request                                                       | Response                                                   |
/// | ------------------------------------------------------------- | ---------------------------------------------------------- |
/// | a Trust Mark in the store                                      | `200`, status `revoked`, `expired` from its `exp` on, or `active` |
/// | a Trust Mark by this issuer whose type and subject the store holds, but not this JWT | `200`, status `invalid`: not a Trust Mark the issuer recorded |
/// | any other Trust Mark JWT                                       | `404 not_found`                                            |
/// | not a `POST`; `trust_mark` missing, repeated or not a `trust-mark+jwt` | `400 invalid_request`                              |
/// | the store or the signer fails                                  | `500 server_error`                                         |
///
/// The store is looked up by the exact JWT, since a Trust Mark Issuer records the Trust Marks it
/// issues and the store is its record. A JWT that claims to be by the issuer, about a subject and
/// type it issued, but that the store does not hold, was altered, signed by someone else, or
/// signed without being recorded; Section 8.4.2 calls each of these `invalid`. The JWT is checked
/// to be a `trust-mark+jwt` before the store is asked.
///
/// Reference: OpenID Federation 1.0 - Section 8.4 Trust Mark Status
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4>)
pub struct TrustMarkStatusEndpoint {
    issuer: EntityId,
    trust_marks: Arc<dyn TrustMarkStore>,
    signer: Arc<dyn Signer>,
}

impl TrustMarkStatusEndpoint {
    /// An endpoint that reports, for `issuer`, the status of the Trust Marks in `trust_marks`,
    /// signed with `signer`, one of the issuer's Federation Entity Keys.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.4 Trust Mark Status
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4>)
    pub fn new(issuer: EntityId, trust_marks: Arc<dyn TrustMarkStore>, signer: Arc<dyn Signer>) -> Self {
        Self {
            issuer,
            trust_marks,
            signer,
        }
    }

    /// Answers a Trust Mark Status request, see the table on [`TrustMarkStatusEndpoint`].
    ///
    /// A `server_error` response does not say why. Call [`try_handle`](Self::try_handle) to
    /// learn it.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.4.2 Trust Mark Status Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4.2>)
    pub async fn handle(&self, request: &EndpointRequest) -> EndpointResponse {
        self.try_handle(request).await.unwrap_or_else(|_| {
            ErrorResponse::new(ErrorCode::ServerError, "the Trust Mark status could not be reported")
                .to_endpoint_response()
        })
    }

    /// Like [`handle`](Self::handle), but returns why the status could not be reported instead of
    /// the `server_error` response. Errors in the request are still answered with their error
    /// response.
    ///
    /// # Errors
    ///
    /// [`FederationError::Store`] when the store fails, [`FederationError::Configuration`] when it
    /// returns a Trust Mark other than the one asked for, and the errors of
    /// [`TrustMarkStatusResponse::sign`].
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.4.2 Trust Mark Status Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4.2>)
    pub async fn try_handle(&self, request: &EndpointRequest) -> FederationResult<EndpointResponse> {
        if request.method() != HttpMethod::Post {
            return Ok(invalid_request("a Trust Mark Status request is a POST"));
        }
        let jwt = match request.parameter("trust_mark") {
            Ok(Some(jwt)) => jwt,
            Ok(None) => return Ok(invalid_request("the trust_mark parameter is required")),
            Err(error) => return Ok(error.to_endpoint_response()),
        };

        let Ok(claims) = trust_mark_claims(jwt) else {
            return Ok(invalid_request("the trust_mark parameter is not a Trust Mark JWT"));
        };

        let now = Utc::now().timestamp();
        let status = match self.trust_marks.trust_mark(jwt).await? {
            Some(issued) if issued.jwt != jwt => {
                return Err(FederationError::Configuration(
                    "the Trust Mark store returned another Trust Mark than the one asked for".to_string(),
                ))
            }
            Some(issued) => issued.status_at(now),
            None => {
                let issued_to_subject = claims.iss == self.issuer
                    && self
                        .trust_marks
                        .trust_marks(Some(&claims.trust_mark_type), Some(&claims.sub))
                        .await?
                        .iter()
                        .any(|issued| issued.claims.sub == claims.sub);
                if !issued_to_subject {
                    return Ok(ErrorResponse::new(
                        ErrorCode::NotFound,
                        format!("{} did not issue this Trust Mark", self.issuer),
                    )
                    .to_endpoint_response());
                }
                TrustMarkStatus::Invalid
            }
        };

        let response = TrustMarkStatusResponse::new(self.issuer.clone(), now, jwt, status)
            .sign(self.signer.as_ref())
            .await?;
        Ok(EndpointResponse::new(
            200,
            TRUST_MARK_STATUS_RESPONSE_CONTENT_TYPE,
            response,
        ))
    }
}

fn invalid_request(description: &str) -> EndpointResponse {
    ErrorResponse::new(ErrorCode::InvalidRequest, description).to_endpoint_response()
}

/// Shows the issuer and the signer's `kid`.
impl fmt::Debug for TrustMarkStatusEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustMarkStatusEndpoint")
            .field("issuer", &self.issuer)
            .field("kid", &self.signer.kid())
            .finish_non_exhaustive()
    }
}
