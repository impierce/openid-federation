//! The Trust Marked Entities Listing endpoint: a Trust Mark Issuer lists there the entities that
//! hold a valid Trust Mark of a type it issued (OpenID Federation 1.0, Section 8.5).

use super::{
    entity_id_parameter, required_parameter, EndpointRequest, EndpointResponse, ErrorCode, ErrorResponse,
    JSON_CONTENT_TYPE,
};
use crate::{EntityId, FederationResult, TrustMarkStatus, TrustMarkStore};
use chrono::Utc;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

/// Lists the entities that hold an active Trust Mark of a type in a [`TrustMarkStore`].
///
/// A request is a `GET` with the parameters in the query, or a `POST` with them in the body when
/// client authentication is used (Section 8.5.1). Authenticating the client is the application's
/// concern, as for [`TrustMarkStatusEndpoint`](crate::TrustMarkStatusEndpoint). Unknown
/// parameters are ignored (Section 8).
///
/// | Request                                                  | Response                                                         |
/// | -------------------------------------------------------- | ---------------------------------------------------------------- |
/// | `trust_mark_type`                                        | `200`, `application/json`, every subject with an active Trust Mark of that type |
/// | `trust_mark_type` and `sub`                              | the same, holding only `sub`, or empty                           |
/// | `trust_mark_type` missing or repeated; `sub` repeated or not an Entity Identifier | `400 invalid_request`                   |
/// | the store fails                                          | `500 server_error`                                               |
///
/// A Trust Mark is active, "issued and still valid" in the words of Section 8.5, while it is
/// neither revoked nor expired, see [`IssuedTrustMark::status_at`](crate::IssuedTrustMark::status_at).
/// A type the issuer never issued lists no entity. The response is a JSON array of Entity
/// Identifiers, each once, spelled as its Trust Mark's `sub` spells it, and sorted, so that the
/// same store gives the same response. The records the store returns are checked against the
/// request, so a store that answers too broadly does not list entities of another type.
///
/// Reference: OpenID Federation 1.0 - Section 8.5 Trust Marked Entities Listing
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.5>)
pub struct TrustMarkedEntitiesEndpoint {
    trust_marks: Arc<dyn TrustMarkStore>,
}

impl TrustMarkedEntitiesEndpoint {
    /// An endpoint that lists the subjects of the Trust Marks in `trust_marks`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.5 Trust Marked Entities Listing
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.5>)
    pub fn new(trust_marks: Arc<dyn TrustMarkStore>) -> Self {
        Self { trust_marks }
    }

    /// Answers a Trust Marked Entities Listing request, see the table on
    /// [`TrustMarkedEntitiesEndpoint`].
    ///
    /// A `server_error` response does not say why. Call [`try_handle`](Self::try_handle) to
    /// learn it.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.5.2 Trust Marked Entities Listing Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.5.2>)
    pub async fn handle(&self, request: &EndpointRequest) -> EndpointResponse {
        self.try_handle(request).await.unwrap_or_else(|_| {
            ErrorResponse::new(ErrorCode::ServerError, "the Trust Marked Entities could not be listed")
                .to_endpoint_response()
        })
    }

    /// Like [`handle`](Self::handle), but returns why the entities could not be listed instead
    /// of the `server_error` response. Errors in the request are still answered with their error
    /// response.
    ///
    /// # Errors
    ///
    /// [`FederationError::Store`](crate::FederationError::Store) when the store fails.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.5.2 Trust Marked Entities Listing Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.5.2>)
    pub async fn try_handle(&self, request: &EndpointRequest) -> FederationResult<EndpointResponse> {
        let (trust_mark_type, sub) = match (
            required_parameter(request, "trust_mark_type"),
            entity_id_parameter(request, "sub"),
        ) {
            (Ok(trust_mark_type), Ok(sub)) => (trust_mark_type, sub),
            (Err(error), _) | (_, Err(error)) => return Ok(error.to_endpoint_response()),
        };

        let now = Utc::now().timestamp();
        let issued = self
            .trust_marks
            .trust_marks(Some(trust_mark_type), sub.as_ref())
            .await?;
        let mut subjects: Vec<&EntityId> = issued
            .iter()
            .filter(|issued| {
                issued.claims.trust_mark_type == trust_mark_type
                    && sub.as_ref().is_none_or(|sub| issued.claims.sub == *sub)
                    && issued.status_at(now) == TrustMarkStatus::Active
            })
            .map(|issued| &issued.claims.sub)
            .collect();
        subjects.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        // Two spellings of one entity, such as with and without a trailing slash, list it once.
        let mut seen = HashSet::new();
        subjects.retain(|subject| seen.insert(*subject));

        let body = serde_json::to_string(&subjects)?;
        Ok(EndpointResponse::new(200, JSON_CONTENT_TYPE, body))
    }
}

impl fmt::Debug for TrustMarkedEntitiesEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustMarkedEntitiesEndpoint").finish_non_exhaustive()
    }
}
