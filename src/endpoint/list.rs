//! The subordinate listing endpoint: a Trust Anchor or Intermediate Entity lists the Entity
//! Identifiers of its Immediate Subordinates there (OpenID Federation 1.0, Section 8.2).

use super::{EndpointRequest, EndpointResponse, ErrorCode, ErrorResponse, JSON_CONTENT_TYPE};
use crate::{EntityId, EntityType, FederationResult, Subordinate, SubordinateStore, TrustMarkStatus, TrustMarkStore};
use chrono::Utc;
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::sync::Arc;

/// Lists the Immediate Subordinates in a [`SubordinateStore`], filtered by the request, and by the
/// Trust Marks in a [`TrustMarkStore`] when it has one, see
/// [`with_trust_marks`](Self::with_trust_marks).
///
/// A request is a `GET` with the filters in the query, or a `POST` with them in the body when
/// client authentication is used (Section 8.2.1). Authenticating the client is the application's
/// concern, as for [`FetchEndpoint`](crate::FetchEndpoint). Unknown parameters are ignored
/// (Section 8).
///
/// | Request                                    | Response                                                 |
/// | ------------------------------------------ | -------------------------------------------------------- |
/// | no filter                                  | `200`, `application/json`, every subordinate             |
/// | `entity_type`, repeatable                  | only subordinates with every given Entity Type           |
/// | `intermediate=true`                        | only Intermediate Entities                               |
/// | `intermediate=false`                       | no filter, since the parameter only filters when `true`  |
/// | `trust_marked=true`                        | only subordinates holding an active Trust Mark of any type |
/// | `trust_mark_type`                          | only subordinates holding an active Trust Mark of that type |
/// | `trust_marked=true` or `trust_mark_type` without a [`TrustMarkStore`] | `400 unsupported_parameter`   |
/// | `trust_marked=false`                       | no filter                                                |
/// | `intermediate` or `trust_marked` repeated, or neither `true` nor `false`; `trust_mark_type` repeated | `400 invalid_request` |
/// | a store fails                              | `500 server_error`                                       |
///
/// The filters combine: a subordinate is listed when it passes every one. The response is a JSON
/// array of Entity Identifiers, spelled as the subordinates publish them and sorted, so that the
/// same store gives the same response.
///
/// The Trust Mark filters read the Trust Marks the responder issued, from the store it records
/// them in as a Trust Mark Issuer. A Trust Mark is active, "issued and still valid" in the words
/// of Section 8.2.1, while it is neither revoked nor expired and its `iat` is not in the future,
/// see [`IssuedTrustMark::status_at`](crate::IssuedTrustMark::status_at), and it marks the
/// subordinate its `sub` names. A type the responder never issued keeps no subordinate. Without
/// a Trust Mark store, the endpoint answers the filters as the specification requires of a
/// responder that does not support them.
///
/// Reference: OpenID Federation 1.0 - Section 8.2 Subordinate Listing
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
pub struct ListEndpoint {
    subordinates: Arc<dyn SubordinateStore>,
    trust_marks: Option<Arc<dyn TrustMarkStore>>,
}

impl ListEndpoint {
    /// An endpoint that lists the subordinates in `subordinates`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2 Subordinate Listing
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
    pub fn new(subordinates: Arc<dyn SubordinateStore>) -> Self {
        Self {
            subordinates,
            trust_marks: None,
        }
    }

    /// Supports the `trust_marked` and `trust_mark_type` filters with the Trust Marks the
    /// responder issued, which it records in `trust_marks`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2.1 Subordinate Listing Request
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2.1>)
    #[must_use]
    pub fn with_trust_marks(mut self, trust_marks: Arc<dyn TrustMarkStore>) -> Self {
        self.trust_marks = Some(trust_marks);
        self
    }

    /// Answers a listing request, see the table on [`ListEndpoint`].
    ///
    /// A `server_error` response does not say why, since the cause, such as an unreachable
    /// database, is the deployment's business. Call [`try_handle`](Self::try_handle) to learn it.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2.2 Subordinate Listing Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2.2>)
    pub async fn handle(&self, request: &EndpointRequest) -> EndpointResponse {
        self.try_handle(request).await.unwrap_or_else(|_| {
            ErrorResponse::new(ErrorCode::ServerError, "the Immediate Subordinates could not be listed")
                .to_endpoint_response()
        })
    }

    /// Like [`handle`](Self::handle), but returns why the subordinates could not be listed instead
    /// of the `server_error` response. Errors in the request are still answered with their error
    /// response.
    ///
    /// # Errors
    ///
    /// [`FederationError::Store`](crate::FederationError::Store) when a store fails.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2.2 Subordinate Listing Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2.2>)
    pub async fn try_handle(&self, request: &EndpointRequest) -> FederationResult<EndpointResponse> {
        let filter = match Filter::from_request(request, self.trust_marks.is_some()) {
            Ok(filter) => filter,
            Err(error) => return Ok(error.to_endpoint_response()),
        };
        let trust_marked = match &self.trust_marks {
            Some(store) if filter.trust_marked => {
                Some(trust_marked(store.as_ref(), filter.trust_mark_type.as_deref()).await?)
            }
            _ => None,
        };

        let mut entity_ids: Vec<String> = self
            .subordinates
            .subordinates()
            .await?
            .iter()
            .filter(|subordinate| {
                filter.admits(subordinate)
                    && trust_marked
                        .as_ref()
                        .is_none_or(|trust_marked| trust_marked.contains(&subordinate.entity_id))
            })
            .map(|subordinate| subordinate.entity_id.to_string())
            .collect();
        entity_ids.sort();

        let body = serde_json::to_string(&entity_ids)?;
        Ok(EndpointResponse::new(200, JSON_CONTENT_TYPE, body))
    }
}

/// The filters of a listing request (Section 8.2.1).
struct Filter {
    entity_types: Vec<EntityType>,
    intermediate: bool,
    /// Only subordinates holding an active Trust Mark, of `trust_mark_type` when it is given.
    trust_marked: bool,
    trust_mark_type: Option<String>,
}

impl Filter {
    fn from_request(request: &EndpointRequest, supports_trust_marks: bool) -> Result<Self, ErrorResponse> {
        let trust_marked = boolean(request, "trust_marked")?;
        let trust_mark_type = request.parameter("trust_mark_type")?;
        if !supports_trust_marks {
            if trust_marked {
                return Err(unsupported("trust_marked"));
            }
            if trust_mark_type.is_some() {
                return Err(unsupported("trust_mark_type"));
            }
        }
        let intermediate = boolean(request, "intermediate")?;
        // A repeated value filters the same as one; each is parsed and compared once.
        let entity_types = request
            .parameters()
            .iter()
            .filter(|(name, _)| name == "entity_type")
            .map(|(_, value)| value.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(entity_type)
            .collect();
        Ok(Self {
            entity_types,
            intermediate,
            // A type keeps only subordinates with an active Trust Mark, so it implies `trust_marked`.
            trust_marked: trust_marked || trust_mark_type.is_some(),
            trust_mark_type: trust_mark_type.map(str::to_string),
        })
    }

    fn admits(&self, subordinate: &Subordinate) -> bool {
        (!self.intermediate || subordinate.intermediate)
            && self
                .entity_types
                .iter()
                .all(|entity_type| subordinate.entity_types.contains(entity_type))
    }
}

/// The subjects of the active Trust Marks in `store`, of `trust_mark_type` when it is given.
async fn trust_marked(
    store: &dyn TrustMarkStore,
    trust_mark_type: Option<&str>,
) -> FederationResult<HashSet<EntityId>> {
    let now = Utc::now().timestamp();
    Ok(store
        .trust_marks(trust_mark_type, None)
        .await?
        .into_iter()
        // The records are checked against the query, so a store that answers too broadly does not
        // widen the filter.
        .filter(|issued| {
            trust_mark_type.is_none_or(|trust_mark_type| issued.claims.trust_mark_type == trust_mark_type)
                && issued.status_at(now) == TrustMarkStatus::Active
        })
        .map(|issued| issued.claims.sub)
        .collect())
}

/// The Boolean parameter `name`: `false` when absent.
fn boolean(request: &EndpointRequest, name: &str) -> Result<bool, ErrorResponse> {
    match request.parameter(name)? {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ErrorResponse::new(
            ErrorCode::InvalidRequest,
            format!("the {name} parameter must be true or false"),
        )),
    }
}

/// The Entity Type Identifier `value`, as a subordinate record holds it.
fn entity_type(value: &str) -> EntityType {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .unwrap_or_else(|_| EntityType::Other(value.to_string()))
}

fn unsupported(name: &str) -> ErrorResponse {
    ErrorResponse::new(
        ErrorCode::UnsupportedParameter,
        format!("the {name} filter is not supported"),
    )
}

impl fmt::Debug for ListEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListEndpoint").finish_non_exhaustive()
    }
}
