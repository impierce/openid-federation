//! The subordinate listing endpoint: a Trust Anchor or Intermediate Entity lists the Entity
//! Identifiers of its Immediate Subordinates there (OpenID Federation 1.0, Section 8.2).

use super::{EndpointRequest, EndpointResponse, ErrorCode, ErrorResponse, JSON_CONTENT_TYPE};
use crate::{EntityType, FederationResult, Subordinate, SubordinateStore};
use std::fmt;
use std::sync::Arc;

/// Lists the Immediate Subordinates in a [`SubordinateStore`], filtered by the request.
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
/// | `trust_marked=true`, `trust_mark_type`     | `400 unsupported_parameter`                              |
/// | `trust_marked=false`                       | no filter                                                |
/// | `intermediate` or `trust_marked` repeated, or neither `true` nor `false` | `400 invalid_request` |
/// | the store fails                            | `500 server_error`                                       |
///
/// The filters combine: a subordinate is listed when it passes every one. The response is a JSON
/// array of Entity Identifiers, spelled as the subordinates publish them and sorted, so that the
/// same store gives the same response.
///
/// The Trust Mark filters need to know which Trust Marks the responder issued, which no store of
/// this crate records yet, so the endpoint answers them as the specification requires of a
/// responder that does not support them.
///
/// Reference: OpenID Federation 1.0 - Section 8.2 Subordinate Listing
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
pub struct ListEndpoint {
    subordinates: Arc<dyn SubordinateStore>,
}

impl ListEndpoint {
    /// An endpoint that lists the subordinates in `subordinates`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2 Subordinate Listing
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
    pub fn new(subordinates: Arc<dyn SubordinateStore>) -> Self {
        Self { subordinates }
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
    /// [`FederationError::Store`](crate::FederationError::Store) when the store fails.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2.2 Subordinate Listing Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2.2>)
    pub async fn try_handle(&self, request: &EndpointRequest) -> FederationResult<EndpointResponse> {
        let filter = match Filter::from_request(request) {
            Ok(filter) => filter,
            Err(error) => return Ok(error.to_endpoint_response()),
        };

        let mut entity_ids: Vec<String> = self
            .subordinates
            .subordinates()
            .await?
            .iter()
            .filter(|subordinate| filter.admits(subordinate))
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
}

impl Filter {
    fn from_request(request: &EndpointRequest) -> Result<Self, ErrorResponse> {
        if boolean(request, "trust_marked")? {
            return Err(unsupported("trust_marked"));
        }
        if request.parameter("trust_mark_type")?.is_some() {
            return Err(unsupported("trust_mark_type"));
        }
        let intermediate = boolean(request, "intermediate")?;
        let entity_types = request
            .parameters()
            .iter()
            .filter(|(name, _)| name == "entity_type")
            .map(|(_, value)| entity_type(value))
            .collect();
        Ok(Self {
            entity_types,
            intermediate,
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
