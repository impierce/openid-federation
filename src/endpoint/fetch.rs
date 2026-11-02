//! The fetch endpoint: an entity with Subordinates publishes Subordinate Statements about its
//! Immediate Subordinates there (OpenID Federation 1.0, Section 8.1).

use super::{EndpointRequest, EndpointResponse, ErrorCode, ErrorResponse, ENTITY_STATEMENT_CONTENT_TYPE};
use crate::{EntityId, FederationError, FederationResult, Signer, SubordinateStore, UrlValidator};
use chrono::Duration;
use std::fmt;
use std::sync::Arc;
use url::Url;

/// Serves Subordinate Statements about the Immediate Subordinates in a [`SubordinateStore`],
/// issued by a Trust Anchor or Intermediate Entity and signed with its key.
///
/// A request is a `GET` with the `sub` parameter, or a `POST` with it in the body when client
/// authentication is used (Section 8.1.1). Authenticating the client is the application's
/// concern: it checks the request before calling the handler, which reads `sub` from either
/// method and ignores every other parameter, such as `client_assertion` (Section 8).
///
/// Each statement is built from what the Superior registered with
/// [`Subordinate::subordinate_statement`](crate::Subordinate::subordinate_statement), carries
/// the fetch endpoint as `source_endpoint`, and is valid for the configured lifetime, 24 hours by
/// default, from the moment it is signed.
///
/// | Request                                     | Response                                                    |
/// | ------------------------------------------- | ----------------------------------------------------------- |
/// | `sub` names a registered subordinate        | `200`, [`ENTITY_STATEMENT_CONTENT_TYPE`], the statement     |
/// | `sub` is missing, repeated or not an `https` URL without a fragment | `400 invalid_request`                                       |
/// | `sub` is the issuer's own Entity Identifier | `400 invalid_request`                                       |
/// | `sub` names no registered subordinate       | `404 not_found`                                             |
/// | the store or the signer fails               | `500 server_error`                                          |
///
/// `sub` is compared as a URL, so `https://op.example.org` and `https://op.example.org/` fetch
/// the same statement (ADR 0004).
///
/// # Privacy
///
/// Every request tells the issuer which entity someone is evaluating, and from which network
/// address. When the endpoint is public and needs no client authentication, a request does not
/// prove any interaction between entities, but the issuer could still use the requests to track
/// who evaluates whom. Section 19.3 suggests static and short-lived Trust Chains where
/// appropriate, which reduce the need to fetch Subordinate Statements in real time.
///
/// Wiring the handler into an `axum` router (the crate depends on no web framework, ADR 0005):
///
/// ```rust,ignore
/// use axum::{extract::{RawQuery, State}, http::{header, StatusCode}, response::IntoResponse, routing::get, Router};
/// use openid_federation::{EndpointRequest, EndpointResponse, FetchEndpoint};
/// use std::sync::Arc;
///
/// fn into_axum(response: EndpointResponse) -> impl IntoResponse {
///     (
///         StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
///         [(header::CONTENT_TYPE, response.content_type)],
///         response.body,
///     )
/// }
///
/// async fn fetch(State(endpoint): State<Arc<FetchEndpoint>>, RawQuery(query): RawQuery) -> impl IntoResponse {
///     into_axum(endpoint.handle(&EndpointRequest::get(query.as_deref().unwrap_or_default())).await)
/// }
///
/// let endpoint = Arc::new(FetchEndpoint::new(issuer, fetch_endpoint_url, subordinates, signer));
/// let app = Router::new().route("/fetch", get(fetch)).with_state(endpoint);
/// ```
///
/// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1>) and Section 19.3 Fetch
/// Endpoint Privacy Considerations
/// (<https://openid.net/specs/openid-federation-1_0.html#section-19.3>)
pub struct FetchEndpoint {
    issuer: EntityId,
    endpoint: Url,
    subordinates: Arc<dyn SubordinateStore>,
    signer: Arc<dyn Signer>,
    lifetime: Duration,
}

impl FetchEndpoint {
    /// An endpoint at `endpoint`, the `federation_fetch_endpoint` that `issuer` publishes, serving
    /// statements about the subordinates in `subordinates`, signed with `signer`, one of the
    /// issuer's keys.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1>)
    pub fn new(
        issuer: EntityId,
        endpoint: Url,
        subordinates: Arc<dyn SubordinateStore>,
        signer: Arc<dyn Signer>,
    ) -> Self {
        Self {
            issuer,
            endpoint,
            subordinates,
            signer,
            lifetime: Duration::hours(24),
        }
    }

    /// Issue each Subordinate Statement for `lifetime`, from `iat` to `exp`. It must be at least
    /// one second, since both are whole seconds.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.1
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>)
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Answers a fetch request, see the table on [`FetchEndpoint`].
    ///
    /// A `server_error` response does not say why, since the cause, such as an unreachable
    /// database or HSM, is the deployment's business. Call [`try_handle`](Self::try_handle) to
    /// learn it.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1.2 Fetch Subordinate Statement Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1.2>)
    pub async fn handle(&self, request: &EndpointRequest) -> EndpointResponse {
        self.try_handle(request).await.unwrap_or_else(|_| {
            ErrorResponse::new(ErrorCode::ServerError, "the Subordinate Statement could not be issued")
                .to_endpoint_response()
        })
    }

    /// Like [`handle`](Self::handle), but returns why the statement could not be issued instead
    /// of the `server_error` response. Errors in the request are still answered with their error
    /// response.
    ///
    /// # Errors
    ///
    /// [`FederationError::Store`] when the store fails, [`FederationError::Configuration`] when it
    /// returns a subordinate other than the one asked for, and the errors of
    /// [`SubordinateStatementBuilder::build`](crate::SubordinateStatementBuilder::build) and
    /// [`SubordinateStatement::sign`](crate::SubordinateStatement::sign).
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1.2 Fetch Subordinate Statement Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1.2>)
    pub async fn try_handle(&self, request: &EndpointRequest) -> FederationResult<EndpointResponse> {
        let sub = match request.parameter("sub") {
            Ok(Some(sub)) => sub,
            Ok(None) => return Ok(invalid_request("the sub parameter is required")),
            Err(error) => return Ok(error.to_endpoint_response()),
        };
        // An Entity Identifier is an `https` URL with a host and no fragment (Section 1.2), so
        // anything else cannot name a subordinate and is a malformed request, not an unknown one.
        let Some(sub) = EntityId::parse(sub)
            .ok()
            .filter(|sub| UrlValidator::validate_entity_id(sub.as_url()).is_ok())
        else {
            return Ok(invalid_request("the sub parameter is not an Entity Identifier"));
        };
        if sub == self.issuer {
            return Ok(invalid_request(
                "the sub parameter is the issuer's own Entity Identifier",
            ));
        }

        let Some(subordinate) = self.subordinates.subordinate(&sub).await? else {
            return Ok(ErrorResponse::new(
                ErrorCode::NotFound,
                format!("{sub} is not an Immediate Subordinate of {}", self.issuer),
            )
            .to_endpoint_response());
        };
        if subordinate.entity_id != sub {
            return Err(FederationError::Configuration(format!(
                "the subordinate store returned {} when asked for {sub}",
                subordinate.entity_id
            )));
        }

        let statement = subordinate
            .subordinate_statement(self.issuer.clone())
            .lifetime(self.lifetime)
            .source_endpoint(self.endpoint.clone())
            .build()?;
        let jwt = statement.sign(self.signer.as_ref()).await?;
        Ok(EndpointResponse::new(200, ENTITY_STATEMENT_CONTENT_TYPE, jwt))
    }
}

fn invalid_request(description: &str) -> EndpointResponse {
    ErrorResponse::new(ErrorCode::InvalidRequest, description).to_endpoint_response()
}

/// Shows the issuer, the endpoint, the signer's `kid` and the lifetime.
impl fmt::Debug for FetchEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchEndpoint")
            .field("issuer", &self.issuer)
            .field("endpoint", &self.endpoint.as_str())
            .field("kid", &self.signer.kid())
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}
