//! The Entity Configuration endpoint: an entity publishes its signed Entity Configuration at
//! `<Entity Identifier>/.well-known/openid-federation` (OpenID Federation 1.0, Section 9).

use super::{EndpointResponse, ErrorCode, ErrorResponse, ENTITY_STATEMENT_CONTENT_TYPE};
use crate::{EntityConfiguration, FederationError, FederationResult, Signer};
use chrono::{Duration, Utc};
use std::fmt;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Serves an entity's Entity Configuration, signed with one of the entity's own keys.
///
/// The handler signs the configuration when it has none cached, or when the cached one is
/// within the refresh margin of its `exp`, so it never serves an expired configuration. Each
/// signing stamps `iat` with the current time and `exp` with `iat` plus the lifetime; the `iat`
/// and `exp` of the configuration passed to [`EntityConfigurationEndpoint::new`] are not used.
/// Requests that arrive while a configuration is being signed wait for it, so a burst of
/// requests signs once.
///
/// The defaults are a lifetime of 24 hours and a refresh margin of 1 hour.
///
/// Wiring the handler into an `axum` router (the crate depends on no web framework, ADR 0005):
///
/// ```rust,ignore
/// use axum::{extract::State, http::{header, StatusCode}, response::IntoResponse, routing::get, Router};
/// use openid_federation::{EndpointResponse, EntityConfigurationEndpoint};
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
/// async fn entity_configuration(State(endpoint): State<Arc<EntityConfigurationEndpoint>>) -> impl IntoResponse {
///     into_axum(endpoint.handle().await)
/// }
///
/// let endpoint = Arc::new(EntityConfigurationEndpoint::new(configuration, signer));
/// let app = Router::new()
///     .route(&endpoint.path(), get(entity_configuration))
///     .with_state(endpoint);
/// ```
///
/// Reference: OpenID Federation 1.0 - Section 9 Obtaining Federation Entity Configuration
/// Information (<https://openid.net/specs/openid-federation-1_0.html#section-9>)
pub struct EntityConfigurationEndpoint {
    configuration: EntityConfiguration,
    signer: Arc<dyn Signer>,
    lifetime: Duration,
    refresh_margin: Duration,
    cached: Mutex<Option<SignedConfiguration>>,
}

/// A signed Entity Configuration and its `exp`.
struct SignedConfiguration {
    jwt: String,
    exp: i64,
}

impl EntityConfigurationEndpoint {
    /// An endpoint that serves `configuration`, signed with `signer`, whose `kid` must name a key
    /// in the configuration's own `jwks`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 9 Obtaining Federation Entity Configuration
    /// Information (<https://openid.net/specs/openid-federation-1_0.html#section-9>)
    pub fn new(configuration: EntityConfiguration, signer: Arc<dyn Signer>) -> Self {
        Self {
            configuration,
            signer,
            lifetime: Duration::hours(24),
            refresh_margin: Duration::hours(1),
            cached: Mutex::new(None),
        }
    }

    /// Sign each Entity Configuration for `lifetime`, from `iat` to `exp`. It must be at least one
    /// second, since both are whole seconds.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.1 Claims that MUST or MAY Appear in both
    /// Entity Configurations and Subordinate Statements
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>)
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Sign a fresh Entity Configuration once the cached one expires within `refresh_margin`. It
    /// must not be negative; a margin of at least the lifetime signs one for every request.
    ///
    /// Reference: OpenID Federation 1.0 - Section 9 Obtaining Federation Entity Configuration
    /// Information (<https://openid.net/specs/openid-federation-1_0.html#section-9>)
    pub fn with_refresh_margin(mut self, refresh_margin: Duration) -> Self {
        self.refresh_margin = refresh_margin;
        self
    }

    /// The path to mount the handler on: the path of the entity's
    /// [`entity_configuration_url`](crate::EntityId::entity_configuration_url), such as
    /// `/federation/.well-known/openid-federation` for `https://example.org/federation/`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 9 Obtaining Federation Entity Configuration
    /// Information (<https://openid.net/specs/openid-federation-1_0.html#section-9>)
    pub fn path(&self) -> String {
        self.configuration
            .claims
            .sub
            .entity_configuration_url()
            .path()
            .to_string()
    }

    /// Answers a `GET` request for the Entity Configuration: `200` with
    /// [`ENTITY_STATEMENT_CONTENT_TYPE`] and the signed configuration, or `500` with the
    /// `server_error` error response when it cannot be signed.
    ///
    /// The error response does not say why, since the cause, such as an unreachable HSM, is the
    /// deployment's business. Call [`try_handle`](Self::try_handle) to learn it.
    ///
    /// Reference: OpenID Federation 1.0 - Section 9.2 Federation Entity Configuration Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-9.2>)
    pub async fn handle(&self) -> EndpointResponse {
        self.try_handle().await.unwrap_or_else(|_| {
            ErrorResponse::new(ErrorCode::ServerError, "the Entity Configuration could not be signed")
                .to_endpoint_response()
        })
    }

    /// Like [`handle`](Self::handle), but returns why the Entity Configuration could not be
    /// signed instead of the `server_error` response.
    ///
    /// # Errors
    ///
    /// [`FederationError::Configuration`] for a lifetime under one second or a negative
    /// refresh margin, and the errors of [`EntityConfiguration::sign`].
    ///
    /// Reference: OpenID Federation 1.0 - Section 9.2 Federation Entity Configuration Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-9.2>)
    pub async fn try_handle(&self) -> FederationResult<EndpointResponse> {
        let jwt = self.signed_configuration().await?;
        Ok(EndpointResponse::new(200, ENTITY_STATEMENT_CONTENT_TYPE, jwt))
    }

    /// The cached Entity Configuration, or a freshly signed one when the cached one expires
    /// within the refresh margin.
    async fn signed_configuration(&self) -> FederationResult<String> {
        if self.lifetime.num_seconds() <= 0 {
            return Err(FederationError::Configuration(format!(
                "the Entity Configuration lifetime must be at least one second, but it is {}",
                self.lifetime
            )));
        }
        if self.refresh_margin < Duration::zero() {
            return Err(FederationError::Configuration(format!(
                "the Entity Configuration refresh margin must not be negative, but it is {}",
                self.refresh_margin
            )));
        }

        let mut cached = self.cached.lock().await;
        let now = Utc::now().timestamp();
        if let Some(signed) = cached.as_ref() {
            if now + self.refresh_margin.num_seconds() < signed.exp {
                return Ok(signed.jwt.clone());
            }
        }

        let mut configuration = self.configuration.clone();
        configuration.claims.iat = now;
        configuration.claims.exp = now + self.lifetime.num_seconds();
        let jwt = configuration.sign(self.signer.as_ref()).await?;
        *cached = Some(SignedConfiguration {
            jwt: jwt.clone(),
            exp: configuration.claims.exp,
        });
        Ok(jwt)
    }
}

/// Shows the Entity Identifier, the signer's `kid`, the lifetime and the refresh margin.
impl fmt::Debug for EntityConfigurationEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntityConfigurationEndpoint")
            .field("entity_id", &self.configuration.claims.sub)
            .field("kid", &self.signer.kid())
            .field("lifetime", &self.lifetime)
            .field("refresh_margin", &self.refresh_margin)
            .finish_non_exhaustive()
    }
}
