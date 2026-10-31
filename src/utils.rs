//! Utility functions for OpenID Federation operations.

use crate::{
    EndpointError, EntityConfiguration, EntityId, ErrorResponse, FederationError, FederationResult,
    SubordinateStatement, TrustChain,
};
use chrono::{Duration, Utc};
use reqwest::Client;
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use url::Url;

use async_trait::async_trait;

/// Trait for HTTP clients used in federation operations.
///
/// This trait abstracts the HTTP layer to allow consumers to provide their own
/// HTTP client implementation (e.g., alternative HTTP libraries, mock clients for testing).
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Send a `GET` request to `url` and return the response, whatever its status.
    ///
    /// Return an error only when no response arrived (a network failure, for example).
    /// [`FederationClient`] turns a status other than 2xx into [`FederationError::Endpoint`],
    /// reading the error response of OpenID Federation 1.0,
    /// [Section 8.9](https://openid.net/specs/openid-federation-1_0.html#section-8.9), from the
    /// body.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8 Federation Endpoints
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8>)
    async fn get(&self, url: Url) -> FederationResult<HttpResponse>;
}

/// A response as an [`HttpClient`] received it.
///
/// Reference: OpenID Federation 1.0 - Section 8 Federation Endpoints
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8>)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The value of the `Content-Type` header, if the response had one.
    pub content_type: Option<String>,
    /// The response body.
    pub body: String,
}

impl HttpResponse {
    /// A response with the given status, content type and body.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8 Federation Endpoints
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8>)
    pub fn new(status: u16, content_type: Option<String>, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
        }
    }

    /// Whether the status is 2xx.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8 Federation Endpoints
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8>)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body of a 2xx response, or [`FederationError::Endpoint`] for any other status, with
    /// the error response the body carries if it is one (Section 8.9).
    ///
    /// The error response is read from the body whatever the content type, since Section 8.9
    /// only says the content type SHOULD be `application/json`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.9 Error Responses
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.9>)
    pub fn into_success_body(self, url: Url) -> FederationResult<String> {
        if self.is_success() {
            return Ok(self.body);
        }
        Err(EndpointError {
            url,
            status: self.status,
            response: serde_json::from_str::<ErrorResponse>(&self.body).ok(),
        }
        .into())
    }
}

/// Default HTTP client implementation using `reqwest`.
///
/// The body of a response with a status other than 2xx is read up to 64 KiB; a longer body, or
/// one that cannot be read, is returned empty, so [`FederationClient`] still reports the status.
pub struct ReqwestHttpClient {
    client: Client,
}

impl ReqwestHttpClient {
    /// Create a new `ReqwestHttpClient` with the default `reqwest::Client`.
    pub fn new() -> Self {
        Self { client: Client::new() }
    }

    /// Create a `ReqwestHttpClient` with a custom `reqwest::Client`.
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// The most bytes [`ReqwestHttpClient`] reads from the body of a response with a status other
/// than 2xx. An error response (Section 8.9) is a short JSON object; a longer body is discarded.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Reads the body of a response with a status other than 2xx, at most [`MAX_ERROR_BODY_BYTES`].
/// A longer body, or one that fails to read (a truncated body, for example), yields an empty
/// body, so the caller still reports the status. A truncated prefix is never returned, since it
/// could still parse as an error response.
async fn read_error_body(response: &mut reqwest::Response) -> String {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_ERROR_BODY_BYTES => body.extend_from_slice(&chunk),
            Ok(Some(_)) | Err(_) => return String::new(),
            Ok(None) => return String::from_utf8_lossy(&body).into_owned(),
        }
    }
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn get(&self, url: Url) -> FederationResult<HttpResponse> {
        let mut response = self.client.get(url).send().await?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = if (200..300).contains(&status) {
            response.text().await?
        } else {
            read_error_body(&mut response).await
        };
        Ok(HttpResponse::new(status, content_type, body))
    }
}

/// Result of best-effort trust chain discovery, see
/// [`FederationClient::discover_all_trust_chains_with_failures`].
#[derive(Debug, Default)]
pub struct TrustChainDiscovery {
    /// Every authenticated trust chain that was found.
    pub chains: Vec<TrustChain>,
    /// Every branch that was skipped because it could not be resolved or authenticated.
    pub failures: Vec<TrustChainDiscoveryFailure>,
}

/// A branch skipped during best-effort trust chain discovery.
#[derive(Debug)]
pub struct TrustChainDiscoveryFailure {
    /// The entity that was being resolved when the branch failed: a superior whose configuration
    /// or subordinate statement could not be resolved, or the trust anchor of a chain that failed
    /// validation.
    pub entity_id: EntityId,
    /// Why the branch was skipped.
    pub error: FederationError,
}

/// HTTP client for federation operations.
///
/// This client can be instantiated with any implementation of [`HttpClient`],
/// allowing for flexibility in HTTP layer implementation (e.g., testing with mocks,
/// using alternative HTTP libraries).
#[derive(Clone)]
pub struct FederationClient {
    http_client: Arc<dyn HttpClient>,
}

impl FederationClient {
    /// Create a new federation client with the default `reqwest`-backed HTTP client.
    pub fn new() -> Self {
        Self {
            http_client: Arc::new(ReqwestHttpClient::new()),
        }
    }

    /// Create a federation client with a custom HTTP client implementation.
    pub fn with_http_client<C: HttpClient + 'static>(client: C) -> Self {
        Self {
            http_client: Arc::new(client),
        }
    }

    /// Create a federation client with a boxed HTTP client.
    ///
    /// This is useful when you have a trait object or need to store multiple client types.
    pub fn with_boxed_http_client(client: Arc<dyn HttpClient>) -> Self {
        Self { http_client: client }
    }

    /// Fetch an entity configuration from the well-known endpoint.
    ///
    /// Reference: OpenID Federation 1.0 - Section 9 Obtaining Federation Entity Configuration Information
    /// <https://openid.net/specs/openid-federation-1_0.html#name-obtaining-federation-entity->
    pub async fn fetch_entity_configuration(&self, entity_id: &EntityId) -> FederationResult<String> {
        let well_known_url = self.build_well_known_url(entity_id)?;
        self.fetch_text(well_known_url).await
    }

    /// `GET` `url` and return the body of a 2xx response, or [`FederationError::Endpoint`].
    async fn fetch_text(&self, url: Url) -> FederationResult<String> {
        self.http_client.get(url.clone()).await?.into_success_body(url)
    }

    /// Fetch and authenticate the entity configuration of `entity_id`.
    ///
    /// Unlike [`FederationClient::fetch_entity_configuration`], which returns the raw response body,
    /// this verifies that the fetched document really is `entity_id`'s configuration: it must be
    /// structurally valid, have `iss` and `sub` equal to `entity_id`, and be self-signed with a key
    /// from its own `jwks` (see [`EntityConfiguration::from_verified_jwt`]). Discovery relies on
    /// this binding before following `authority_hints` or federation endpoints.
    ///
    /// # Returns
    /// The raw JWT together with the verified configuration.
    pub async fn resolve_entity_configuration(
        &self,
        entity_id: &EntityId,
    ) -> FederationResult<(String, EntityConfiguration)> {
        let jwt = self.fetch_entity_configuration(entity_id).await?;
        let config = EntityConfiguration::from_verified_jwt(&jwt, entity_id)?;
        Ok((jwt, config))
    }

    /// Fetch and authenticate the subordinate statement that `superior` issues about `subject`.
    ///
    /// The statement is fetched from the superior's `federation_fetch_endpoint` and verified with
    /// [`SubordinateStatement::from_verified_jwt`] against `superior_keys`, which must be keys
    /// already authenticated for the superior. During discovery those are the keys from the
    /// superior's verified entity configuration; [`TrustChain::try_new`] later re-verifies the
    /// whole chain with keys endorsed from the trust anchor downwards.
    async fn resolve_subordinate_statement(
        &self,
        superior: &EntityId,
        superior_keys: &crate::JwkSet,
        federation_fetch_endpoint: &Url,
        subject: &EntityId,
    ) -> FederationResult<(String, SubordinateStatement)> {
        let jwt = self
            .fetch_subordinate_statement(federation_fetch_endpoint, subject)
            .await?;
        let statement = SubordinateStatement::from_verified_jwt(&jwt, superior, subject, superior_keys)?;
        Ok((jwt, statement))
    }

    /// Fetch an subordinate statement from a federation fetch endpoint.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
    /// <https://openid.net/specs/openid-federation-1_0.html#name-fetching-a-subordinate-sta>
    pub async fn fetch_subordinate_statement(
        &self,
        federation_fetch_endpoint: &Url,
        subject: &EntityId,
    ) -> FederationResult<String> {
        let mut url = federation_fetch_endpoint.clone();
        url.query_pairs_mut().append_pair("sub", subject.as_str());

        self.fetch_text(url).await
    }

    /// Discover a trust chain from a leaf entity to a trusted anchor.
    ///
    /// This method implements Section 10.1 of OpenID Federation 1.0: fetching entity statements
    /// to establish a trust chain. It performs a single-path discovery by:
    /// 1. Fetching the leaf entity's configuration
    /// 2. Extracting authority hints (immediate superiors)
    /// 3. For each superior, fetching their configuration and subordinate statement
    /// 4. Recursively discovering superiors until reaching a trusted anchor
    ///
    /// # Arguments
    /// * `start_entity_id` - Starting entity for discovery.
    /// * `trusted_anchors` - Optional set of trusted anchor entity IDs (federation roots).
    ///   If `None`, trusted anchors are read from the starting entity configuration's
    ///   `trust_anchor_hints`.
    ///
    /// # Returns
    /// A `TrustChain` containing JWTs from leaf to trusted anchor, or an error if:
    /// - No path can be found to a trusted anchor
    /// - Authority hints are missing or empty
    /// - Required endpoints are unavailable
    /// - HTTP requests fail
    /// - Loop detection identifies a cycle
    ///
    /// Reference: OpenID Federation 1.0 - Section 10.1
    /// <https://openid.net/specs/openid-federation-1_0.html#name-fetching-entity-statement>
    pub async fn discover_trust_chain(
        &self,
        start_entity_id: &EntityId,
        trusted_anchors: Option<&[EntityId]>,
    ) -> FederationResult<TrustChain> {
        let mut visited = HashSet::new();
        let mut chain = Vec::new();

        let (_, start_entity_configuration) = self.resolve_entity_configuration(start_entity_id).await?;

        let trusted_anchors: Vec<EntityId> = if let Some(trusted_anchors) = trusted_anchors {
            trusted_anchors.to_vec()
        } else {
            let trust_anchor_hints = start_entity_configuration.trust_anchor_hints.clone().ok_or_else(|| {
                FederationError::EntityResolution(
                    "starting entity configuration has no trust_anchor_hints and no trusted anchors were provided"
                        .to_string(),
                )
            })?;

            if trust_anchor_hints.is_empty() {
                return Err(FederationError::EntityResolution(
                    "starting entity configuration has empty trust_anchor_hints and no trusted anchors were provided"
                        .to_string(),
                ));
            }

            trust_anchor_hints
        };

        self.discover_recursive(start_entity_id, &trusted_anchors, &mut visited, &mut chain)
            .await?;

        if chain.is_empty() {
            return Err(FederationError::EntityResolution(
                "No trust chain found to any trusted anchor".to_string(),
            ));
        }

        TrustChain::try_new(chain)
    }

    /// Discover every authenticated trust chain reachable from a starting entity.
    ///
    /// Every returned chain passed [`TrustChain::try_new`], and every entity configuration on it
    /// was fetched from, and is bound to, the entity identifier it claims. This method does not
    /// decide which trust anchors are trustworthy; callers must compare each chain's anchor
    /// (see [`TrustChain::trust_anchor_entity_id_and_configuration`]) against their own trust list.
    ///
    /// Unlike [`FederationClient::discover_trust_chain`], this method does not take a trusted-anchor
    /// list and does not read trusted anchors from the starting entity configuration. It walks every
    /// authority-hint branch it can resolve and returns all valid chains it finds.
    ///
    /// Every superior reached ends a chain, not only one without `authority_hints`: a Trust Anchor
    /// may have Superiors of its own when it also acts as an Intermediate Entity in another
    /// federation, so an entity with Superiors may still be the caller's Trust Anchor. A leaf below
    /// an Intermediate Entity below a Trust Anchor therefore yields two chains, one ending at each.
    ///
    /// Reference: OpenID Federation 1.0 - Section 4.1 Beginning and Ending Trust Chains
    /// <https://openid.net/specs/openid-federation-1_0.html#name-beginning-and-ending-trust->
    ///
    /// Branches that cannot be resolved or authenticated are skipped silently. Use
    /// [`FederationClient::discover_all_trust_chains_with_failures`] to learn which ones.
    pub async fn discover_all_trust_chains(&self, start_entity_id: &EntityId) -> FederationResult<Vec<TrustChain>> {
        let discovery = self.discover_all_trust_chains_with_failures(start_entity_id).await?;

        if discovery.chains.is_empty() {
            return Err(FederationError::EntityResolution("No trust chains found".to_string()));
        }

        Ok(discovery.chains)
    }

    /// Discover every authenticated trust chain reachable from a starting entity, and report every
    /// branch that had to be skipped.
    ///
    /// Walks the same branches and returns the same chains as
    /// [`FederationClient::discover_all_trust_chains`]. In addition, every skipped branch is
    /// recorded as a [`TrustChainDiscoveryFailure`]: a superior whose configuration, federation
    /// fetch endpoint or subordinate statement could not be resolved, a loop, or a found chain that
    /// failed [`TrustChain::try_new`]. This lets callers tell an entity without trust chains from
    /// one whose superiors could not be reached.
    ///
    /// # Returns
    /// The discovered chains and failures, which may both be empty. Fails only if the starting
    /// entity's own configuration cannot be resolved.
    pub async fn discover_all_trust_chains_with_failures(
        &self,
        start_entity_id: &EntityId,
    ) -> FederationResult<TrustChainDiscovery> {
        let mut discovery = TrustChainDiscovery::default();
        let mut visited = HashSet::new();
        let mut chain = Vec::new();

        self.discover_all_recursive(start_entity_id, &mut visited, &mut chain, &mut discovery)
            .await?;

        Ok(discovery)
    }

    /// Recursively discover one anchored trust chain by traversing superiors.
    ///
    /// Keep this function separate from `discover_all_recursive`: anchored discovery has
    /// fail-fast behavior and stronger errors, while the all-chains variant is best-effort
    /// and should continue exploring even when individual branches fail.
    fn discover_recursive<'a>(
        &'a self,
        entity_id: &'a EntityId,
        trusted_anchors: &'a [EntityId],
        visited: &'a mut HashSet<EntityId>,
        chain: &'a mut Vec<String>,
    ) -> Pin<Box<dyn Future<Output = FederationResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if visited.contains(entity_id) {
                return Err(FederationError::EntityResolution(format!(
                    "Loop detected in trust chain discovery at entity: {}",
                    entity_id
                )));
            }
            visited.insert(entity_id.clone());

            // Binds the fetched document to `entity_id`, so that a trusted anchor's entry in the
            // chain is really the configuration served by (and self-signed by) that anchor.
            let (config_jwt, config) = self.resolve_entity_configuration(entity_id).await?;
            // Superiors are asked about the entity under the identifier it publishes, which may be
            // spelled differently from `entity_id`, e.g. from an authority hint with a trailing `/`.
            let subject_id = &config.claims.sub;
            let is_root = chain.is_empty();
            let is_trusted_anchor = trusted_anchors.contains(entity_id);
            if is_root || is_trusted_anchor {
                chain.push(config_jwt);
            }

            if is_trusted_anchor {
                return Ok(());
            }

            let authority_hints = config.authority_hints.ok_or_else(|| {
                FederationError::EntityResolution(format!("Entity {} has no authority hints", entity_id))
            })?;

            if authority_hints.is_empty() {
                return Err(FederationError::EntityResolution(format!(
                    "Entity {} has empty authority hints",
                    entity_id
                )));
            }

            let mut last_error: Option<String> = None;
            for superior_id in authority_hints.iter() {
                let (_, superior_config) = match self.resolve_entity_configuration(superior_id).await {
                    Ok(resolved) => resolved,
                    Err(err) => {
                        last_error = Some(format!(
                            "Failed to resolve superior {} configuration: {}",
                            superior_id, err
                        ));
                        continue;
                    }
                };

                let fetch_endpoint = superior_config
                    .metadata
                    .as_ref()
                    .and_then(|m| m.federation_entity.as_ref())
                    .and_then(|f| f.federation_fetch_endpoint.clone())
                    .ok_or_else(|| {
                        FederationError::EntityResolution(format!(
                            "Superior {} has no federation_fetch_endpoint",
                            superior_id
                        ))
                    })?;

                let (subordinate_jwt, _) = match self
                    .resolve_subordinate_statement(superior_id, &superior_config.jwks, &fetch_endpoint, subject_id)
                    .await
                {
                    Ok(resolved) => resolved,
                    Err(err) => {
                        last_error = Some(format!(
                            "Failed to resolve subordinate statement from {} for {} via {}: {}",
                            superior_id, entity_id, fetch_endpoint, err
                        ));
                        continue;
                    }
                };

                let rollback_len = chain.len();
                chain.push(subordinate_jwt);

                match self
                    .discover_recursive(superior_id, trusted_anchors, visited, chain)
                    .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        last_error = Some(err.to_string());
                        chain.truncate(rollback_len);
                        continue;
                    }
                }
            }

            let details = last_error.map(|e| format!(" Last error: {}", e)).unwrap_or_default();
            Err(FederationError::EntityResolution(format!(
                "No superior for {} could establish a path to a trusted anchor.{}",
                entity_id, details
            )))
        })
    }

    /// Recursively discover all authenticated trust chains by traversing every superior branch.
    ///
    /// Keep this function separate from `discover_recursive`: all-chains discovery is
    /// intentionally best-effort and continues exploring siblings when one branch fails,
    /// recording the failure in `discovery`, while anchored discovery fails fast.
    ///
    /// Returns an error only if `entity_id` itself cannot be resolved or closes a loop; the
    /// caller records that as a failure of its branch.
    fn discover_all_recursive<'a>(
        &'a self,
        entity_id: &'a EntityId,
        visited: &'a mut HashSet<EntityId>,
        chain: &'a mut Vec<String>,
        discovery: &'a mut TrustChainDiscovery,
    ) -> Pin<Box<dyn Future<Output = FederationResult<()>> + Send + 'a>> {
        Box::pin(async move {
            if visited.contains(entity_id) {
                return Err(FederationError::EntityResolution(format!(
                    "Loop detected in trust chain discovery at entity: {}",
                    entity_id
                )));
            }
            visited.insert(entity_id.clone());

            let result = async {
                // Binds the fetched document to `entity_id`; a terminal configuration that claims
                // another entity's identity is rejected here instead of becoming a chain's anchor.
                let (config_jwt, config) = self.resolve_entity_configuration(entity_id).await?;
                // Superiors are asked about the entity under the identifier it publishes, which may be
                // spelled differently from `entity_id`, e.g. from an authority hint with a trailing `/`.
                let subject_id = &config.claims.sub;
                let is_leaf = chain.is_empty();

                if is_leaf {
                    chain.push(config_jwt);
                } else {
                    // Every superior ends a chain, not only one without superiors of its own: a
                    // Trust Anchor may also act as an Intermediate Entity in another federation
                    // (Section 4.1), and which anchors to trust is the caller's decision.
                    chain.push(config_jwt);
                    match TrustChain::try_new(chain.clone()) {
                        Ok(trust_chain) => discovery.chains.push(trust_chain),
                        Err(error) => discovery.failures.push(TrustChainDiscoveryFailure {
                            entity_id: entity_id.clone(),
                            error,
                        }),
                    }
                    // Backtrack: the configuration ends this chain only, longer ones continue with
                    // the subordinate statements about this entity.
                    chain.pop();
                }

                let authority_hints = match config.authority_hints {
                    Some(hints) if !hints.is_empty() => hints,
                    _ => {
                        if is_leaf {
                            chain.pop();
                        }

                        return Ok(());
                    }
                };

                for superior_id in authority_hints.iter() {
                    let skip = |error| TrustChainDiscoveryFailure {
                        entity_id: superior_id.clone(),
                        error,
                    };

                    let (_, superior_config) = match self.resolve_entity_configuration(superior_id).await {
                        Ok(resolved) => resolved,
                        Err(err) => {
                            discovery.failures.push(skip(err));
                            continue;
                        }
                    };

                    let fetch_endpoint = match superior_config
                        .metadata
                        .as_ref()
                        .and_then(|m| m.federation_entity.as_ref())
                        .and_then(|f| f.federation_fetch_endpoint.clone())
                    {
                        Some(endpoint) => endpoint,
                        None => {
                            discovery.failures.push(skip(FederationError::EntityResolution(format!(
                                "Superior {} has no federation_fetch_endpoint",
                                superior_id
                            ))));
                            continue;
                        }
                    };

                    let (subordinate_jwt, _) = match self
                        .resolve_subordinate_statement(superior_id, &superior_config.jwks, &fetch_endpoint, subject_id)
                        .await
                    {
                        Ok(resolved) => resolved,
                        Err(err) => {
                            discovery.failures.push(skip(err));
                            continue;
                        }
                    };

                    chain.push(subordinate_jwt);

                    let branch_result = self
                        .discover_all_recursive(superior_id, visited, chain, discovery)
                        .await;

                    // Remove the subordinate statement that was added for this child branch.
                    chain.pop();

                    if let Err(err) = branch_result {
                        discovery.failures.push(skip(err));
                    }
                }

                // Backtrack the leaf configuration pushed by this frame.
                if is_leaf {
                    chain.pop();
                }

                Ok(())
            }
            .await;

            visited.remove(entity_id);
            result
        })
    }

    /// List entities from a federation list endpoint.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.3 Federation List Endpoint
    /// <https://openid.net/specs/openid-federation-1_0.html#name-federation-list-endpoint>
    pub async fn list_entities(&self, list_endpoint: &Url) -> FederationResult<Vec<EntityId>> {
        let response_text = self.fetch_text(list_endpoint.clone()).await?;
        let entity_list: Vec<String> = serde_json::from_str(&response_text)?;
        entity_list
            .into_iter()
            .map(|entity_id| EntityId::parse(&entity_id))
            .collect()
    }

    /// Build the well-known OpenID Federation URL for an entity: the Entity Identifier, including
    /// any path and without a trailing `/`, followed by `/.well-known/openid-federation`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 9 Obtaining Federation Entity Configuration Information
    /// <https://openid.net/specs/openid-federation-1_0.html#name-obtaining-federation-entity->
    fn build_well_known_url(&self, entity_id: &EntityId) -> FederationResult<Url> {
        let mut url = entity_id.as_url().clone();
        url.set_query(None);
        url.set_fragment(None);
        let path = format!("{}/.well-known/openid-federation", url.path().trim_end_matches('/'));
        url.set_path(&path);
        Ok(url)
    }
}

impl Default for FederationClient {
    fn default() -> Self {
        Self::new()
    }
}

/// URL validation utilities.
pub struct UrlValidator;

impl UrlValidator {
    /// Validate that a URL is suitable for use as an entity identifier.
    ///
    /// Reference: OpenID Federation 1.0 - Section 2.1 Entity Identifier
    /// <https://openid.net/specs/openid-federation-1_0.html#name-entity-identifier>
    pub fn validate_entity_id(url: &Url) -> FederationResult<()> {
        // Entity ID must use HTTPS
        if url.scheme() != "https" {
            return Err(FederationError::Configuration(
                "Entity ID must use HTTPS scheme".to_string(),
            ));
        }

        // Entity ID must not have a fragment
        if url.fragment().is_some() {
            return Err(FederationError::Configuration(
                "Entity ID must not contain a fragment".to_string(),
            ));
        }

        // Entity ID must have a host
        if url.host().is_none() {
            return Err(FederationError::Configuration("Entity ID must have a host".to_string()));
        }

        Ok(())
    }

    /// Validate that a URL is suitable for use as a federation endpoint: it uses `https`, has a
    /// host and has no fragment.
    ///
    /// Reference: OpenID Federation 1.0 - Section 5.1.1 Federation Entity
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.1>)
    pub fn validate_endpoint_url(url: &Url) -> FederationResult<()> {
        // Endpoint must use HTTPS
        if url.scheme() != "https" {
            return Err(FederationError::Configuration(
                "Endpoint URL must use HTTPS scheme".to_string(),
            ));
        }

        // Endpoint must not have a fragment
        if url.fragment().is_some() {
            return Err(FederationError::Configuration(
                "Endpoint URL must not contain a fragment".to_string(),
            ));
        }

        // Endpoint must have a host
        if url.host().is_none() {
            return Err(FederationError::Configuration(
                "Endpoint URL must have a host".to_string(),
            ));
        }

        Ok(())
    }
}

/// Get a timestamp that expires after the specified duration from now.
pub fn expires_in(duration: Duration) -> i64 {
    Utc::now().timestamp() + duration.num_seconds()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn well_known_url(entity_id: &str) -> String {
        FederationClient::new()
            .build_well_known_url(&EntityId::parse(entity_id).unwrap())
            .unwrap()
            .to_string()
    }

    #[test]
    fn appends_the_well_known_path_to_a_host_only_entity_identifier() {
        assert_eq!(
            well_known_url("https://entity.example"),
            "https://entity.example/.well-known/openid-federation"
        );
    }

    #[test]
    fn keeps_the_path_of_an_entity_identifier() {
        assert_eq!(
            well_known_url("https://entity.example/federation"),
            "https://entity.example/federation/.well-known/openid-federation"
        );
    }

    #[test]
    fn removes_a_trailing_slash_before_appending_the_well_known_path() {
        assert_eq!(
            well_known_url("https://entity.example/federation/"),
            "https://entity.example/federation/.well-known/openid-federation"
        );
    }
}
