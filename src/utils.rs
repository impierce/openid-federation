//! Utility functions for OpenID Federation operations.

use crate::{extract_claims_unverified, EntityConfiguration, EntityId, FederationError, FederationResult, TrustChain};
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
/// Implementations should fetch the given URL as text and return the response body or an error.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Fetch text content from the given URL.
    ///
    /// # Arguments
    /// * `url` - The URL to fetch from.
    ///
    /// # Returns
    /// The response body as a string, or a `FederationError` on HTTP error or network failure.
    async fn fetch_text(&self, url: Url) -> FederationResult<String>;
}

/// Default HTTP client implementation using `reqwest`.
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

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn fetch_text(&self, url: Url) -> FederationResult<String> {
        let response = self.client.get(url.clone()).send().await?;

        if !response.status().is_success() {
            return Err(FederationError::EntityResolution(format!(
                "Failed to fetch response from {url}: HTTP {}",
                response.status()
            )));
        }

        response.text().await.map_err(FederationError::from)
    }
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
    /// https://openid.net/specs/openid-federation-1_0.html#name-obtaining-federation-entity-
    pub async fn fetch_entity_configuration(&self, entity_id: &EntityId) -> FederationResult<String> {
        let well_known_url = self.build_well_known_url(entity_id)?;
        self.http_client.fetch_text(well_known_url).await
    }

    /// Fetch an subordinate statement from a federation fetch endpoint.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
    /// https://openid.net/specs/openid-federation-1_0.html#name-fetching-a-subordinate-sta
    pub async fn fetch_subordinate_statement(
        &self,
        federation_fetch_endpoint: &Url,
        subject: &EntityId,
    ) -> FederationResult<String> {
        let mut url = federation_fetch_endpoint.clone();
        url.query_pairs_mut().append_pair("sub", subject.as_str());

        self.http_client.fetch_text(url).await
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
    /// https://openid.net/specs/openid-federation-1_0.html#name-fetching-entity-statement
    pub async fn discover_trust_chain(
        &self,
        start_entity_id: &EntityId,
        trusted_anchors: Option<&[EntityId]>,
    ) -> FederationResult<TrustChain> {
        let mut visited = HashSet::new();
        let mut chain = Vec::new();

        let start_entity_config_jwt = self.fetch_entity_configuration(start_entity_id).await?;
        let start_entity_configuration: EntityConfiguration = extract_claims_unverified(&start_entity_config_jwt)?;

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

    /// Discover every structurally valid trust chain reachable from a starting entity.
    ///
    /// Unlike [`FederationClient::discover_trust_chain`], this method does not take a trusted-anchor
    /// list and does not read trusted anchors from the starting entity configuration. It walks every
    /// authority-hint branch it can resolve and returns all valid chains it finds.
    pub async fn discover_all_trust_chains(&self, start_entity_id: &EntityId) -> FederationResult<Vec<TrustChain>> {
        let mut discovered = Vec::new();
        let mut visited = HashSet::new();
        let mut chain = Vec::new();

        self.discover_all_recursive(start_entity_id, &mut visited, &mut chain, &mut discovered)
            .await?;

        if discovered.is_empty() {
            return Err(FederationError::EntityResolution("No trust chains found".to_string()));
        }

        Ok(discovered)
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

            let config_jwt = self.fetch_entity_configuration(entity_id).await?;
            let config: EntityConfiguration = extract_claims_unverified(&config_jwt)?;
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
                let superior_config_jwt = match self.fetch_entity_configuration(superior_id).await {
                    Ok(jwt) => jwt,
                    Err(err) => {
                        last_error = Some(format!(
                            "Failed to fetch superior {} configuration: {}",
                            superior_id, err
                        ));
                        continue;
                    }
                };

                let superior_config: EntityConfiguration = extract_claims_unverified(&superior_config_jwt)?;

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

                let subordinate_jwt = match self.fetch_subordinate_statement(&fetch_endpoint, entity_id).await {
                    Ok(jwt) => jwt,
                    Err(err) => {
                        last_error = Some(format!(
                            "Failed to fetch subordinate statement from {} for {} via {}: {}",
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

    /// Recursively discover all structurally valid trust chains by traversing every superior branch.
    ///
    /// Keep this function separate from `discover_recursive`: all-chains discovery is
    /// intentionally best-effort and continues exploring siblings when one branch fails,
    /// while anchored discovery should return richer branch-specific errors.
    fn discover_all_recursive<'a>(
        &'a self,
        entity_id: &'a EntityId,
        visited: &'a mut HashSet<EntityId>,
        chain: &'a mut Vec<String>,
        discovered: &'a mut Vec<TrustChain>,
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
                let config_jwt = self.fetch_entity_configuration(entity_id).await?;
                let config: EntityConfiguration = extract_claims_unverified(&config_jwt)?;
                let is_leaf = chain.is_empty();
                // Remember if this step added its own config JWT to `chain`.
                // If yes, this step must remove it before returning.
                // Otherwise we might pop a parent item or leak items into sibling branches.
                let mut pushed_config = false;

                if is_leaf {
                    chain.push(config_jwt.clone());
                    pushed_config = true;
                }

                let authority_hints = match config.authority_hints {
                    Some(hints) if !hints.is_empty() => hints,
                    _ => {
                        // Terminal branch: include this node config as the chain endpoint.
                        if !is_leaf {
                            chain.push(config_jwt);
                            pushed_config = true;
                        }

                        if chain.len() >= 2 {
                            if let Ok(trust_chain) = TrustChain::try_new(chain.clone()) {
                                discovered.push(trust_chain);
                            }
                        }

                        // Backtrack to restore the parent frame's chain state.
                        if pushed_config {
                            chain.pop();
                        }

                        return Ok(());
                    }
                };

                for superior_id in authority_hints.iter() {
                    let superior_config_jwt = match self.fetch_entity_configuration(superior_id).await {
                        Ok(jwt) => jwt,
                        Err(_) => {
                            continue;
                        }
                    };

                    let superior_config: EntityConfiguration = match extract_claims_unverified(&superior_config_jwt) {
                        Ok(config) => config,
                        Err(_) => {
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
                        None => continue,
                    };

                    let subordinate_jwt = match self.fetch_subordinate_statement(&fetch_endpoint, entity_id).await {
                        Ok(jwt) => jwt,
                        Err(_) => {
                            continue;
                        }
                    };

                    chain.push(subordinate_jwt);

                    let branch_result = self
                        .discover_all_recursive(superior_id, visited, chain, discovered)
                        .await;

                    // Remove the subordinate statement that was added for this child branch.
                    chain.pop();

                    if branch_result.is_err() {
                        continue;
                    }
                }

                // Backtrack config push done by this frame (root case).
                if pushed_config {
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
    /// https://openid.net/specs/openid-federation-1_0.html#name-federation-list-endpoint
    pub async fn list_entities(&self, list_endpoint: &Url) -> FederationResult<Vec<EntityId>> {
        let response_text = self.http_client.fetch_text(list_endpoint.clone()).await?;
        let entity_list: Vec<String> = serde_json::from_str(&response_text)?;
        entity_list
            .into_iter()
            .map(|url_str| Url::parse(&url_str).map_err(FederationError::from))
            .collect()
    }

    /// Build the well-known OpenID Federation URL for an entity.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Entity Configuration Endpoint
    /// https://openid.net/specs/openid-federation-1_0.html#name-entity-configuration-endpoi
    fn build_well_known_url(&self, entity_id: &EntityId) -> FederationResult<Url> {
        let mut url = entity_id.clone();
        url.set_path("/.well-known/openid-federation");
        url.set_query(None);
        url.set_fragment(None);
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
    /// https://openid.net/specs/openid-federation-1_0.html#name-entity-identifier
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

    /// Validate that a URL is suitable for use as an endpoint.
    pub fn validate_endpoint_url(url: &Url) -> FederationResult<()> {
        // Endpoint must use HTTPS
        if url.scheme() != "https" {
            return Err(FederationError::Configuration(
                "Endpoint URL must use HTTPS scheme".to_string(),
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
