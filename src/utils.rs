//! Utility functions for OpenID Federation operations.

use crate::{EntityConfiguration, EntityId, FederationError, FederationResult, JwtProcessor, TrustChain};
use chrono::{Duration, Utc};
use reqwest::Client;
use std::collections::HashSet;
use std::sync::Arc;
use url::Url;

use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;

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
        let response = self
            .client
            .get(url)
            .header("Accept", "application/entity-statement+jwt") // TODO: this fn is very generic ("fetch_text") but then typed to only one type of response type?
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(FederationError::EntityResolution(format!(
                "Failed to fetch entity statement: HTTP {}",
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
        fetch_endpoint: &Url,
        issuer: &EntityId,
        subject: &EntityId,
    ) -> FederationResult<String> {
        let mut url = fetch_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("iss", issuer.as_str())
            .append_pair("sub", subject.as_str());

        self.http_client.fetch_text(url).await
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
    /// * `leaf_entity_id` - The entity to start discovery from
    /// * `trusted_anchors` - Set of trusted anchor entity IDs (federation roots)
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
        leaf_entity_id: &EntityId,
        trusted_anchors: &[EntityId],
    ) -> FederationResult<TrustChain> {
        let trusted_anchors_set: HashSet<_> = trusted_anchors.iter().cloned().collect();
        let mut visited = HashSet::new();
        let mut chain = Vec::new();

        self.discover_recursive(leaf_entity_id, &trusted_anchors_set, &mut visited, &mut chain)
            .await?;

        if chain.is_empty() {
            return Err(FederationError::EntityResolution(
                "No trust chain found to any trusted anchor".to_string(),
            ));
        }

        Ok(TrustChain {
            chain,
            metadata: None,
            trust_marks: None,
        })
    }

    /// Recursively discover trust chain by traversing superiors.
    ///
    /// Private helper for discover_trust_chain that builds the chain bottom-up.
    fn discover_recursive<'a>(
        &'a self,
        entity_id: &'a EntityId,
        trusted_anchors: &'a HashSet<EntityId>,
        visited: &'a mut HashSet<EntityId>,
        chain: &'a mut Vec<String>,
    ) -> Pin<Box<dyn Future<Output = FederationResult<()>> + 'a>> {
        Box::pin(async move {
            // Check for loops
            if visited.contains(entity_id) {
                return Err(FederationError::EntityResolution(format!(
                    "Loop detected in trust chain discovery at entity: {}",
                    entity_id
                )));
            }
            visited.insert(entity_id.clone());

            // Fetch the entity's configuration
            let config_jwt = self.fetch_entity_configuration(entity_id).await?;
            let config: EntityConfiguration = JwtProcessor::new().extract_claims_unverified(&config_jwt)?;

            // Add this entity's configuration to the chain
            chain.push(config_jwt);

            // Check if this entity is a trusted anchor
            if trusted_anchors.contains(entity_id) {
                return Ok(());
            }

            // Extract authority hints (immediate superiors)
            let authority_hints = config.authority_hints.ok_or_else(|| {
                FederationError::EntityResolution(format!("Entity {} has no authority hints", entity_id))
            })?;

            if authority_hints.is_empty() {
                return Err(FederationError::EntityResolution(format!(
                    "Entity {} has empty authority hints",
                    entity_id
                )));
            }

            // Try each superior (single-path: use first available)
            for superior_id in authority_hints.iter() {
                // Fetch superior's configuration first
                if let Ok(superior_config_jwt) = self.fetch_entity_configuration(superior_id).await {
                    let superior_config: EntityConfiguration =
                        JwtProcessor::new().extract_claims_unverified(&superior_config_jwt)?;

                    // Fetch the subordinate statement (entity signed by superior)
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

                    if let Ok(subordinate_jwt) = self
                        .fetch_subordinate_statement(&fetch_endpoint, superior_id, entity_id)
                        .await
                    {
                        // Insert the subordinate statement at the beginning (before current entity's config)
                        chain.insert(chain.len() - 1, subordinate_jwt);

                        // Recursively discover from the superior
                        match self
                            .discover_recursive(superior_id, trusted_anchors, visited, chain)
                            .await
                        {
                            Ok(()) => return Ok(()),
                            Err(err) => {
                                if let FederationError::EntityResolution(msg) = &err {
                                    if msg.to_lowercase().contains("loop") {
                                        return Err(err);
                                    }
                                }

                                // Remove this superior from chain and try next one
                                if chain.len() >= 2 {
                                    chain.remove(chain.len() - 2);
                                }
                                continue;
                            }
                        }
                    }
                }
            }

            Err(FederationError::EntityResolution(format!(
                "No superior for {} could establish a path to a trusted anchor",
                entity_id
            )))
        })
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
