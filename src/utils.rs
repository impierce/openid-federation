//! Utility functions for OpenID Federation operations.

use crate::{EntityId, FederationError, FederationResult};
use reqwest::Client;
use url::Url;

/// HTTP client for federation operations.
pub struct FederationClient {
    client: Client,
}

impl FederationClient {
    /// Create a new federation client.
    pub fn new() -> Self {
        Self { client: Client::new() }
    }

    /// Create a federation client with a custom HTTP client.
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    /// Fetch an entity configuration from the well-known endpoint.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Entity Configuration Endpoint
    /// https://openid.net/specs/openid-federation-1_0.html#name-entity-configuration-endpoi
    pub async fn fetch_entity_configuration(&self, entity_id: &EntityId) -> FederationResult<String> {
        let well_known_url = self.build_well_known_url(entity_id)?;

        let response = self
            .client
            .get(well_known_url)
            .header("Accept", "application/entity-statement+jwt")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(FederationError::EntityResolution(format!(
                "Failed to fetch entity configuration: HTTP {}",
                response.status()
            )));
        }

        response.text().await.map_err(FederationError::from)
    }

    /// Fetch an entity statement from a federation fetch endpoint.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2 Federation Fetch Endpoint
    /// https://openid.net/specs/openid-federation-1_0.html#name-federation-fetch-endpoint
    pub async fn fetch_entity_statement(
        &self,
        fetch_endpoint: &Url,
        issuer: &EntityId,
        subject: &EntityId,
    ) -> FederationResult<String> {
        let mut url = fetch_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("iss", issuer.as_str())
            .append_pair("sub", subject.as_str());

        let response = self
            .client
            .get(url)
            .header("Accept", "application/entity-statement+jwt")
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

    /// List entities from a federation list endpoint.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.3 Federation List Endpoint
    /// https://openid.net/specs/openid-federation-1_0.html#name-federation-list-endpoint
    pub async fn list_entities(&self, list_endpoint: &Url) -> FederationResult<Vec<EntityId>> {
        let response = self
            .client
            .get(list_endpoint.clone())
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(FederationError::EntityResolution(format!(
                "Failed to list entities: HTTP {}",
                response.status()
            )));
        }

        let entity_list: Vec<String> = response.json().await?;
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

/// Time utilities for federation operations.
pub mod time {
    use chrono::{Duration, Utc};

    /// Get the current UTC time as seconds since Unix epoch.
    pub fn now() -> i64 {
        Utc::now().timestamp()
    }

    /// Get a timestamp that expires after the specified duration from now.
    pub fn expires_in(duration: Duration) -> i64 {
        now() + duration.num_seconds()
    }

    /// Get a timestamp that was issued the specified duration ago.
    pub fn issued_ago(duration: Duration) -> i64 {
        now() - duration.num_seconds()
    }

    /// Check if a timestamp is in the past (expired).
    pub fn is_expired(timestamp: i64) -> bool {
        timestamp < now()
    }

    /// Check if a timestamp is in the future (not yet valid).
    pub fn is_not_yet_valid(timestamp: i64) -> bool {
        timestamp > now()
    }

    /// Get a standard expiration time for entity configurations (24 hours from now).
    pub fn standard_entity_config_expiry() -> i64 {
        expires_in(Duration::hours(24))
    }

    /// Get a standard expiration time for entity statements (1 hour from now).
    pub fn standard_entity_statement_expiry() -> i64 {
        expires_in(Duration::hours(1))
    }
}

/// Path building utilities for federation operations.
pub mod path {
    use crate::{EntityId, FederationError, FederationResult};

    /// Build a trust chain discovery path.
    pub fn build_trust_chain_path(
        leaf_entity: &EntityId,
        trust_anchor: &EntityId,
        intermediates: &[EntityId],
    ) -> FederationResult<Vec<EntityId>> {
        let mut path = Vec::new();
        path.push(leaf_entity.clone());
        path.extend_from_slice(intermediates);
        path.push(trust_anchor.clone());

        // Validate that all entities in the path are valid
        for entity_id in &path {
            crate::UrlValidator::validate_entity_id(entity_id)?;
        }

        Ok(path)
    }

    /// Extract the domain from an entity ID.
    pub fn extract_domain(entity_id: &EntityId) -> FederationResult<String> {
        entity_id
            .host_str()
            .map(|host| host.to_string())
            .ok_or_else(|| FederationError::Configuration("Entity ID does not have a valid host".to_string()))
    }

    /// Check if two entity IDs are in the same domain.
    pub fn same_domain(entity1: &EntityId, entity2: &EntityId) -> FederationResult<bool> {
        let domain1 = extract_domain(entity1)?;
        let domain2 = extract_domain(entity2)?;
        Ok(domain1 == domain2)
    }
}
