//! Structure representing a Federation Entity of any type.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use crate::{
    EntityConfiguration, EntityId, EntityStatement, FederationClient, FederationError, FederationResult, JwtProcessor,
    TrustChain,
};

/// A federation entity with its local configuration and subordinate statements.
#[derive(Clone, Serialize, Deserialize)]
pub struct FederationEntity {
    /// Runtime client used for network operations; skipped in serde.
    #[serde(skip, default)]
    pub client: FederationClient,
    /// The entity identifier.
    pub entity_id: EntityId,
    /// The self-issued entity configuration.
    pub entity_configuration: EntityConfiguration,
    /// Subordinate statements issued by this entity about subordinate entities.
    pub subordinate_statements: Vec<EntityStatement>,
}

impl std::fmt::Debug for FederationEntity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationEntity")
            .field("entity_id", &self.entity_id)
            .field("entity_configuration", &self.entity_configuration)
            .field("subordinate_statements", &self.subordinate_statements)
            .finish()
    }
}

impl PartialEq for FederationEntity {
    fn eq(&self, other: &Self) -> bool {
        self.entity_id == other.entity_id
            && self.entity_configuration == other.entity_configuration
            && self.subordinate_statements == other.subordinate_statements
    }
}

impl FederationEntity {
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
    /// * `start_entity_id` - Optional starting entity for discovery.
    ///   If `None`, discovery starts from `self.entity_id`.
    /// * `trusted_anchors` - Optional set of trusted anchor entity IDs (federation roots).
    ///   If `None`, trusted anchors are read from `self.entity_configuration.trust_anchor_hints`.
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
        start_entity_id: Option<&EntityId>,
        trusted_anchors: Option<&[EntityId]>,
    ) -> FederationResult<TrustChain> {
        let mut visited = HashSet::new();
        let mut chain = Vec::new();
        let start_entity_id = start_entity_id.unwrap_or(&self.entity_id);

        let trusted_anchors: Vec<EntityId> = if let Some(trusted_anchors) = trusted_anchors {
            trusted_anchors.to_vec()
        } else {
            let trust_anchor_hints = self.entity_configuration.trust_anchor_hints.clone().ok_or_else(|| {
                FederationError::EntityResolution(
                    "self.entity_configuration has no trust_anchor_hints and no trusted anchors were provided"
                        .to_string(),
                )
            })?;

            if trust_anchor_hints.is_empty() {
                return Err(FederationError::EntityResolution(
                    "self.entity_configuration has empty trust_anchor_hints and no trusted anchors were provided"
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

    /// Recursively discover trust chain by traversing superiors.
    fn discover_recursive<'a>(
        &'a self,
        entity_id: &'a EntityId,
        trusted_anchors: &'a [EntityId],
        visited: &'a mut HashSet<EntityId>,
        chain: &'a mut Vec<String>,
    ) -> Pin<Box<dyn Future<Output = FederationResult<()>> + 'a>> {
        Box::pin(async move {
            if visited.contains(entity_id) {
                return Err(FederationError::EntityResolution(format!(
                    "Loop detected in trust chain discovery at entity: {}",
                    entity_id
                )));
            }
            visited.insert(entity_id.clone());

            let config_jwt = self.client.fetch_entity_configuration(entity_id).await?;
            let config: EntityConfiguration = JwtProcessor::new().extract_claims_unverified(&config_jwt)?;

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

            for superior_id in authority_hints.iter() {
                if let Ok(superior_config_jwt) = self.client.fetch_entity_configuration(superior_id).await {
                    let superior_config: EntityConfiguration =
                        JwtProcessor::new().extract_claims_unverified(&superior_config_jwt)?;

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
                        .client
                        .fetch_entity_statement(&fetch_endpoint, superior_id, entity_id)
                        .await
                    {
                        let rollback_len = chain.len();
                        chain.push(subordinate_jwt);

                        match self
                            .discover_recursive(superior_id, trusted_anchors, visited, chain)
                            .await
                        {
                            Ok(()) => return Ok(()),
                            Err(_) => {
                                chain.truncate(rollback_len);
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
}
