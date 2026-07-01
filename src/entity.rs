//! Structure representing a Federation Entity of any type.

use serde::{Deserialize, Serialize};

use crate::{
    EntityConfiguration, EntityId, EntityStatement, FederationClient, FederationError, FederationResult, TrustChain,
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
    /// Discover a trust chain from this entity to a trusted anchor.
    ///
    /// This is a convenience wrapper around [`FederationClient::discover_trust_chain`]
    /// that uses `self.entity_id` when `start_entity_id` is `None`.
    /// When `trusted_anchors` is `None`, it uses the `trust_anchor_hints` from this entity's configuration.
    pub async fn discover_trust_chain(
        &self,
        start_entity_id: Option<&EntityId>,
        trusted_anchors: Option<&[EntityId]>,
    ) -> FederationResult<TrustChain> {
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

        self.client
            .discover_trust_chain(start_entity_id, Some(&trusted_anchors))
            .await
    }
}
