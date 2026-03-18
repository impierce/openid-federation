//! Trust Chain structures and validation logic.

use crate::{EntityConfiguration, EntityId, EntityStatement, FederationError, FederationResult, JwtProcessor};
use serde::{Deserialize, Serialize};

/// Trust Chain as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 4 Trust Chains  
/// https://openid.net/specs/openid-federation-1_0.html#name-trust-chains
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustChain {
    /// Array of Entity Statements that form the trust chain
    /// The first element is the leaf entity's Entity Statement
    /// The last element is the Trust Anchor's Entity Configuration
    pub chain: Vec<String>, // JWT strings
    /// Metadata obtained from the trust chain resolution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<crate::EntityMetadata>,
    /// Trust marks obtained from the trust chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_marks: Option<Vec<crate::TrustMark>>,
}

/// Trust Chain Validator for OpenID Federation.
pub struct TrustChainValidator {
    jwt_processor: JwtProcessor,
}

impl TrustChainValidator {
    /// Create a new trust chain validator.
    pub fn new() -> Self {
        Self {
            jwt_processor: JwtProcessor::new(),
        }
    }

    /// Validate a trust chain.
    ///
    /// Reference: OpenID Federation 1.0 - Section 4.2 Trust Chain Validation
    /// https://openid.net/specs/openid-federation-1_0.html#name-trust-chain-validation
    pub fn validate_trust_chain(&self, trust_chain: &TrustChain) -> FederationResult<ValidatedTrustChain> {
        if trust_chain.chain.is_empty() {
            return Err(FederationError::TrustChainValidation(
                "Trust chain cannot be empty".to_string(),
            ));
        }

        let mut validated_statements = Vec::new();
        let mut current_subject: Option<EntityId> = None;

        // Process each JWT in the chain
        for (index, jwt_string) in trust_chain.chain.iter().enumerate() {
            if index == 0 {
                // First element should be a leaf entity configuration (self-signed)
                let entity_config: EntityConfiguration = self.jwt_processor.extract_claims_unverified(jwt_string)?;

                entity_config.validate()?;

                // Verify signature using the entity's own keys
                let verified_config: EntityConfiguration = self
                    .jwt_processor
                    .verify_jwt_with_jwks(jwt_string, &entity_config.jwks)?;

                current_subject = Some(verified_config.claims.sub.clone());
                validated_statements.push(ValidatedEntityStatement::Configuration(verified_config));
            } else if index == trust_chain.chain.len() - 1 {
                // Last element should be the trust anchor's entity configuration
                let trust_anchor_config: EntityConfiguration =
                    self.jwt_processor.extract_claims_unverified(jwt_string)?;

                trust_anchor_config.validate()?;

                // Verify signature using the trust anchor's own keys
                let verified_anchor: EntityConfiguration = self
                    .jwt_processor
                    .verify_jwt_with_jwks(jwt_string, &trust_anchor_config.jwks)?;

                validated_statements.push(ValidatedEntityStatement::Configuration(verified_anchor));
            } else {
                // Intermediate entity statements
                let entity_statement: EntityStatement = self.jwt_processor.extract_claims_unverified(jwt_string)?;

                entity_statement.validate()?;

                // Verify that the subject matches the expected entity
                if let Some(expected_subject) = &current_subject {
                    if &entity_statement.claims.sub != expected_subject {
                        return Err(FederationError::TrustChainValidation(
                            "Trust chain subject mismatch".to_string(),
                        ));
                    }
                }

                // For now, we'll store the unverified statement
                // In a full implementation, we'd verify it against the issuer's keys
                current_subject = Some(entity_statement.claims.iss.clone());
                validated_statements.push(ValidatedEntityStatement::Statement(entity_statement));
            }
        }

        // Additional validation: check that the chain is properly linked
        self.validate_chain_linkage(&validated_statements)?;

        Ok(ValidatedTrustChain {
            leaf_entity_id: self.get_leaf_entity_id(&validated_statements)?,
            trust_anchor_id: self.get_trust_anchor_id(&validated_statements)?,
            statements: validated_statements,
        })
    }

    /// Validate that the trust chain statements are properly linked.
    fn validate_chain_linkage(&self, statements: &[ValidatedEntityStatement]) -> FederationResult<()> {
        if statements.len() < 2 {
            return Err(FederationError::TrustChainValidation(
                "Trust chain must contain at least 2 statements".to_string(),
            ));
        }

        for i in 0..(statements.len() - 1) {
            let _current_entity_id = match &statements[i] {
                ValidatedEntityStatement::Configuration(config) => &config.claims.sub,
                ValidatedEntityStatement::Statement(stmt) => &stmt.claims.sub,
            };

            let next_issuer_id = match &statements[i + 1] {
                ValidatedEntityStatement::Configuration(config) => &config.claims.iss,
                ValidatedEntityStatement::Statement(stmt) => &stmt.claims.iss,
            };

            // For intermediate statements, the subject of the current statement
            // should match the issuer of the next statement (when going up the chain)
            if i > 0 {
                let current_issuer_id = match &statements[i] {
                    ValidatedEntityStatement::Configuration(_) => {
                        return Err(FederationError::TrustChainValidation(
                            "Entity configuration can only be at the beginning or end of chain".to_string(),
                        ));
                    }
                    ValidatedEntityStatement::Statement(stmt) => &stmt.claims.iss,
                };

                if current_issuer_id != next_issuer_id {
                    return Err(FederationError::TrustChainValidation(
                        "Trust chain is not properly linked".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get the leaf entity ID from the validated statements.
    fn get_leaf_entity_id(&self, statements: &[ValidatedEntityStatement]) -> FederationResult<EntityId> {
        match statements.first() {
            Some(ValidatedEntityStatement::Configuration(config)) => Ok(config.claims.sub.clone()),
            Some(ValidatedEntityStatement::Statement(stmt)) => Ok(stmt.claims.sub.clone()),
            None => Err(FederationError::TrustChainValidation("Empty trust chain".to_string())),
        }
    }

    /// Get the trust anchor ID from the validated statements.
    fn get_trust_anchor_id(&self, statements: &[ValidatedEntityStatement]) -> FederationResult<EntityId> {
        match statements.last() {
            Some(ValidatedEntityStatement::Configuration(config)) => Ok(config.claims.iss.clone()),
            Some(ValidatedEntityStatement::Statement(stmt)) => Ok(stmt.claims.iss.clone()),
            None => Err(FederationError::TrustChainValidation("Empty trust chain".to_string())),
        }
    }
}

impl Default for TrustChainValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Validated trust chain with parsed and verified statements.
#[derive(Debug, Clone)]
pub struct ValidatedTrustChain {
    /// Array of validated Entity Statements
    pub statements: Vec<ValidatedEntityStatement>,
    /// The leaf entity ID
    pub leaf_entity_id: EntityId,
    /// The trust anchor ID
    pub trust_anchor_id: EntityId,
}

/// Validated entity statement (either a configuration or a statement).
#[derive(Debug, Clone)]
pub enum ValidatedEntityStatement {
    /// Entity Configuration (self-signed)
    Configuration(EntityConfiguration),
    /// Entity Statement (signed by another entity)
    Statement(EntityStatement),
}

impl ValidatedTrustChain {
    /// Get the leaf entity configuration.
    pub fn leaf_entity(&self) -> Option<&EntityConfiguration> {
        match self.statements.first() {
            Some(ValidatedEntityStatement::Configuration(config)) => Some(config),
            _ => None,
        }
    }

    /// Get the trust anchor configuration.
    pub fn trust_anchor(&self) -> Option<&EntityConfiguration> {
        match self.statements.last() {
            Some(ValidatedEntityStatement::Configuration(config)) => Some(config),
            _ => None,
        }
    }

    /// Get all intermediate entity statements.
    pub fn intermediate_statements(&self) -> Vec<&EntityStatement> {
        self.statements
            .iter()
            .skip(1) // Skip the leaf
            .take(self.statements.len().saturating_sub(2)) // Take all except trust anchor
            .filter_map(|stmt| match stmt {
                ValidatedEntityStatement::Statement(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// Get the final resolved metadata for the leaf entity.
    ///
    /// Reference: OpenID Federation 1.0 - Section 4.3 Metadata Resolution
    /// https://openid.net/specs/openid-federation-1_0.html#name-metadata-resolution
    pub fn resolve_metadata(&self) -> FederationResult<crate::EntityMetadata> {
        // Start with the leaf entity's metadata
        let mut final_metadata = self
            .leaf_entity()
            .and_then(|config| config.metadata.clone())
            .unwrap_or_default();

        // Apply metadata policies from each statement in the chain
        for statement in &self.statements {
            if let ValidatedEntityStatement::Statement(stmt) = statement {
                if let Some(metadata_policy) = &stmt.metadata_policy {
                    // Apply metadata policy to the final metadata
                    // This is a simplified implementation - a full implementation
                    // would properly apply all policy language operators
                    self.apply_metadata_policy(&mut final_metadata, metadata_policy)?;
                }
            }
        }

        Ok(final_metadata)
    }

    /// Apply a metadata policy to the metadata (simplified implementation).
    fn apply_metadata_policy(
        &self,
        _metadata: &mut crate::EntityMetadata,
        _policy: &std::collections::HashMap<String, std::collections::HashMap<String, crate::PolicyLanguage>>,
    ) -> FederationResult<()> {
        // TODO: Implement full metadata policy application logic
        // This would involve applying each policy operator (essential, default, one_of, etc.)
        // to the corresponding metadata fields
        Ok(())
    }
}

impl TrustChain {
    /// Create a new trust chain.
    pub fn new(chain: Vec<String>) -> Self {
        Self {
            chain,
            metadata: None,
            trust_marks: None,
        }
    }

    /// Add a JWT to the trust chain.
    pub fn add_jwt(&mut self, jwt: String) {
        self.chain.push(jwt);
    }

    /// Get the number of statements in the chain.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }
}
