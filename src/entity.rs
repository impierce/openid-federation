//! Entity Statement and Entity Configuration structures.

use crate::{
    AuthorityHints, Constraints, EntityId, EntityMetadata, FederationError, FederationResult, JwkSet, JwtClaims,
    PolicyLanguage, TrustMark,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Entity Statement as defined in the OpenID Federation specification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityStatement {
    /// Standard JWT claims
    #[serde(flatten)]
    pub claims: JwtClaims,
    /// JSON Web Key Set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<JwkSet>,
    /// Entity metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EntityMetadata>,
    /// Metadata policy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<HashMap<String, HashMap<String, PolicyLanguage>>>,
    /// Constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    /// Critical extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// Metadata policy critical
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_policy_crit: Option<Vec<String>>,
    /// Trust marks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_marks: Option<Vec<TrustMark>>,
    /// Authority hints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_hints: Option<AuthorityHints>,
    /// Source endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_endpoint: Option<String>,
}

/// Entity Configuration as defined in the OpenID Federation specification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityConfiguration {
    /// Standard JWT claims
    #[serde(flatten)]
    pub claims: JwtClaims,
    /// JSON Web Key Set
    pub jwks: JwkSet,
    /// Entity metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EntityMetadata>,
    /// Authority hints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_hints: Option<AuthorityHints>,
    /// Critical extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// Trust marks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_marks: Option<Vec<TrustMark>>,
}

impl EntityStatement {
    /// Create a new Entity Statement.
    pub fn new(issuer: EntityId, subject: EntityId, exp: DateTime<Utc>, iat: DateTime<Utc>) -> Self {
        let claims = JwtClaims {
            iss: issuer,
            sub: subject,
            aud: None,
            exp,
            nbf: None,
            iat,
            jti: None,
            additional: HashMap::new(),
        };

        Self {
            claims,
            jwks: None,
            metadata: None,
            metadata_policy: None,
            constraints: None,
            crit: None,
            metadata_policy_crit: None,
            trust_marks: None,
            authority_hints: None,
            source_endpoint: None,
        }
    }

    /// Set the JWK Set for this entity statement.
    pub fn with_jwks(mut self, jwks: JwkSet) -> Self {
        self.jwks = Some(jwks);
        self
    }

    /// Set the metadata for this entity statement.
    pub fn with_metadata(mut self, metadata: EntityMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the metadata policy for this entity statement.
    pub fn with_metadata_policy(mut self, metadata_policy: HashMap<String, HashMap<String, PolicyLanguage>>) -> Self {
        self.metadata_policy = Some(metadata_policy);
        self
    }

    /// Set the constraints for this entity statement.
    pub fn with_constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// Set the trust marks for this entity statement.
    pub fn with_trust_marks(mut self, trust_marks: Vec<TrustMark>) -> Self {
        self.trust_marks = Some(trust_marks);
        self
    }

    /// Set the authority hints for this entity statement.
    pub fn with_authority_hints(mut self, authority_hints: AuthorityHints) -> Self {
        self.authority_hints = Some(authority_hints);
        self
    }

    /// Validate the entity statement structure.
    pub fn validate(&self) -> FederationResult<()> {
        // Basic validation
        if self.claims.iss == self.claims.sub {
            // Self-signed entity configuration
            if self.jwks.is_none() {
                return Err(FederationError::InvalidEntityStatement(
                    "Self-signed entity statement must contain jwks".to_string(),
                ));
            }
        }

        // Check expiration
        if self.claims.exp < Utc::now() {
            return Err(FederationError::InvalidEntityStatement(
                "Entity statement has expired".to_string(),
            ));
        }

        // Check not before if present
        if let Some(nbf) = self.claims.nbf {
            if nbf > Utc::now() {
                return Err(FederationError::InvalidEntityStatement(
                    "Entity statement is not yet valid".to_string(),
                ));
            }
        }

        // Validate critical extensions
        if let Some(crit) = &self.crit {
            for critical_claim in crit {
                // Check if we understand this critical claim
                match critical_claim.as_str() {
                    "metadata_policy" => {
                        if self.metadata_policy.is_none() {
                            return Err(FederationError::InvalidEntityStatement(
                                "Critical metadata_policy claim missing".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(FederationError::InvalidEntityStatement(format!(
                            "Unknown critical claim: {}",
                            critical_claim
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if this is a self-signed entity configuration.
    pub fn is_self_signed(&self) -> bool {
        self.claims.iss == self.claims.sub
    }
}

impl EntityConfiguration {
    /// Create a new Entity Configuration.
    pub fn new(entity_id: EntityId, jwks: JwkSet, exp: DateTime<Utc>, iat: DateTime<Utc>) -> Self {
        let claims = JwtClaims {
            iss: entity_id.clone(),
            sub: entity_id,
            aud: None,
            exp,
            nbf: None,
            iat,
            jti: None,
            additional: HashMap::new(),
        };

        Self {
            claims,
            jwks,
            metadata: None,
            authority_hints: None,
            crit: None,
            trust_marks: None,
        }
    }

    /// Set the metadata for this entity configuration.
    pub fn with_metadata(mut self, metadata: EntityMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the authority hints for this entity configuration.
    pub fn with_authority_hints(mut self, authority_hints: AuthorityHints) -> Self {
        self.authority_hints = Some(authority_hints);
        self
    }

    /// Set the trust marks for this entity configuration.
    pub fn with_trust_marks(mut self, trust_marks: Vec<TrustMark>) -> Self {
        self.trust_marks = Some(trust_marks);
        self
    }

    /// Validate the entity configuration structure.
    pub fn validate(&self) -> FederationResult<()> {
        // Entity configuration must be self-signed
        if self.claims.iss != self.claims.sub {
            return Err(FederationError::InvalidEntityStatement(
                "Entity configuration must be self-signed (iss == sub)".to_string(),
            ));
        }

        // Must have jwks
        if self.jwks.keys.is_empty() {
            return Err(FederationError::InvalidEntityStatement(
                "Entity configuration must contain at least one key in jwks".to_string(),
            ));
        }

        // Check expiration
        if self.claims.exp < Utc::now() {
            return Err(FederationError::InvalidEntityStatement(
                "Entity configuration has expired".to_string(),
            ));
        }

        // Check not before if present
        if let Some(nbf) = self.claims.nbf {
            if nbf > Utc::now() {
                return Err(FederationError::InvalidEntityStatement(
                    "Entity configuration is not yet valid".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Check if this is a self-signed entity configuration.
    pub fn is_self_signed(&self) -> bool {
        self.claims.iss == self.claims.sub
    }

    /// Convert this entity configuration to an entity statement.
    pub fn to_entity_statement(&self) -> EntityStatement {
        EntityStatement {
            claims: self.claims.clone(),
            jwks: Some(self.jwks.clone()),
            metadata: self.metadata.clone(),
            metadata_policy: None,
            constraints: None,
            crit: self.crit.clone(),
            metadata_policy_crit: None,
            trust_marks: self.trust_marks.clone(),
            authority_hints: self.authority_hints.clone(),
            source_endpoint: None,
        }
    }
}
