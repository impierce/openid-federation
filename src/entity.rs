//! Entity Statement and Entity Configuration structures.

use crate::{
    Constraints, EntityId, EntityMetadata, FederationError, FederationResult, JwkSet, JwtClaims, PolicyLanguage,
    TrustMark, TrustMarkIssuers, TrustMarkOwners,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Entity Statement as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 3.1 Entity Statement
/// https://openid.net/specs/openid-federation-1_0.html#name-entity-statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubordinateStatement {
    #[serde(flatten)]
    pub claims: JwtClaims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    /// Critical extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    pub jwks: JwkSet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EntityMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<HashMap<String, HashMap<String, PolicyLanguage>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_policy_crit: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_endpoint: Option<String>,
}

/// Entity Configuration as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 3.2 Entity Configuration
/// https://openid.net/specs/openid-federation-1_0.html#name-entity-configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityConfiguration {
    // Required if the entity is not the trust anchor, but a leaf or intermediate entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_hints: Option<Vec<EntityId>>,
    #[serde(flatten)]
    pub claims: JwtClaims,
    /// Critical extensions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    pub jwks: JwkSet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EntityMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_anchor_hints: Option<Vec<EntityId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_marks: Option<Vec<TrustMark>>,
    // Only allowed if the entity is a trust anchor, otherwise IGNORE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_mark_issuers: Option<TrustMarkIssuers>,
    // Only allowed if the entity is a trust anchor, otherwise IGNORE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_mark_owners: Option<TrustMarkOwners>,
}

impl SubordinateStatement {
    /// Create a new Entity Statement.
    pub fn new(issuer: EntityId, subject: EntityId, exp: i64, iat: i64, jwks: JwkSet) -> Self {
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
            jwks,
            metadata: None,
            metadata_policy: None,
            constraints: None,
            crit: None,
            metadata_policy_crit: None,
            source_endpoint: None,
        }
    }

    /// Set the JWK Set for this entity statement.
    pub fn with_jwks(mut self, jwks: JwkSet) -> Self {
        self.jwks = jwks;
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

    /// Validate the entity statement structure.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.1 Entity Statement Validation
    /// https://openid.net/specs/openid-federation-1_0.html#name-entity-statement-validation
    pub fn validate(&self) -> FederationResult<()> {
        if self.claims.iss == self.claims.sub {
            return Err(FederationError::InvalidSubordinateStatement(
                "Subordinate Statements cannot be self-signed".to_string(),
            ));
        }

        // Check expiration
        if self.claims.exp < Utc::now().timestamp() {
            return Err(FederationError::InvalidSubordinateStatement(
                "Entity statement has expired".to_string(),
            ));
        }

        // Check not before if present
        if let Some(nbf) = self.claims.nbf {
            if nbf > Utc::now().timestamp() {
                return Err(FederationError::InvalidSubordinateStatement(
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
                            return Err(FederationError::InvalidSubordinateStatement(
                                "Critical metadata_policy claim missing".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(FederationError::InvalidSubordinateStatement(format!(
                            "Unknown critical claim: {}",
                            critical_claim
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

impl EntityConfiguration {
    /// Create a new Entity Configuration.
    pub fn new(entity_id: EntityId, jwks: JwkSet, exp: i64, iat: i64) -> Self {
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
            trust_anchor_hints: None,
            trust_marks: None,
            trust_mark_issuers: None,
            trust_mark_owners: None,
        }
    }

    /// Set the metadata for this entity configuration.
    pub fn with_metadata(mut self, metadata: EntityMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the authority hints for this entity configuration.
    pub fn with_authority_hints(mut self, authority_hints: Vec<EntityId>) -> Self {
        self.authority_hints = Some(authority_hints);
        self
    }

    /// Set the trust anchor hints for this entity configuration.
    pub fn with_trust_anchor_hints(mut self, trust_anchor_hints: Vec<EntityId>) -> Self {
        self.trust_anchor_hints = Some(trust_anchor_hints);
        self
    }

    /// Set the trust marks for this entity configuration.
    pub fn with_trust_marks(mut self, trust_marks: Vec<TrustMark>) -> Self {
        self.trust_marks = Some(trust_marks);
        self
    }

    /// Set the trust mark issuers for this entity configuration.
    pub fn with_trust_mark_issuers(mut self, trust_mark_issuers: TrustMarkIssuers) -> Self {
        self.trust_mark_issuers = Some(trust_mark_issuers);
        self
    }

    /// Set the trust mark owners for this entity configuration.
    pub fn with_trust_mark_owners(mut self, trust_mark_owners: TrustMarkOwners) -> Self {
        self.trust_mark_owners = Some(trust_mark_owners);
        self
    }

    /// Validate the entity configuration structure.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.2.1 Entity Configuration Validation
    /// https://openid.net/specs/openid-federation-1_0.html#name-entity-configuration-valida
    pub fn validate(&self) -> FederationResult<()> {
        // Entity configuration must be self-signed
        if self.claims.iss != self.claims.sub {
            return Err(FederationError::InvalidSubordinateStatement(
                "Entity configuration must be self-signed (iss == sub)".to_string(),
            ));
        }

        // Must have jwks
        if self.jwks.keys.is_empty() {
            return Err(FederationError::InvalidSubordinateStatement(
                "Entity configuration must contain at least one key in jwks".to_string(),
            ));
        }

        // Check expiration
        if self.claims.exp < Utc::now().timestamp() {
            return Err(FederationError::InvalidSubordinateStatement(
                "Entity configuration has expired".to_string(),
            ));
        }

        // Check not before if present
        if let Some(nbf) = self.claims.nbf {
            if nbf > Utc::now().timestamp() {
                return Err(FederationError::InvalidSubordinateStatement(
                    "Entity configuration is not yet valid".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Convert this entity configuration to an entity statement.
    pub fn to_subordinate_statement(&self) -> SubordinateStatement {
        SubordinateStatement {
            claims: self.claims.clone(),
            constraints: None,
            crit: self.crit.clone(),
            jwks: self.jwks.clone(),
            metadata: self.metadata.clone(),
            metadata_policy: None,
            metadata_policy_crit: None,
            source_endpoint: None,
        }
    }
}
