//! Subordinate Statement and Entity Configuration structures.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    Constraints, EntityId, EntityMetadata, FederationError, FederationResult, JwkSet, JwtClaims, PolicyOperators,
    TrustMark, TrustMarkIssuers, TrustMarkOwners,
};

/// Subordinate Statement as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 3.1 Subordinate Statement
/// https://openid.net/specs/openid-federation-1_0.html#name-entity-statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubordinateStatement {
    #[serde(flatten)]
    pub claims: JwtClaims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    pub jwks: JwkSet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EntityMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<HashMap<String, HashMap<String, PolicyOperators>>>,
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

    pub fn with_jwks(mut self, jwks: JwkSet) -> Self {
        self.jwks = jwks;
        self
    }

    pub fn with_metadata(mut self, metadata: EntityMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn with_metadata_policy(mut self, metadata_policy: HashMap<String, HashMap<String, PolicyOperators>>) -> Self {
        self.metadata_policy = Some(metadata_policy);
        self
    }

    pub fn with_constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    // TODO: validate JWT here as well, not only contents. This should check the exp and nbf claims already.
    /// Validate the subordinate statement structure, this does not validate the JWT and its signature.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.1 Subordinate Statement Validation
    /// https://openid.net/specs/openid-federation-1_0.html#name-entity-statement-validation
    pub fn validate(&self) -> FederationResult<()> {
        if self.claims.iss == self.claims.sub {
            return Err(FederationError::InvalidSubordinateStatement(
                "Subordinate Statements cannot be self-signed".to_string(),
            ));
        }

        if self.claims.exp < Utc::now().timestamp() {
            return Err(FederationError::InvalidSubordinateStatement(
                "Subordinate statement has expired".to_string(),
            ));
        }

        if self.jwks.keys.is_empty() {
            return Err(FederationError::InvalidSubordinateStatement(
                "Subordinate statement must contain at least one key in jwks".to_string(),
            ));
        }

        if let Some(nbf) = self.claims.nbf {
            if nbf > Utc::now().timestamp() {
                return Err(FederationError::InvalidSubordinateStatement(
                    "Subordinate statement is not yet valid".to_string(),
                ));
            }
        }

        // TODO: Validate, if present, `constraints`, `crit`, `metadata_policy`, and `metadata_policy_crit` according to the specification.

        Ok(())
    }
}

impl EntityConfiguration {
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

    pub fn with_metadata(mut self, metadata: EntityMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn with_authority_hints(mut self, authority_hints: Vec<EntityId>) -> Self {
        self.authority_hints = Some(authority_hints);
        self
    }

    pub fn with_trust_anchor_hints(mut self, trust_anchor_hints: Vec<EntityId>) -> Self {
        self.trust_anchor_hints = Some(trust_anchor_hints);
        self
    }

    pub fn with_trust_marks(mut self, trust_marks: Vec<TrustMark>) -> Self {
        self.trust_marks = Some(trust_marks);
        self
    }

    pub fn with_trust_mark_issuers(mut self, trust_mark_issuers: TrustMarkIssuers) -> Self {
        self.trust_mark_issuers = Some(trust_mark_issuers);
        self
    }

    pub fn with_trust_mark_owners(mut self, trust_mark_owners: TrustMarkOwners) -> Self {
        self.trust_mark_owners = Some(trust_mark_owners);
        self
    }

    // TODO: validate JWT here as well, not only contents. This should check the exp and nbf claims already.
    /// Validate the entity configuration structure, this does not validate the JWT and its signature.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.2.1 Entity Configuration Validation
    /// https://openid.net/specs/openid-federation-1_0.html#name-entity-configuration-valida
    pub fn validate(&self) -> FederationResult<()> {
        if self.claims.iss != self.claims.sub {
            return Err(FederationError::InvalidSubordinateStatement(
                "Entity configuration must be self-signed (iss == sub)".to_string(),
            ));
        }

        if self.jwks.keys.is_empty() {
            return Err(FederationError::InvalidSubordinateStatement(
                "Entity configuration must contain at least one key in jwks".to_string(),
            ));
        }

        if self.claims.exp < Utc::now().timestamp() {
            return Err(FederationError::InvalidSubordinateStatement(
                "Entity configuration has expired".to_string(),
            ));
        }

        if let Some(nbf) = self.claims.nbf {
            if nbf > Utc::now().timestamp() {
                return Err(FederationError::InvalidSubordinateStatement(
                    "Entity configuration is not yet valid".to_string(),
                ));
            }
        }

        // TODO: Validate `crit` if present according to the specification.

        Ok(())
    }

    /// Convert this entity configuration to an subordinate statement. All new fields in the subordinate statement will be set to None.
    pub fn to_subordinate_statement(&self, sub: EntityId) -> SubordinateStatement {
        SubordinateStatement {
            claims: {
                let mut claims = self.claims.clone();
                claims.sub = sub;
                claims
            },
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
