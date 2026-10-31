//! Subordinate Statement and Entity Configuration structures.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    extract_claims_unverified, sign_federation_jwt, Constraints, EntityId, EntityMetadata, FederationError,
    FederationResult, JwkSet, JwtArtifactType, JwtClaims, JwtProcessor, PolicyOperators, Signer, TrustMarkEntry,
    TrustMarkIssuers, TrustMarkOwners, UrlValidator,
};

/// Subordinate Statement as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 3.1 Subordinate Statement
/// <https://openid.net/specs/openid-federation-1_0.html#name-entity-statement>
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
/// <https://openid.net/specs/openid-federation-1_0.html#name-entity-configuration>
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
    pub trust_marks: Option<Vec<TrustMarkEntry>>,
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

    /// Decode and authenticate a Subordinate Statement JWT.
    ///
    /// This is the only way to turn an untrusted JWT string into a `SubordinateStatement` that is
    /// known to have been issued by `issuer` about `subject`. It checks, in order:
    /// 1. the structural requirements of [`SubordinateStatement::validate`],
    /// 2. that the claimed `iss` and `sub` are exactly the expected entities,
    /// 3. that the JWT carries the `entity-statement+jwt` type and is signed with one of
    ///    `issuer_keys`, which MUST be keys already authenticated for `issuer` (for example the
    ///    `jwks` of the Subordinate Statement about `issuer`, or the Trust Anchor's keys).
    ///
    /// Reference: OpenID Federation 1.0 - Section 10.2 Validating a Trust Chain
    /// <https://openid.net/specs/openid-federation-1_0.html#name-validating-a-trust-chain>
    pub fn from_verified_jwt(
        jwt: &str,
        issuer: &EntityId,
        subject: &EntityId,
        issuer_keys: &JwkSet,
    ) -> FederationResult<Self> {
        let unverified: Self = extract_claims_unverified(jwt)?;
        unverified.validate()?;

        if unverified.claims.iss != *issuer {
            return Err(FederationError::InvalidSubordinateStatement(format!(
                "Subordinate statement issuer mismatch: expected {}, got {}",
                issuer, unverified.claims.iss
            )));
        }

        if unverified.claims.sub != *subject {
            return Err(FederationError::InvalidSubordinateStatement(format!(
                "Subordinate statement subject mismatch: expected {}, got {}",
                subject, unverified.claims.sub
            )));
        }

        JwtProcessor::new()
            .verify_jwt_with_jwks(jwt, issuer_keys, JwtArtifactType::EntityStatement)
            .map_err(|err| {
                FederationError::InvalidSubordinateStatement(format!(
                    "Subordinate statement issued by {} about {} is not signed with an authenticated key of the issuer: {}",
                    issuer, subject, err
                ))
            })
    }

    // TODO: validate JWT here as well, not only contents. This should check the exp and nbf claims already.
    /// Validate the subordinate statement structure, this does not validate the JWT and its signature.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.1 Subordinate Statement Validation
    /// <https://openid.net/specs/openid-federation-1_0.html#name-entity-statement-validation>
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

impl SubordinateStatement {
    /// Signs this statement with `signer`, a key of the issuer (`iss`), as an
    /// `entity-statement+jwt` that names the key in `kid`.
    ///
    /// The statement is checked before the signer is called: [`SubordinateStatement::validate`],
    /// `iss` and `sub` as `https` Entity Identifiers without a fragment, the endpoints of any
    /// `federation_entity` metadata with
    /// [`FederationEntityMetadata::validate`](crate::FederationEntityMetadata::validate), and
    /// [`JwkSet::validate`] on `jwks`, so the subject's keys are published only as public keys
    /// with unique `kid`s. Whether the signer's key is one the issuer publishes cannot be checked
    /// here; verifiers check it against the issuer's authenticated keys.
    ///
    /// # Errors
    ///
    /// The errors of the two checks above, and of [`sign_federation_jwt`].
    ///
    /// Reference: OpenID Federation 1.0 - Section 3 Entity Statement
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3>) and Section 3.1.1
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>)
    pub async fn sign(&self, signer: &dyn Signer) -> FederationResult<String> {
        self.validate()?;
        validate_entity_ids_for_signing(&self.claims)?;
        validate_federation_entity_for_signing(self.metadata.as_ref())?;
        self.jwks.validate()?;
        sign_federation_jwt(self, JwtArtifactType::EntityStatement, signer).await
    }
}

/// Checks `iss` and `sub` of a statement this crate is about to sign: each Entity Identifier uses
/// `https`, has a host and has no fragment. The check runs when signing only; statements fetched
/// from other entities are not held to it.
///
/// Reference: OpenID Federation 1.0 - Section 1.2 Terminology, Entity Identifier
/// (<https://openid.net/specs/openid-federation-1_0.html#section-1.2>)
/// Checks the `federation_entity` metadata of a statement this crate is about to sign with
/// [`FederationEntityMetadata::validate`](crate::FederationEntityMetadata::validate): `https`
/// federation endpoints without a fragment, and no `none` in
/// `endpoint_auth_signing_alg_values_supported`. Like the Entity Identifier check, it runs when
/// signing only.
///
/// Reference: OpenID Federation 1.0 - Section 5.1.1 Federation Entity
/// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.1>)
fn validate_federation_entity_for_signing(metadata: Option<&EntityMetadata>) -> FederationResult<()> {
    match metadata.and_then(|metadata| metadata.federation_entity.as_ref()) {
        Some(federation_entity) => federation_entity.validate(),
        None => Ok(()),
    }
}

fn validate_entity_ids_for_signing(claims: &JwtClaims) -> FederationResult<()> {
    for (claim, entity_id) in [("iss", &claims.iss), ("sub", &claims.sub)] {
        validate_entity_id_for_signing(claim, entity_id)?;
    }
    Ok(())
}

fn validate_entity_id_for_signing(claim: &str, entity_id: &EntityId) -> FederationResult<()> {
    UrlValidator::validate_entity_id(entity_id.as_url())
        .map_err(|err| FederationError::Configuration(format!("{claim} {entity_id}: {err}")))
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

    /// Set the Trust Marks the entity holds, each as its type next to the signed Trust Mark JWT.
    pub fn with_trust_marks(mut self, trust_marks: Vec<TrustMarkEntry>) -> Self {
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

    /// Decode and authenticate a self-signed Entity Configuration JWT published by `entity_id`.
    ///
    /// This is the only way to turn an untrusted JWT string (typically fetched from the entity's
    /// `.well-known/openid-federation` endpoint) into an `EntityConfiguration` that is known to be
    /// the configuration *of that entity*. It checks, in order:
    /// 1. the structural requirements of [`EntityConfiguration::validate`],
    /// 2. that both `iss` and `sub` are exactly `entity_id`, so a document served by one entity
    ///    cannot claim another entity's identity,
    /// 3. that the JWT carries the `entity-statement+jwt` type and is signed with a key from its
    ///    own `jwks` (self-signed).
    ///
    /// Note that a valid self-signature only proves that the publisher controls the keys it
    /// advertises. Whether those keys are endorsed by a federation is established by
    /// [`crate::TrustChain::try_new`], which checks them against the Subordinate Statement issued
    /// by the entity's superior.
    ///
    /// Reference: OpenID Federation 1.0 - Section 9 Obtaining Federation Entity Configuration Information
    /// <https://openid.net/specs/openid-federation-1_0.html#name-obtaining-federation-entity->
    pub fn from_verified_jwt(jwt: &str, entity_id: &EntityId) -> FederationResult<Self> {
        let unverified: Self = extract_claims_unverified(jwt)?;
        unverified.validate()?;

        if unverified.claims.iss != *entity_id || unverified.claims.sub != *entity_id {
            return Err(FederationError::InvalidSubordinateStatement(format!(
                "Entity configuration identity mismatch: expected {}, got iss={} sub={}",
                entity_id, unverified.claims.iss, unverified.claims.sub
            )));
        }

        JwtProcessor::new()
            .verify_jwt_with_jwks(jwt, &unverified.jwks, JwtArtifactType::EntityStatement)
            .map_err(|err| {
                FederationError::InvalidSubordinateStatement(format!(
                    "Entity configuration of {} is not signed with a key from its own jwks: {}",
                    entity_id, err
                ))
            })
    }

    // TODO: validate JWT here as well, not only contents. This should check the exp and nbf claims already.
    /// Validate the entity configuration structure, this does not validate the JWT and its signature.
    ///
    /// Each `trust_marks` entry is checked with [`TrustMarkEntry::validate`]: its type must equal
    /// the `trust_mark_type` claim of its Trust Mark JWT. Whether the Trust Marks themselves are
    /// valid and trusted is a separate step.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.2.1 Entity Configuration Validation
    /// <https://openid.net/specs/openid-federation-1_0.html#name-entity-configuration-valida>
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

        for entry in self.trust_marks.iter().flatten() {
            entry.validate()?;
        }

        // TODO: Validate `crit` if present according to the specification.

        Ok(())
    }

    /// Signs this Entity Configuration with `signer`, one of the entity's own keys, as an
    /// `entity-statement+jwt` that names the key in `kid`.
    ///
    /// Before the signer is called, the configuration must pass [`EntityConfiguration::validate`]
    /// and [`JwkSet::validate`], its Entity Identifier and every Entity Identifier in
    /// `authority_hints` and `trust_anchor_hints` must use `https` and have no fragment, its
    /// `federation_entity` metadata must pass
    /// [`FederationEntityMetadata::validate`](crate::FederationEntityMetadata::validate), and the
    /// signer's `kid` must name a key in the configuration's own `jwks`, since verifiers check
    /// the self-signature against them. After signing, the result is
    /// verified the way a verifier does it, with [`EntityConfiguration::from_verified_jwt`], so a
    /// signer whose key is not the published key under that `kid` fails here rather than producing
    /// a configuration nobody can verify.
    ///
    /// # Errors
    ///
    /// The errors of the checks above, [`FederationError::Configuration`] for a `kid` that is not
    /// in `jwks`, and the errors of [`sign_federation_jwt`].
    ///
    /// Reference: OpenID Federation 1.0 - Section 3 Entity Statement
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3>) and Section 3.2.1
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.2.1>)
    pub async fn sign(&self, signer: &dyn Signer) -> FederationResult<String> {
        self.validate()?;
        validate_entity_ids_for_signing(&self.claims)?;
        for (claim, hints) in [
            ("authority_hints", &self.authority_hints),
            ("trust_anchor_hints", &self.trust_anchor_hints),
        ] {
            for entity_id in hints.iter().flatten() {
                validate_entity_id_for_signing(claim, entity_id)?;
            }
        }
        validate_federation_entity_for_signing(self.metadata.as_ref())?;
        self.jwks.validate()?;
        if !self
            .jwks
            .keys
            .iter()
            .any(|key| key.kid.as_deref() == Some(signer.kid()))
        {
            return Err(FederationError::Configuration(format!(
                "the signer's kid {:?} is not a key in the Entity Configuration's own jwks",
                signer.kid()
            )));
        }
        let jwt = sign_federation_jwt(self, JwtArtifactType::EntityStatement, signer).await?;
        EntityConfiguration::from_verified_jwt(&jwt, &self.claims.sub).map_err(|err| {
            FederationError::Configuration(format!(
                "the Entity Configuration signed with {:?} does not verify against its own jwks: {err}",
                signer.kid()
            ))
        })?;
        Ok(jwt)
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
