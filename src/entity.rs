//! Subordinate Statement and Entity Configuration structures.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use url::Url;

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
        self.validate_for_issuing()?;
        validate_entity_ids_for_signing(&self.claims)?;
        validate_federation_entity_for_signing(self.metadata.as_ref())?;
        self.jwks.validate()?;
        sign_federation_jwt(self, JwtArtifactType::EntityStatement, signer).await
    }

    /// Starts a [`SubordinateStatementBuilder`] for a statement that `issuer`, a Superior, issues
    /// about `subject`, one of its Immediate Subordinates. `jwks` are the subject's Federation
    /// Entity Keys as the Superior registered them, not the keys the subject publishes in its own
    /// Entity Configuration and not the Superior's own keys.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.1
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>)
    pub fn builder(issuer: EntityId, subject: EntityId, jwks: JwkSet) -> SubordinateStatementBuilder {
        SubordinateStatementBuilder {
            issuer,
            subject,
            jwks,
            issued_at: None,
            expiry: None,
            metadata: None,
            metadata_policy: None,
            metadata_policy_crit: None,
            constraints: None,
            source_endpoint: None,
            crit: None,
            extension_claims: HashMap::new(),
        }
    }

    /// The rules a producer of a Subordinate Statement follows, on top of
    /// [`SubordinateStatement::validate`]:
    ///
    /// - No extension claim takes a name this specification or RFC 7519 defines.
    /// - `crit` is not `[]`, has no duplicates, names no claim this specification or RFC 7519
    ///   defines, and names only extension claims present in the statement (Section 13.4).
    /// - `metadata_policy_crit` is not `[]`, has no duplicates and names none of the standard
    ///   policy operators (Sections 3.1.3 and 6.1.3.1).
    /// - `source_endpoint` is an `https` URL with a host and without a fragment (Sections 3.1.3
    ///   and 8.1).
    ///
    /// They are producer rules, so they run when the crate builds or signs a statement, not on
    /// statements fetched from other entities.
    fn validate_for_issuing(&self) -> FederationResult<()> {
        // An extension claim never takes a name the specification defines: `crit` or
        // `metadata_policy` among the extension claims would bypass the checks below.
        if let Some(name) = self
            .claims
            .additional
            .keys()
            .find(|name| SPECIFIED_ENTITY_STATEMENT_CLAIMS.contains(&name.as_str()))
        {
            return Err(FederationError::InvalidSubordinateStatement(format!(
                "extension claim {name:?} is a claim the specification defines"
            )));
        }

        if let Some(crit) = &self.crit {
            validate_claim_name_list("crit", crit)?;
            for name in crit {
                if SPECIFIED_ENTITY_STATEMENT_CLAIMS.contains(&name.as_str()) {
                    return Err(FederationError::InvalidSubordinateStatement(format!(
                        "crit must not name {name:?}, a claim the specification defines"
                    )));
                }
                if !self.claims.additional.contains_key(name) {
                    return Err(FederationError::InvalidSubordinateStatement(format!(
                        "crit names {name:?}, which is not a claim of the statement"
                    )));
                }
            }
        }

        if let Some(operators) = &self.metadata_policy_crit {
            validate_claim_name_list("metadata_policy_crit", operators)?;
            if let Some(operator) = operators
                .iter()
                .find(|operator| STANDARD_POLICY_OPERATORS.contains(&operator.as_str()))
            {
                return Err(FederationError::InvalidSubordinateStatement(format!(
                    "metadata_policy_crit must not name {operator:?}, a standard policy operator"
                )));
            }
        }

        if let Some(source_endpoint) = &self.source_endpoint {
            Url::parse(source_endpoint)
                .map_err(|err| err.to_string())
                .and_then(|url| UrlValidator::validate_endpoint_url(&url).map_err(|err| err.to_string()))
                .map_err(|err| {
                    FederationError::InvalidSubordinateStatement(format!(
                        "source_endpoint {source_endpoint:?} is not a valid endpoint URL: {err}"
                    ))
                })?;
        }

        Ok(())
    }
}

/// The claim names this specification (Section 3.1) and RFC 7519 (Section 4.1) define for Entity
/// Statements. A producer never lists them in `crit` (Section 13.4).
const SPECIFIED_ENTITY_STATEMENT_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "jwks",
    "metadata",
    "crit",
    "authority_hints",
    "trust_anchor_hints",
    "trust_marks",
    "trust_mark_issuers",
    "trust_mark_owners",
    "constraints",
    "metadata_policy",
    "metadata_policy_crit",
    "source_endpoint",
    "trust_anchor",
];

/// The standard metadata policy operators (Section 6.1.3.1). `metadata_policy_crit` lists only
/// operators other than these.
const STANDARD_POLICY_OPERATORS: &[&str] = &[
    "value",
    "add",
    "default",
    "one_of",
    "subset_of",
    "superset_of",
    "essential",
];

/// `crit` and `metadata_policy_crit` are never the empty array and never list a name twice.
fn validate_claim_name_list(claim: &str, names: &[String]) -> FederationResult<()> {
    if names.is_empty() {
        return Err(FederationError::InvalidSubordinateStatement(format!(
            "{claim} must not be the empty array"
        )));
    }
    let mut seen = HashSet::new();
    if let Some(duplicate) = names.iter().find(|name| !seen.insert(name.as_str())) {
        return Err(FederationError::InvalidSubordinateStatement(format!(
            "{claim} lists {duplicate:?} more than once"
        )));
    }
    Ok(())
}

/// When a statement built with [`SubordinateStatementBuilder`] expires.
#[derive(Debug, Clone, Copy)]
enum Expiry {
    At(i64),
    After(Duration),
}

/// Builds a [`SubordinateStatement`] from what a Superior registered about one of its Immediate
/// Subordinates. Start one with [`SubordinateStatement::builder`].
///
/// Everything in the statement comes from the Superior: `iss` is the Superior, `jwks` are the
/// subject's keys as the Superior registered them, `iat` and `exp` are the Superior's choice, and
/// `metadata` holds only the values the Superior overrides. Nothing is copied from the subject's
/// Entity Configuration.
///
/// ```
/// use chrono::Duration;
/// use openid_federation::{EntityId, Jwk, JwkSet, SubordinateStatement};
///
/// let mut key: Jwk = serde_json::from_value(serde_json::json!({
///     "kty": "EC",
///     "crv": "P-256",
///     "kid": "op-key",
///     "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
///     "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
/// }))
/// .unwrap();
/// key.use_ = Some("sig".to_string());
/// let mut jwks = JwkSet::new();
/// jwks.add_key(key);
///
/// let statement = SubordinateStatement::builder(
///     EntityId::parse("https://ta.example.org").unwrap(),
///     EntityId::parse("https://op.example.org").unwrap(),
///     jwks,
/// )
/// .lifetime(Duration::days(1))
/// .build()
/// .unwrap();
/// assert_eq!(statement.claims.exp - statement.claims.iat, 86_400);
/// ```
///
/// Reference: OpenID Federation 1.0 - Sections 3.1.1 and 3.1.3
/// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>)
#[derive(Debug, Clone)]
#[must_use]
pub struct SubordinateStatementBuilder {
    issuer: EntityId,
    subject: EntityId,
    jwks: JwkSet,
    issued_at: Option<i64>,
    expiry: Option<Expiry>,
    metadata: Option<EntityMetadata>,
    metadata_policy: Option<HashMap<String, HashMap<String, PolicyOperators>>>,
    metadata_policy_crit: Option<Vec<String>>,
    constraints: Option<Constraints>,
    source_endpoint: Option<Url>,
    crit: Option<Vec<String>>,
    extension_claims: HashMap<String, serde_json::Value>,
}

impl SubordinateStatementBuilder {
    /// `iat`, in seconds since the Unix epoch. Without it, `iat` is the time of
    /// [`build`](Self::build).
    pub fn issued_at(mut self, iat: i64) -> Self {
        self.issued_at = Some(iat);
        self
    }

    /// `exp`, in seconds since the Unix epoch. Replaces an earlier [`lifetime`](Self::lifetime).
    pub fn expires_at(mut self, exp: i64) -> Self {
        self.expiry = Some(Expiry::At(exp));
        self
    }

    /// `exp` as `iat` plus `lifetime`. Replaces an earlier [`expires_at`](Self::expires_at).
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        self.expiry = Some(Expiry::After(lifetime));
        self
    }

    /// Metadata the Superior overrides for the subject. It applies only to the Entity Types the
    /// subject declares, and only to the subject (Section 3.1.3).
    pub fn metadata(mut self, metadata: EntityMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// The metadata policy for the subject and every Entity below it, keyed by Entity Type
    /// Identifier, then by metadata parameter (Section 6.1).
    pub fn metadata_policy(mut self, metadata_policy: HashMap<String, HashMap<String, PolicyOperators>>) -> Self {
        self.metadata_policy = Some(metadata_policy);
        self
    }

    /// Policy operators other than the standard ones that every verifier must understand
    /// (Section 3.1.3).
    pub fn metadata_policy_crit(mut self, operators: Vec<String>) -> Self {
        self.metadata_policy_crit = Some(operators);
        self
    }

    /// Constraints on the Trust Chains through the subject (Section 6.2).
    pub fn constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// The fetch endpoint the statement is issued from (Sections 3.1.3 and 8.1).
    pub fn source_endpoint(mut self, source_endpoint: Url) -> Self {
        self.source_endpoint = Some(source_endpoint);
        self
    }

    /// An extension claim, one this specification does not define: [`build`](Self::build)
    /// rejects a name the specification or RFC 7519 defines, such as `crit`. Name the claim in
    /// [`crit`](Self::crit) if verifiers must understand it.
    pub fn extension_claim(mut self, name: impl Into<String>, value: serde_json::Value) -> Self {
        self.extension_claims.insert(name.into(), value);
        self
    }

    /// Extension claims that every verifier must understand and process (Section 13.4). Each one
    /// is added with [`extension_claim`](Self::extension_claim).
    pub fn crit(mut self, claims: Vec<String>) -> Self {
        self.crit = Some(claims);
        self
    }

    /// Builds the statement and checks it: [`SubordinateStatement::validate`] (among others,
    /// `iss != sub` and an `exp` in the future), `exp` after `iat`, and the producer rules for
    /// `crit`, `metadata_policy_crit` and `source_endpoint` (Sections 3.1.3 and 13.4).
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidSubordinateStatement`] when no expiry was set or a check fails.
    pub fn build(self) -> FederationResult<SubordinateStatement> {
        let iat = self.issued_at.unwrap_or_else(|| Utc::now().timestamp());
        let exp = match self.expiry {
            Some(Expiry::At(exp)) => exp,
            Some(Expiry::After(lifetime)) => iat.saturating_add(lifetime.num_seconds()),
            None => {
                return Err(FederationError::InvalidSubordinateStatement(
                    "a Subordinate Statement needs an expiry: set expires_at or lifetime".to_string(),
                ))
            }
        };
        if exp <= iat {
            return Err(FederationError::InvalidSubordinateStatement(format!(
                "exp ({exp}) must be after iat ({iat})"
            )));
        }

        let mut statement = SubordinateStatement::new(self.issuer, self.subject, exp, iat, self.jwks);
        statement.claims.additional = self.extension_claims;
        statement.metadata = self.metadata;
        statement.metadata_policy = self.metadata_policy;
        statement.metadata_policy_crit = self.metadata_policy_crit;
        statement.constraints = self.constraints;
        statement.source_endpoint = self.source_endpoint.map(String::from);
        statement.crit = self.crit;

        statement.validate()?;
        statement.validate_for_issuing()?;
        Ok(statement)
    }
}

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

/// Checks `iss` and `sub` of a statement this crate is about to sign: each Entity Identifier uses
/// `https`, has a host and has no fragment. The check runs when signing only; statements fetched
/// from other entities are not held to it.
///
/// Reference: OpenID Federation 1.0 - Section 1.2 Terminology, Entity Identifier
/// (<https://openid.net/specs/openid-federation-1_0.html#section-1.2>)
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
    /// valid and trusted is a separate step. `authority_hints` and `trust_anchor_hints`, when
    /// present, must not be empty (Section 3.1.2).
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

        for (claim, hints) in [
            ("authority_hints", &self.authority_hints),
            ("trust_anchor_hints", &self.trust_anchor_hints),
        ] {
            if hints.as_ref().is_some_and(Vec::is_empty) {
                return Err(FederationError::InvalidSubordinateStatement(format!(
                    "Entity configuration {claim} must not be the empty array"
                )));
            }
        }

        for entry in self.trust_marks.iter().flatten() {
            entry.validate()?;
        }

        // TODO: Validate `crit` if present according to the specification.

        Ok(())
    }

    /// Checks the rules for the Entity Configuration of a Trust Anchor, on top of
    /// [`EntityConfiguration::validate`].
    ///
    /// - A Trust Anchor with no Superiors (`has_superiors == false`) publishes neither
    ///   `authority_hints` nor `trust_anchor_hints`. One that also acts as an Intermediate Entity
    ///   in another federation (Section 4.1) publishes `authority_hints` naming its Immediate
    ///   Superiors.
    /// - Its `federation_entity` metadata publishes `federation_fetch_endpoint` and
    ///   `federation_list_endpoint` (Sections 5.1.1, 8.1, 8.2).
    ///
    /// `trust_mark_issuers` and `trust_mark_owners` take effect only in a Trust Anchor's
    /// configuration (Section 3.1.2).
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.2
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.2>) and Section 5.1.1
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.1>)
    pub fn validate_as_trust_anchor(&self, has_superiors: bool) -> FederationResult<()> {
        self.validate()?;
        if has_superiors {
            self.require_authority_hints("a Trust Anchor with Superiors")?;
        } else {
            for (claim, hints) in [
                ("authority_hints", &self.authority_hints),
                ("trust_anchor_hints", &self.trust_anchor_hints),
            ] {
                if hints.is_some() {
                    return Err(FederationError::InvalidSubordinateStatement(format!(
                        "the Entity Configuration of a Trust Anchor with no Superiors must not contain {claim}"
                    )));
                }
            }
        }
        self.require_superior_endpoints("a Trust Anchor")
    }

    /// Checks the rules for the Entity Configuration of an Intermediate Entity, on top of
    /// [`EntityConfiguration::validate`]: it names its Immediate Superiors in `authority_hints`,
    /// and its `federation_entity` metadata publishes `federation_fetch_endpoint` and
    /// `federation_list_endpoint` (Sections 5.1.1, 8.1, 8.2).
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.2
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.2>) and Section 5.1.1
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.1>)
    pub fn validate_as_intermediate(&self) -> FederationResult<()> {
        self.validate()?;
        self.require_authority_hints("an Intermediate Entity")?;
        self.require_superior_endpoints("an Intermediate Entity")
    }

    fn require_authority_hints(&self, role: &str) -> FederationResult<()> {
        if self.authority_hints.is_none() {
            return Err(FederationError::InvalidSubordinateStatement(format!(
                "the Entity Configuration of {role} must name its Immediate Superiors in authority_hints"
            )));
        }
        Ok(())
    }

    fn require_superior_endpoints(&self, role: &str) -> FederationResult<()> {
        let federation_entity = self
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.federation_entity.as_ref());
        for (name, endpoint) in [
            (
                "federation_fetch_endpoint",
                federation_entity.and_then(|metadata| metadata.federation_fetch_endpoint.as_ref()),
            ),
            (
                "federation_list_endpoint",
                federation_entity.and_then(|metadata| metadata.federation_list_endpoint.as_ref()),
            ),
        ] {
            if endpoint.is_none() {
                return Err(FederationError::InvalidMetadata(format!(
                    "the federation_entity metadata of {role} must publish {name}"
                )));
            }
        }
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
    ///
    /// The result is not a correct Subordinate Statement whichever configuration it is called on:
    /// called on the subordinate's configuration, `iss`, `iat` and `exp` stay the subordinate's;
    /// called on the Superior's, `jwks` are the Superior's keys. It also copies `metadata` and
    /// `crit`, which are the subject's own values, not the Superior's overrides.
    #[deprecated(
        since = "0.4.0",
        note = "issue Subordinate Statements with `SubordinateStatement::builder` from what the Superior registered"
    )]
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
