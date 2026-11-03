//! What the issuing side reads from the application's storage: the Immediate Subordinates a
//! Trust Anchor or Intermediate Entity registered, and the Trust Marks a Trust Mark Issuer issued,
//! each behind an async trait with an in-memory implementation (ADR 0005).

use crate::jwt::CLOCK_SKEW_LEEWAY;
use crate::{
    extract_claims_unverified, Constraints, EntityId, EntityMetadata, EntityType, FederationError, FederationResult,
    JwkSet, JwtArtifactType, PolicyOperators, StoreError, SubordinateStatement, SubordinateStatementBuilder, TrustMark,
    TrustMarkStatus,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

/// An Immediate Subordinate as its Superior registered it: what the Superior states about it in
/// a Subordinate Statement, and what the subordinate listing endpoint filters on.
///
/// Reference: OpenID Federation 1.0 - Section 3.1.3 Claims that MUST or MAY Appear in Subordinate
/// Statements (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.3>) and Section
/// 8.2.1 Subordinate Listing Request
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2.1>)
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Subordinate {
    /// The subordinate's Entity Identifier, spelled as the subordinate publishes it.
    pub entity_id: EntityId,
    /// The subordinate's Federation Entity Keys, which the Superior vouches for.
    pub jwks: JwkSet,
    /// The Entity Types the subordinate publishes metadata for.
    pub entity_types: Vec<EntityType>,
    /// Whether the subordinate is an Intermediate Entity, with Subordinates of its own.
    pub intermediate: bool,
    /// Metadata the Superior states about the subordinate, which overrides the subordinate's own.
    pub metadata: Option<EntityMetadata>,
    /// The metadata policy the Superior applies to the subordinate and the entities below it.
    pub metadata_policy: Option<HashMap<String, HashMap<String, PolicyOperators>>>,
    /// The policy operators that are not standard and that the metadata policy depends on.
    pub metadata_policy_crit: Option<Vec<String>>,
    /// The constraints on Trust Chains through the subordinate.
    pub constraints: Option<Constraints>,
}

impl Subordinate {
    /// A subordinate with `entity_id` and its keys `jwks`, no Entity Types, not an Intermediate
    /// Entity, and nothing else stated about it.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.3
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.3>)
    pub fn new(entity_id: EntityId, jwks: JwkSet) -> Self {
        Self {
            entity_id,
            jwks,
            entity_types: Vec::new(),
            intermediate: false,
            metadata: None,
            metadata_policy: None,
            metadata_policy_crit: None,
            constraints: None,
        }
    }

    /// Sets the Entity Types the subordinate publishes metadata for.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2.1 Subordinate Listing Request
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2.1>)
    pub fn with_entity_types(mut self, entity_types: Vec<EntityType>) -> Self {
        self.entity_types = entity_types;
        self
    }

    /// Sets whether the subordinate is an Intermediate Entity.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2.1 Subordinate Listing Request
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2.1>)
    pub fn with_intermediate(mut self, intermediate: bool) -> Self {
        self.intermediate = intermediate;
        self
    }

    /// Sets the metadata the Superior states about the subordinate.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.3
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.3>)
    pub fn with_metadata(mut self, metadata: EntityMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Sets the metadata policy the Superior applies.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.1 Metadata Policy
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-6.1>)
    pub fn with_metadata_policy(mut self, metadata_policy: HashMap<String, HashMap<String, PolicyOperators>>) -> Self {
        self.metadata_policy = Some(metadata_policy);
        self
    }

    /// Sets the policy operators that are not standard and that the metadata policy depends on.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.3
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.3>)
    pub fn with_metadata_policy_crit(mut self, operators: Vec<String>) -> Self {
        self.metadata_policy_crit = Some(operators);
        self
    }

    /// Sets the constraints on Trust Chains through the subordinate.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2 Constraints
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-6.2>)
    pub fn with_constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = Some(constraints);
        self
    }

    /// A [`SubordinateStatement::builder`] that `issuer` uses to state what it registered about
    /// this subordinate. The caller sets the expiry, and anything else, before building.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.3
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.3>)
    pub fn subordinate_statement(&self, issuer: EntityId) -> SubordinateStatementBuilder {
        let mut builder = SubordinateStatement::builder(issuer, self.entity_id.clone(), self.jwks.clone());
        if let Some(metadata) = &self.metadata {
            builder = builder.metadata(metadata.clone());
        }
        if let Some(metadata_policy) = &self.metadata_policy {
            builder = builder.metadata_policy(metadata_policy.clone());
        }
        if let Some(operators) = &self.metadata_policy_crit {
            builder = builder.metadata_policy_crit(operators.clone());
        }
        if let Some(constraints) = &self.constraints {
            builder = builder.constraints(constraints.clone());
        }
        builder
    }
}

/// Where a Trust Anchor or Intermediate Entity keeps its registered Immediate Subordinates.
///
/// The application implements it on its own database; [`InMemorySubordinateStore`] serves tests,
/// examples and small deployments. Entity Identifiers are compared as URLs, as [`EntityId`]
/// compares them, so `https://op.example.org` and `https://op.example.org/` are the same
/// subordinate (ADR 0004).
///
/// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1>) and Section 8.2
/// Subordinate Listing (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
#[async_trait]
pub trait SubordinateStore: Send + Sync {
    /// The registered subordinate whose Entity Identifier is `entity_id`, or `None`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1>)
    async fn subordinate(&self, entity_id: &EntityId) -> Result<Option<Subordinate>, StoreError>;

    /// Every registered subordinate, in no particular order.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2 Subordinate Listing
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
    async fn subordinates(&self) -> Result<Vec<Subordinate>, StoreError>;
}

/// A [`SubordinateStore`] in memory, for tests, examples and small deployments.
///
/// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1>)
#[derive(Debug, Default)]
pub struct InMemorySubordinateStore {
    subordinates: RwLock<HashMap<EntityId, Subordinate>>,
}

impl InMemorySubordinateStore {
    /// An empty store.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1>) and Section 8.2
    /// Subordinate Listing (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `subordinate`, replacing and returning a subordinate with the same Entity
    /// Identifier, compared as a URL.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1>) and Section 8.2
    /// Subordinate Listing (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
    pub fn insert(&self, subordinate: Subordinate) -> Option<Subordinate> {
        let mut subordinates = self.subordinates.write().unwrap_or_else(PoisonError::into_inner);
        // `HashMap::insert` keeps the old key, so remove first: the new spelling is the one served.
        let replaced = subordinates.remove(&subordinate.entity_id);
        subordinates.insert(subordinate.entity_id.clone(), subordinate);
        replaced
    }

    /// Removes and returns the subordinate with `entity_id`, compared as a URL.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.1 Fetching a Subordinate Statement
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.1>) and Section 8.2
    /// Subordinate Listing (<https://openid.net/specs/openid-federation-1_0.html#section-8.2>)
    pub fn remove(&self, entity_id: &EntityId) -> Option<Subordinate> {
        self.subordinates
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(entity_id)
    }
}

#[async_trait]
impl SubordinateStore for InMemorySubordinateStore {
    async fn subordinate(&self, entity_id: &EntityId) -> Result<Option<Subordinate>, StoreError> {
        Ok(self
            .subordinates
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(entity_id)
            .cloned())
    }

    async fn subordinates(&self) -> Result<Vec<Subordinate>, StoreError> {
        Ok(self
            .subordinates
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect())
    }
}

/// A Trust Mark as its issuer recorded it: the signed JWT, its claims, and when it was revoked.
///
/// Reference: OpenID Federation 1.0 - Section 7 Trust Marks
/// (<https://openid.net/specs/openid-federation-1_0.html#section-7>) and Section 8.4 Trust Mark
/// Status (<https://openid.net/specs/openid-federation-1_0.html#section-8.4>)
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct IssuedTrustMark {
    /// The signed Trust Mark JWT, as it was handed to its subject.
    pub jwt: String,
    /// The claims of `jwt`.
    pub claims: TrustMark,
    /// When the issuer revoked the Trust Mark, in seconds since the Unix epoch, or `None`.
    pub revoked_at: Option<i64>,
}

impl IssuedTrustMark {
    /// Records `jwt`, a Trust Mark the issuer signed, for example with
    /// [`TrustMark::sign`](crate::TrustMark::sign), with its claims read from the JWT so the two
    /// cannot differ.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidTrustMark`] when `jwt` is not a JWT typed `trust-mark+jwt` with
    /// Trust Mark claims.
    ///
    /// Reference: OpenID Federation 1.0 - Section 7.1 Trust Mark Claims
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-7.1>)
    pub fn from_jwt(jwt: impl Into<String>) -> FederationResult<Self> {
        let jwt = jwt.into();
        let claims = trust_mark_claims(&jwt)?;
        Ok(Self {
            jwt,
            claims,
            revoked_at: None,
        })
    }

    /// The status of the Trust Mark at `now`: `revoked` once it was revoked, else `expired` from
    /// its `exp` on, else `invalid` while its `iat` is more than the clock skew leeway (60
    /// seconds) after `now`, as [`TrustMark::validate`] refuses it, else `active`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.4.2 Trust Mark Status Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4.2>)
    pub fn status_at(&self, now: i64) -> TrustMarkStatus {
        if self.revoked_at.is_some() {
            TrustMarkStatus::Revoked
        } else if self.claims.exp.is_some_and(|exp| exp <= now) {
            TrustMarkStatus::Expired
        } else if self.claims.iat > now.saturating_add(CLOCK_SKEW_LEEWAY) {
            // Not issued yet: a relying party refuses it until then, so it is not active.
            TrustMarkStatus::Invalid
        } else {
            TrustMarkStatus::Active
        }
    }
}

/// The claims of `jwt`, which must be typed `trust-mark+jwt`, read without verifying the
/// signature.
pub(crate) fn trust_mark_claims(jwt: &str) -> FederationResult<TrustMark> {
    let invalid = |reason: String| FederationError::InvalidTrustMark(format!("not a Trust Mark JWT: {reason}"));
    let header = jsonwebtoken::decode_header(jwt).map_err(|err| invalid(err.to_string()))?;
    JwtArtifactType::TrustMark
        .validate_header_typ(header.typ.as_deref())
        .map_err(|err| invalid(err.to_string()))?;
    extract_claims_unverified(jwt).map_err(|err| invalid(err.to_string()))
}

/// Where a Trust Mark Issuer keeps the Trust Marks it issued.
///
/// The application implements it on its own database; [`InMemoryTrustMarkStore`] serves tests,
/// examples and small deployments.
///
/// Reference: OpenID Federation 1.0 - Section 8.4 Trust Mark Status
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4>), Section 8.5 Trust Marked
/// Entities Listing (<https://openid.net/specs/openid-federation-1_0.html#section-8.5>) and
/// Section 8.6 Trust Mark Endpoint
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.6>)
#[async_trait]
pub trait TrustMarkStore: Send + Sync {
    /// The issued Trust Mark whose JWT is exactly `jwt`, or `None`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.4 Trust Mark Status
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4>)
    async fn trust_mark(&self, jwt: &str) -> Result<Option<IssuedTrustMark>, StoreError>;

    /// Every issued Trust Mark, only those of `trust_mark_type` when it is given and only those
    /// issued to `sub` when it is given, revoked and expired ones included, in no particular
    /// order. An implementation on a database answers it from an index on the type and the
    /// subject.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.2.1 Subordinate Listing Request
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.2.1>), Section 8.5 Trust
    /// Marked Entities Listing (<https://openid.net/specs/openid-federation-1_0.html#section-8.5>)
    /// and Section 8.6 Trust Mark Endpoint
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.6>)
    async fn trust_marks(
        &self,
        trust_mark_type: Option<&str>,
        sub: Option<&EntityId>,
    ) -> Result<Vec<IssuedTrustMark>, StoreError>;
}

/// A [`TrustMarkStore`] in memory, for tests, examples and small deployments.
///
/// Reference: OpenID Federation 1.0 - Section 8.4 Trust Mark Status
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4>)
#[derive(Debug, Default)]
pub struct InMemoryTrustMarkStore {
    trust_marks: RwLock<HashMap<String, IssuedTrustMark>>,
}

impl InMemoryTrustMarkStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `trust_mark`, replacing and returning the record of the same JWT.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.4 Trust Mark Status
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4>)
    pub fn insert(&self, trust_mark: IssuedTrustMark) -> Option<IssuedTrustMark> {
        self.trust_marks
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(trust_mark.jwt.clone(), trust_mark)
    }

    /// Marks the Trust Mark whose JWT is `jwt` as revoked at `revoked_at`, keeping an earlier
    /// revocation. Returns whether the store holds that Trust Mark.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.4.2 Trust Mark Status Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.4.2>)
    pub fn revoke(&self, jwt: &str, revoked_at: i64) -> bool {
        match self
            .trust_marks
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(jwt)
        {
            Some(trust_mark) => {
                trust_mark.revoked_at.get_or_insert(revoked_at);
                true
            }
            None => false,
        }
    }
}

#[async_trait]
impl TrustMarkStore for InMemoryTrustMarkStore {
    async fn trust_mark(&self, jwt: &str) -> Result<Option<IssuedTrustMark>, StoreError> {
        Ok(self
            .trust_marks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(jwt)
            .cloned())
    }

    async fn trust_marks(
        &self,
        trust_mark_type: Option<&str>,
        sub: Option<&EntityId>,
    ) -> Result<Vec<IssuedTrustMark>, StoreError> {
        Ok(self
            .trust_marks
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter(|trust_mark| {
                trust_mark_type.is_none_or(|trust_mark_type| trust_mark.claims.trust_mark_type == trust_mark_type)
                    && sub.is_none_or(|sub| trust_mark.claims.sub == *sub)
            })
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subordinate(id: &str) -> Subordinate {
        Subordinate::new(EntityId::parse(id).unwrap(), JwkSet::new())
    }

    #[tokio::test]
    async fn in_memory_store_finds_a_subordinate_however_its_identifier_is_spelled() {
        let store = InMemorySubordinateStore::new();
        assert_eq!(store.insert(subordinate("https://op.example.org")), None);

        for spelling in ["https://op.example.org", "https://op.example.org/"] {
            let found = store
                .subordinate(&EntityId::parse(spelling).unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.entity_id.as_str(), "https://op.example.org", "kept as registered");
        }
        assert_eq!(
            store
                .subordinate(&EntityId::parse("https://rp.example.org").unwrap())
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn in_memory_store_replaces_lists_and_removes() {
        let store = InMemorySubordinateStore::new();
        store.insert(subordinate("https://op.example.org"));
        store.insert(subordinate("https://rp.example.org"));

        let replaced = store.insert(subordinate("https://op.example.org/").with_intermediate(true));
        assert_eq!(replaced.unwrap().entity_id.as_str(), "https://op.example.org");
        let op = EntityId::parse("https://op.example.org").unwrap();
        let found = store.subordinate(&op).await.unwrap().unwrap();
        assert!(found.intermediate);
        assert_eq!(
            found.entity_id.as_str(),
            "https://op.example.org/",
            "the new spelling is served"
        );

        let mut listed: Vec<_> = store
            .subordinates()
            .await
            .unwrap()
            .into_iter()
            .map(|subordinate| subordinate.entity_id.to_string())
            .collect();
        listed.sort();
        assert_eq!(listed, ["https://op.example.org/", "https://rp.example.org"]);

        assert!(store.remove(&op).is_some());
        assert_eq!(store.subordinate(&op).await.unwrap(), None);
        assert_eq!(store.subordinates().await.unwrap().len(), 1);
    }
}
