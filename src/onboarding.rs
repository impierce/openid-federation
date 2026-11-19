//! Checking a candidate before a Superior registers it as an Immediate Subordinate.
//!
//! The specification does not standardise enrollment (Appendix A.1), but a Superior that
//! registers an Entity whose Entity Configuration does not name it in `authority_hints`, or whose
//! keys differ from the ones registered, issues a Subordinate Statement no Trust Chain can use
//! (Sections 10.1 and 10.2). [`FederationClient::check_candidate_subordinate`] fetches the
//! candidate's Entity Configuration and reports every check it fails, and a
//! [`CandidateReport`] without failures becomes the [`Subordinate`] to store.

use crate::{
    validate_metadata_policy, EntityConfiguration, EntityId, EntityType, FederationClient, FederationError,
    FederationResult, MetadataPolicy, NamingConstraints, Subordinate,
};
use std::fmt;

/// What a Superior requires of a candidate Subordinate and states about it once registered.
///
/// Reference: OpenID Federation 1.0 - Section 6.1 Metadata Policy
/// (<https://openid.net/specs/openid-federation-1_0.html#section-6.1>) and Section 6.2.2 Naming
/// Constraints (<https://openid.net/specs/openid-federation-1_0.html#section-6.2.2>)
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct SubordinatePolicy {
    /// The naming constraints the candidate's Entity Identifier must satisfy, typically those its
    /// own Superior placed on the Superior's Subordinates.
    pub naming_constraints: Option<NamingConstraints>,
    /// The metadata policy the Superior will apply to the candidate.
    pub metadata_policy: Option<MetadataPolicy>,
    /// The policy operators that are not standard and that the metadata policy depends on.
    pub metadata_policy_crit: Option<Vec<String>>,
}

impl SubordinatePolicy {
    /// A policy without naming constraints or metadata policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requires the candidate's Entity Identifier to satisfy `naming_constraints`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2.2 Naming Constraints
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-6.2.2>)
    pub fn with_naming_constraints(mut self, naming_constraints: NamingConstraints) -> Self {
        self.naming_constraints = Some(naming_constraints);
        self
    }

    /// Sets the metadata policy the Superior applies to the candidate.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.1 Metadata Policy
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-6.1>)
    pub fn with_metadata_policy(mut self, metadata_policy: MetadataPolicy) -> Self {
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
}

/// A check a candidate Subordinate fails.
///
/// Reference: OpenID Federation 1.0 - Section 10.1 Fetching Entity Statements to Establish a Trust
/// Chain (<https://openid.net/specs/openid-federation-1_0.html#section-10.1>) and Section 10.2
/// Validating a Trust Chain (<https://openid.net/specs/openid-federation-1_0.html#section-10.2>)
#[derive(Debug)]
#[non_exhaustive]
pub enum CandidateFailure {
    /// The Entity Configuration could not be fetched. The checks that need it did not run.
    ConfigurationUnreachable(FederationError),
    /// The Entity Configuration is not a valid, self-signed configuration of the candidate:
    /// [`EntityConfiguration::from_verified_jwt`] refused it. The checks that need it did not
    /// run.
    InvalidConfiguration(FederationError),
    /// `authority_hints` does not name the Superior, so no Trust Chain from the candidate reaches
    /// it (Section 10.1).
    SuperiorNotInAuthorityHints,
    /// The candidate's `jwks` cannot be published in a Subordinate Statement
    /// ([`JwkSet::validate`](crate::JwkSet::validate)).
    InvalidJwks(FederationError),
    /// The candidate's Entity Identifier does not satisfy the policy's naming constraints.
    OutsideNamingConstraints,
    /// The metadata policy the Superior would apply is not valid ([`validate_metadata_policy`]).
    InvalidMetadataPolicy(FederationError),
}

impl fmt::Display for CandidateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigurationUnreachable(err) => write!(f, "the Entity Configuration could not be fetched: {err}"),
            Self::InvalidConfiguration(err) => write!(f, "the Entity Configuration is not valid: {err}"),
            Self::SuperiorNotInAuthorityHints => f.write_str("authority_hints does not name the Superior"),
            Self::InvalidJwks(err) => write!(f, "the jwks cannot be published: {err}"),
            Self::OutsideNamingConstraints => f.write_str("the Entity Identifier is outside the naming constraints"),
            Self::InvalidMetadataPolicy(err) => write!(f, "the metadata policy is not valid: {err}"),
        }
    }
}

/// The result of [`FederationClient::check_candidate_subordinate`]: what the candidate's verified
/// Entity Configuration says about it, and every check it fails.
///
/// Reference: OpenID Federation 1.0 - Appendix A.1
/// (<https://openid.net/specs/openid-federation-1_0.html#appendix-A.1>)
#[derive(Debug)]
#[non_exhaustive]
pub struct CandidateReport {
    /// The candidate's Entity Identifier, spelled as the Superior asked for it.
    pub entity_id: EntityId,
    /// The verified Entity Configuration, or `None` when it could not be fetched or verified.
    pub configuration: Option<EntityConfiguration>,
    /// The Entity Types the candidate publishes metadata for.
    pub entity_types: Vec<EntityType>,
    /// Whether the candidate is an Intermediate Entity: it publishes a `federation_fetch_endpoint`.
    pub intermediate: bool,
    /// Every check the candidate fails, in the order they ran; empty when it passes.
    pub failures: Vec<CandidateFailure>,
    policy: SubordinatePolicy,
}

impl CandidateReport {
    /// Whether the candidate passed every check.
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// The Subordinate to register: the candidate's Entity Identifier, its `jwks`, Entity Types
    /// and Intermediate status, and the policy's metadata policy.
    ///
    /// # Errors
    ///
    /// [`FederationError::Configuration`] listing the failures, when the candidate failed a check.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.3
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.3>)
    pub fn into_subordinate(self) -> FederationResult<Subordinate> {
        let Some(configuration) = self.configuration.filter(|_| self.failures.is_empty()) else {
            let failures: Vec<String> = self.failures.iter().map(ToString::to_string).collect();
            return Err(FederationError::Configuration(format!(
                "the candidate {} cannot be registered: {}",
                self.entity_id,
                failures.join("; ")
            )));
        };
        let mut subordinate = Subordinate::new(self.entity_id, configuration.jwks)
            .with_entity_types(self.entity_types)
            .with_intermediate(self.intermediate);
        if let Some(metadata_policy) = self.policy.metadata_policy {
            subordinate = subordinate.with_metadata_policy(metadata_policy);
        }
        if let Some(operators) = self.policy.metadata_policy_crit {
            subordinate = subordinate.with_metadata_policy_crit(operators);
        }
        Ok(subordinate)
    }
}

impl FederationClient {
    /// Checks `candidate` before `superior` registers it as an Immediate Subordinate, and reports
    /// every check it fails rather than stopping at the first.
    ///
    /// The candidate's Entity Configuration is fetched and verified with
    /// [`EntityConfiguration::from_verified_jwt`]: it must be the candidate's own and be signed
    /// with a key from its own `jwks`, and its `crit` may name only claims the client was told it
    /// understands ([`with_understood_claims`](Self::with_understood_claims)). Then:
    /// - `authority_hints` must name `superior`, or no Trust Chain from the candidate reaches it;
    /// - `jwks` must pass [`JwkSet::validate`](crate::JwkSet::validate), since the Superior publishes them in its
    ///   Subordinate Statement;
    /// - the Entity Identifier must satisfy the policy's naming constraints, if any;
    /// - the policy's metadata policy, if any, must pass [`validate_metadata_policy`].
    ///
    /// The last two run even when the Entity Configuration is unavailable. The report also lists
    /// the candidate's Entity Types and whether it is an Intermediate Entity, which
    /// [`CandidateReport::into_subordinate`] stores.
    ///
    /// Reference: OpenID Federation 1.0 - Appendix A.1
    /// (<https://openid.net/specs/openid-federation-1_0.html#appendix-A.1>), Section 10.1
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-10.1>) and Section 10.2
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-10.2>)
    pub async fn check_candidate_subordinate(
        &self,
        superior: &EntityId,
        candidate: &EntityId,
        policy: &SubordinatePolicy,
    ) -> CandidateReport {
        let mut failures = Vec::new();

        let configuration = match self.fetch_entity_configuration(candidate).await {
            Err(err) => {
                failures.push(CandidateFailure::ConfigurationUnreachable(err));
                None
            }
            Ok(jwt) => match EntityConfiguration::from_verified_jwt(&jwt, candidate, &self.understood_claims()) {
                Err(err) => {
                    failures.push(CandidateFailure::InvalidConfiguration(err));
                    None
                }
                Ok(configuration) => Some(configuration),
            },
        };

        if let Some(configuration) = &configuration {
            if !configuration
                .authority_hints
                .iter()
                .flatten()
                .any(|hint| hint == superior)
            {
                failures.push(CandidateFailure::SuperiorNotInAuthorityHints);
            }
            if let Err(err) = configuration.jwks.validate() {
                failures.push(CandidateFailure::InvalidJwks(err));
            }
        }
        if let Some(naming_constraints) = &policy.naming_constraints {
            if !naming_constraints.permits(candidate) {
                failures.push(CandidateFailure::OutsideNamingConstraints);
            }
        }
        if let Some(metadata_policy) = &policy.metadata_policy {
            // The Superior publishes the policy, so it understands its own operators.
            if let Err(err) = validate_metadata_policy(metadata_policy, &[]) {
                failures.push(CandidateFailure::InvalidMetadataPolicy(err));
            }
        }

        let metadata = configuration
            .as_ref()
            .and_then(|configuration| configuration.metadata.as_ref());
        CandidateReport {
            entity_id: candidate.clone(),
            entity_types: metadata.map(|metadata| metadata.entity_types()).unwrap_or_default(),
            intermediate: metadata
                .and_then(|metadata| metadata.federation_entity())
                .is_some_and(|federation_entity| federation_entity.federation_fetch_endpoint.is_some()),
            configuration,
            failures,
            policy: policy.clone(),
        }
    }
}
