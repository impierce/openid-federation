//! Verifying a Trust Mark that an Entity presents (OpenID Federation 1.0, Sections 7.2.2, 7.3
//! and 17.5): its issuer is trusted through a Trust Chain to a Trust Anchor, the Trust Anchor
//! recognizes the issuer for the Trust Mark type, the signature and time claims hold, and a
//! delegation from the type's owner is present and valid when the Trust Anchor names an owner.

use crate::jwt::CLOCK_SKEW_LEEWAY;
use crate::{
    extract_claims_unverified, EntityConfiguration, EntityId, FederationClient, FederationError, FederationResult,
    JwkSet, JwtArtifactType, JwtProcessor, SubordinateStatement, TrustChain, TrustMark, TrustMarkDelegation,
    TrustMarkEntry,
};
use std::collections::HashMap;
use std::fmt;

/// The step at which a Trust Mark failed verification, see [`TrustMark::from_verified_jwt`]. It
/// is carried by [`FederationError::TrustMarkRejected`].
///
/// New variants are not breaking changes, so a `match` on it needs a wildcard arm.
///
/// Reference: OpenID Federation 1.0 - Section 7.3 Validating a Trust Mark
/// (<https://openid.net/specs/openid-federation-1_0.html#section-7.3>)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustMarkRejection {
    /// Not a signed JWT typed `trust-mark+jwt` with an acceptable `alg` and Trust Mark claims.
    NotATrustMark(String),
    /// The Trust Mark's `sub` is not the Entity that presents it.
    SubjectMismatch {
        /// The Entity that presents the Trust Mark.
        expected: EntityId,
        /// The Trust Mark's `sub`.
        sub: EntityId,
    },
    /// The Trust Mark's `iss` is not the Entity whose keys verify it.
    IssuerMismatch {
        /// The Entity whose authenticated keys were given.
        expected: EntityId,
        /// The Trust Mark's `iss`.
        iss: EntityId,
    },
    /// `iat` is more than the clock skew leeway (60 seconds) in the future.
    IssuedInFuture,
    /// `exp` is more than the clock skew leeway (60 seconds) in the past.
    Expired,
    /// The signature does not verify with the issuer's key that `kid` names.
    InvalidSignature(String),
    /// The claims other than `delegation` break a rule of [`TrustMark::validate`].
    Invalid(String),
    /// The Trust Anchor's `trust_mark_issuers` does not list the Trust Mark type.
    TypeNotRecognized,
    /// The Trust Anchor's `trust_mark_issuers` lists issuers for the type, and the Trust Mark's
    /// issuer is not one of them.
    IssuerNotRecognized,
    /// The Trust Anchor's `trust_mark_owners` names an owner for the type, and the Trust Mark has
    /// no `delegation`.
    DelegationMissing,
    /// The `delegation` does not pass Section 7.2.2.
    InvalidDelegation(String),
}

impl fmt::Display for TrustMarkRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotATrustMark(reason) => write!(f, "not a Trust Mark: {reason}"),
            Self::SubjectMismatch { expected, sub } => {
                write!(f, "the Trust Mark is about {sub}, not about {expected}")
            }
            Self::IssuerMismatch { expected, iss } => {
                write!(f, "the Trust Mark is issued by {iss}, not by {expected}")
            }
            Self::IssuedInFuture => write!(f, "the Trust Mark is issued in the future"),
            Self::Expired => write!(f, "the Trust Mark has expired"),
            Self::InvalidSignature(reason) => {
                write!(f, "the Trust Mark does not verify with its issuer's key: {reason}")
            }
            Self::Invalid(reason) => write!(f, "{reason}"),
            Self::TypeNotRecognized => write!(
                f,
                "the Trust Anchor does not list the Trust Mark type in trust_mark_issuers"
            ),
            Self::IssuerNotRecognized => write!(
                f,
                "the Trust Anchor does not list the issuer for the Trust Mark type in trust_mark_issuers"
            ),
            Self::DelegationMissing => write!(
                f,
                "the Trust Anchor names an owner for the Trust Mark type, and the Trust Mark has no delegation"
            ),
            Self::InvalidDelegation(reason) => write!(f, "the delegation is not valid: {reason}"),
        }
    }
}

impl std::error::Error for TrustMarkRejection {}

impl From<TrustMarkRejection> for FederationError {
    fn from(rejection: TrustMarkRejection) -> Self {
        Self::TrustMarkRejected(Box::new(rejection))
    }
}

/// A Trust Mark in the leaf's Entity Configuration that did not verify, see
/// [`FederationClient::verify_chain_trust_marks`].
#[derive(Debug)]
#[non_exhaustive]
pub struct TrustMarkFailure {
    /// The entry as the leaf published it.
    pub entry: TrustMarkEntry,
    /// Why it did not verify: [`FederationError::TrustMarkRejected`] for the Trust Mark itself,
    /// another error when the issuer's Trust Chain could not be established.
    pub error: FederationError,
}

impl TrustMark {
    /// Verifies a Trust Mark JWT that `subject` presents, issued by `issuer`, whose Federation
    /// Entity Keys `issuer_keys` were authenticated through a Trust Chain to the Trust Anchor whose
    /// verified Entity Configuration is `trust_anchor`. Trust in the issuer comes first (Section
    /// 7.3); [`FederationClient::verify_trust_mark`] establishes it and then calls this.
    ///
    /// The checks, each a [`TrustMarkRejection`] when it fails, in order:
    /// 1. The JWT is typed `trust-mark+jwt`, has an acceptable `alg` (never `none`) and Trust Mark
    ///    claims ([`NotATrustMark`](TrustMarkRejection::NotATrustMark)).
    /// 2. `sub` is `subject` and `iss` is `issuer`.
    /// 3. `iat` is not in the future and `exp`, if any, not in the past, each allowing 60 seconds
    ///    of clock skew.
    /// 4. The signature verifies with the key of `issuer_keys` that `kid` names.
    /// 5. The claims other than `delegation` pass [`TrustMark::validate`].
    /// 6. The Trust Anchor's `trust_mark_issuers` lists the type, and either lists no issuer for it
    ///    (anyone may issue it) or lists `issuer` (Sections 3.1.2 and 17.5).
    /// 7. When the Trust Anchor's `trust_mark_owners` names an owner for the type, the Trust Mark
    ///    carries a `delegation`. A `delegation` must be typed `trust-mark-delegation+jwt`, be
    ///    signed with the owner's key from `trust_mark_owners` that its `kid` names, have `iss`
    ///    equal to the owner, `sub` equal to the issuer and the Trust Mark's type, and valid time
    ///    claims (Section 7.2.2). A `delegation` for a type without an owner cannot be verified
    ///    and is rejected.
    ///
    /// # Errors
    ///
    /// [`FederationError::TrustMarkRejected`] with the step that failed.
    ///
    /// Reference: OpenID Federation 1.0 - Section 7.3 Validating a Trust Mark
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-7.3>), Section 7.2.2
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-7.2.2>) and Section 17.5
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-17.5>)
    pub fn from_verified_jwt(
        jwt: &str,
        subject: &EntityId,
        issuer: &EntityId,
        issuer_keys: &JwkSet,
        trust_anchor: &EntityConfiguration,
    ) -> FederationResult<Self> {
        verify(jwt, subject, issuer, issuer_keys, trust_anchor)
    }
}

fn verify(
    jwt: &str,
    subject: &EntityId,
    issuer: &EntityId,
    issuer_keys: &JwkSet,
    trust_anchor: &EntityConfiguration,
) -> FederationResult<TrustMark> {
    check_unverified(jwt, subject, issuer)?;

    let trust_mark: TrustMark = JwtProcessor::new()
        .verify_jwt_with_jwks(jwt, issuer_keys, JwtArtifactType::TrustMark)
        .map_err(|err| TrustMarkRejection::InvalidSignature(err.to_string()))?;
    // The delegation is checked below, against the owner's keys, with a rejection of its own.
    TrustMark {
        delegation: None,
        ..trust_mark.clone()
    }
    .validate()
    .map_err(|err| TrustMarkRejection::Invalid(err.to_string()))?;

    check_recognized(&trust_mark.trust_mark_type, issuer, trust_anchor)?;

    let owner = trust_anchor
        .trust_mark_owners
        .as_ref()
        .and_then(|owners| owners.by_type.get(&trust_mark.trust_mark_type));
    match (owner, &trust_mark.delegation) {
        (None, None) => {}
        (Some(_), None) => return Err(TrustMarkRejection::DelegationMissing.into()),
        (None, Some(_)) => {
            return Err(TrustMarkRejection::InvalidDelegation(
                "the Trust Anchor names no owner for the Trust Mark type in trust_mark_owners, so its keys are unknown"
                    .to_string(),
            )
            .into())
        }
        (Some(owner), Some(delegation)) => {
            let invalid = |reason: String| TrustMarkRejection::InvalidDelegation(reason);
            let delegation: TrustMarkDelegation = JwtProcessor::new()
                .verify_jwt_with_jwks(delegation, &owner.jwks, JwtArtifactType::TrustMarkDelegation)
                .map_err(|err| invalid(format!("it does not verify with the owner's key: {err}")))?;
            if delegation.iss != owner.sub {
                return Err(invalid(format!(
                    "it is issued by {}, not by the owner {}",
                    delegation.iss, owner.sub
                ))
                .into());
            }
            if delegation.sub != *issuer {
                return Err(invalid(format!(
                    "it delegates to {}, not to the issuer {issuer}",
                    delegation.sub
                ))
                .into());
            }
            if delegation.trust_mark_type != trust_mark.trust_mark_type {
                return Err(invalid(format!(
                    "it delegates Trust Marks of type {}",
                    delegation.trust_mark_type
                ))
                .into());
            }
            delegation.validate().map_err(|err| invalid(err.to_string()))?;
        }
    }

    Ok(trust_mark)
}

/// Steps 1 to 3 of [`TrustMark::from_verified_jwt`], which need no key: the header's `typ`, the
/// Trust Mark claims, `sub`, `iss` and the time claims, read before the signature is checked.
fn check_unverified(jwt: &str, subject: &EntityId, issuer: &EntityId) -> FederationResult<TrustMark> {
    let header = jsonwebtoken::decode_header(jwt).map_err(|err| TrustMarkRejection::NotATrustMark(err.to_string()))?;
    JwtArtifactType::TrustMark
        .validate_header_typ(header.typ.as_deref())
        .map_err(|err| TrustMarkRejection::NotATrustMark(err.to_string()))?;
    let unverified: TrustMark =
        extract_claims_unverified(jwt).map_err(|err| TrustMarkRejection::NotATrustMark(err.to_string()))?;

    if unverified.sub != *subject {
        return Err(TrustMarkRejection::SubjectMismatch {
            expected: subject.clone(),
            sub: unverified.sub,
        }
        .into());
    }
    if unverified.iss != *issuer {
        return Err(TrustMarkRejection::IssuerMismatch {
            expected: issuer.clone(),
            iss: unverified.iss,
        }
        .into());
    }
    let now = chrono::Utc::now().timestamp();
    if unverified.iat > now.saturating_add(CLOCK_SKEW_LEEWAY) {
        return Err(TrustMarkRejection::IssuedInFuture.into());
    }
    if unverified
        .exp
        .is_some_and(|exp| exp < now.saturating_sub(CLOCK_SKEW_LEEWAY))
    {
        return Err(TrustMarkRejection::Expired.into());
    }

    Ok(unverified)
}

/// Step 6 of [`TrustMark::from_verified_jwt`]: the Trust Anchor's `trust_mark_issuers` lists
/// `trust_mark_type`, and either lists no issuer for it or lists `issuer` (Sections 3.1.2 and
/// 17.5).
fn check_recognized(
    trust_mark_type: &str,
    issuer: &EntityId,
    trust_anchor: &EntityConfiguration,
) -> FederationResult<()> {
    let recognized_issuers = trust_anchor
        .trust_mark_issuers
        .as_ref()
        .and_then(|issuers| issuers.by_type.get(trust_mark_type))
        .ok_or(TrustMarkRejection::TypeNotRecognized)?;
    if !recognized_issuers.is_empty() && !recognized_issuers.contains(issuer) {
        return Err(TrustMarkRejection::IssuerNotRecognized.into());
    }
    Ok(())
}

impl FederationClient {
    /// Verifies a Trust Mark that `subject` presents, under the Trust Anchor `trust_anchor`.
    ///
    /// The Trust Anchor's Entity Configuration is fetched and verified first. Trust in the Trust
    /// Mark Issuer comes before trust in the Trust Mark (Section 7.3): when the issuer is the
    /// Trust Anchor itself, its own keys verify the Trust Mark; otherwise a Trust Chain from the
    /// issuer to the Trust Anchor is discovered with
    /// [`discover_trust_chain`](Self::discover_trust_chain), and the keys the issuer's Immediate
    /// Superior endorses verify it. Then [`TrustMark::from_verified_jwt`] runs its checks.
    ///
    /// The checks that need no key run before discovery: the Trust Mark's type and claims, its
    /// `sub`, its time claims, and whether the Trust Anchor recognizes its issuer for its type. A
    /// Trust Mark that fails them is rejected without a request to the issuer it names, which is
    /// not authenticated yet.
    ///
    /// The caller decides whether it trusts `trust_anchor`, as for discovery.
    ///
    /// # Errors
    ///
    /// [`FederationError::TrustMarkRejected`] when the Trust Mark itself fails, and the errors of
    /// fetching the Trust Anchor's configuration or discovering the issuer's Trust Chain.
    ///
    /// Reference: OpenID Federation 1.0 - Section 7.3 Validating a Trust Mark
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-7.3>)
    pub async fn verify_trust_mark(
        &self,
        trust_mark: &str,
        subject: &EntityId,
        trust_anchor: &EntityId,
    ) -> FederationResult<TrustMark> {
        let (_, configuration) = self.resolve_entity_configuration(trust_anchor).await?;
        self.verify_trust_mark_under(trust_mark, subject, trust_anchor, &configuration, &mut HashMap::new())
            .await
    }

    /// Verifies the Trust Marks in the `trust_marks` of the leaf's Entity Configuration in
    /// `chain`, under the chain's Trust Anchor, and stores those that verify in
    /// [`TrustChain::trust_marks`]. Discovery does not do this by itself, since every Trust Mark
    /// Issuer needs a Trust Chain of its own.
    ///
    /// Each Trust Mark is verified as [`verify_trust_mark`](Self::verify_trust_mark) does, with
    /// the chain's own Trust Anchor configuration. Those that do not verify are returned, with
    /// why; they are not stored. Each issuer's Trust Chain is discovered once per call, and a
    /// Trust Mark the leaf issues itself is verified with the keys `chain` endorses for it.
    ///
    /// # Errors
    ///
    /// The errors of reading the leaf's configuration, the keys endorsed for it and the Trust
    /// Anchor's configuration from `chain`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 7.3 Validating a Trust Mark
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-7.3>)
    pub async fn verify_chain_trust_marks(&self, chain: &mut TrustChain) -> FederationResult<Vec<TrustMarkFailure>> {
        let (subject, leaf) = chain.leaf_entity_id_and_configuration()?;
        let (anchor, anchor_configuration) = chain.trust_anchor_entity_id_and_configuration()?;

        let mut issuer_keys = HashMap::from([(subject.clone(), endorsed_keys(chain)?)]);
        let mut verified = Vec::new();
        let mut failures = Vec::new();
        for entry in leaf.trust_marks.into_iter().flatten() {
            match self
                .verify_trust_mark_under(
                    &entry.trust_mark,
                    &subject,
                    &anchor,
                    &anchor_configuration,
                    &mut issuer_keys,
                )
                .await
            {
                Ok(trust_mark) => verified.push(trust_mark),
                Err(error) => failures.push(TrustMarkFailure { entry, error }),
            }
        }
        chain.trust_marks = Some(verified);
        Ok(failures)
    }

    /// [`verify_trust_mark`](Self::verify_trust_mark) with the Trust Anchor's configuration at
    /// hand. `issuer_keys` holds the keys already authenticated for an issuer, and gains those of
    /// each issuer whose Trust Chain is discovered.
    async fn verify_trust_mark_under(
        &self,
        trust_mark: &str,
        subject: &EntityId,
        anchor: &EntityId,
        anchor_configuration: &EntityConfiguration,
        issuer_keys: &mut HashMap<EntityId, JwkSet>,
    ) -> FederationResult<TrustMark> {
        let issuer = extract_claims_unverified::<TrustMark>(trust_mark)
            .map_err(|err| TrustMarkRejection::NotATrustMark(err.to_string()))?
            .iss;
        // The checks that need no key come first, so that a Trust Mark failing them causes no
        // request to the issuer it names.
        let unverified = check_unverified(trust_mark, subject, &issuer)?;
        check_recognized(&unverified.trust_mark_type, &issuer, anchor_configuration)?;

        let keys = if issuer == *anchor {
            anchor_configuration.jwks.clone()
        } else if let Some(keys) = issuer_keys.get(&issuer) {
            keys.clone()
        } else {
            let chain = self
                .discover_trust_chain(&issuer, Some(std::slice::from_ref(anchor)))
                .await?;
            let keys = endorsed_keys(&chain)?;
            issuer_keys.insert(issuer.clone(), keys.clone());
            keys
        };
        TrustMark::from_verified_jwt(trust_mark, subject, &issuer, &keys, anchor_configuration)
    }
}

/// The keys `chain` authenticates for its leaf: those the leaf's Immediate Superior endorses in
/// its Subordinate Statement, or the Trust Anchor's own when the chain has none.
fn endorsed_keys(chain: &TrustChain) -> FederationResult<JwkSet> {
    match chain.chain.as_slice() {
        [_, statement, _, ..] => Ok(extract_claims_unverified::<SubordinateStatement>(statement)?.jwks),
        _ => Ok(chain.trust_anchor_entity_id_and_configuration()?.1.jwks),
    }
}
