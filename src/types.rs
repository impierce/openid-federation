//! Common types used throughout the OpenID Federation implementation.

use crate::{jwt::JwtClaims, FederationError, FederationResult, JwkSet};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use url::Url;

/// Entity Identifier: a URL that uniquely identifies an entity in the federation.
///
/// The identifier keeps the exact spelling it was parsed from. Parsing a URL normalizes it, for
/// example `https://ta.example.org` becomes `https://ta.example.org/`, and a federation endpoint
/// that compares an identifier as a string does not recognize the normalized spelling. So
/// [`EntityId::as_str`], [`Display`](fmt::Display) and serialization return the spelling as
/// published, which is what requests to other entities carry.
///
/// Two identifiers are equal when they are equivalent URLs, so `https://ta.example.org` and
/// `https://ta.example.org/` are the same entity (RFC 3986, Section 6.2.3 Scheme-Based
/// Normalization). Comparing them as plain strings would break trust chains between entities that
/// spell the same identifier differently.
///
/// Reference: OpenID Federation 1.0 - Section 1.2 Terminology (Entity Identifier)
/// <https://openid.net/specs/openid-federation-1_0.html#name-terminology>
#[derive(Clone)]
pub struct EntityId {
    id: String,
    url: Url,
}

impl EntityId {
    /// Parse an Entity Identifier, keeping `id` as spelled.
    ///
    /// Only checks that `id` is a URL; [`UrlValidator::validate_entity_id`](crate::UrlValidator::validate_entity_id)
    /// checks the rules the specification places on Entity Identifiers.
    pub fn parse(id: &str) -> FederationResult<Self> {
        Ok(Self {
            id: id.to_string(),
            url: Url::parse(id)?,
        })
    }

    /// The identifier as spelled when it was parsed.
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// The identifier as a parsed, normalized URL, for building requests to the entity.
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    /// Where the entity publishes its Entity Configuration: the Entity Identifier, including any
    /// path and without a trailing `/`, followed by `/.well-known/openid-federation`.
    ///
    /// The client fetches from this URL, and an entity serves its configuration at its path, see
    /// [`EntityConfigurationEndpoint::path`](crate::EntityConfigurationEndpoint::path).
    ///
    /// Reference: OpenID Federation 1.0 - Section 9 Obtaining Federation Entity Configuration
    /// Information (<https://openid.net/specs/openid-federation-1_0.html#section-9>)
    pub fn entity_configuration_url(&self) -> Url {
        let mut url = self.url.clone();
        url.set_query(None);
        url.set_fragment(None);
        let path = format!("{}/.well-known/openid-federation", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url
    }
}

impl PartialEq for EntityId {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for EntityId {}

impl Hash for EntityId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl fmt::Debug for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EntityId").field(&self.id).finish()
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}

impl AsRef<str> for EntityId {
    fn as_ref(&self) -> &str {
        &self.id
    }
}

impl FromStr for EntityId {
    type Err = FederationError;

    fn from_str(id: &str) -> FederationResult<Self> {
        Self::parse(id)
    }
}

/// Spells the identifier as `url` prints, which is its normalized form.
impl From<Url> for EntityId {
    fn from(url: Url) -> Self {
        Self {
            id: url.as_str().to_string(),
            url,
        }
    }
}

impl Serialize for EntityId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.id)
    }
}

impl<'de> Deserialize<'de> for EntityId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let id = String::deserialize(deserializer)?;
        Self::parse(&id).map_err(serde::de::Error::custom)
    }
}

/// JSON Web Key Set as defined in RFC 7517.
/// Note: This is a type alias for the raw JWKS structure.
/// Use the `JwkSet` struct from the `jwk` module for full functionality.
pub type RawJwkSet = HashMap<String, serde_json::Value>;

/// Generic metadata type for flexibility.
pub type Metadata = HashMap<String, serde_json::Value>;

/// An Entity Type Identifier: the six the specification defines, or any other, since additional
/// identifiers may be defined by other specifications and a statement that uses one is still valid.
///
/// Reference: OpenID Federation 1.0 - Section 5.1 Entity Type Identifiers
/// <https://openid.net/specs/openid-federation-1_0.html#entity_types>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    /// Federation Entity
    #[serde(rename = "federation_entity")]
    FederationEntity,
    /// OpenID Provider
    #[serde(rename = "openid_provider")]
    OpenIdProvider,
    /// OpenID Relying Party
    #[serde(rename = "openid_relying_party")]
    OpenIdRelyingParty,
    /// OAuth Authorization Server
    #[serde(rename = "oauth_authorization_server")]
    OauthAuthorizationServer,
    /// OAuth Protected Resource
    #[serde(rename = "oauth_resource")]
    OauthResource,
    /// OAuth Client
    #[serde(rename = "oauth_client")]
    OauthClient,
    /// An Entity Type Identifier defined outside this specification, kept verbatim.
    #[serde(untagged)]
    Other(String),
}

/// A Trust Mark as an Entity Configuration carries it in its `trust_marks` claim: the Trust Mark
/// type identifier next to the signed Trust Mark JWT, whose claims are [`TrustMark`].
///
/// Reference: OpenID Federation 1.0 - Section 3.1.2 Claims that MUST or MAY Appear in an Entity Configuration
/// <https://openid.net/specs/openid-federation-1_0.html#name-claims-that-must-or-may-app>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustMarkEntry {
    /// MUST equal the `trust_mark_type` claim of the Trust Mark JWT in `trust_mark`.
    pub trust_mark_type: String,
    /// The signed Trust Mark JWT.
    pub trust_mark: String,
}

impl TrustMarkEntry {
    /// Validate the syntax of the entry: `trust_mark` is a JWT whose payload carries a
    /// `trust_mark_type` claim equal to the entry's `trust_mark_type`.
    ///
    /// This does not verify the Trust Mark's signature, nor whether its issuer is trusted. The
    /// specification keeps that evaluation separate from the syntactic validation of an Entity
    /// Statement, and a Trust Mark signed with an algorithm this crate cannot verify is still a
    /// well-formed entry.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.2 Entity Statement Validation
    /// <https://openid.net/specs/openid-federation-1_0.html#name-entity-statement-validation>
    pub fn validate(&self) -> FederationResult<()> {
        let invalid = |reason: &str| {
            FederationError::InvalidSubordinateStatement(format!(
                "Trust Mark of type {}: {reason}",
                self.trust_mark_type
            ))
        };

        let mut segments = self.trust_mark.split('.');
        let payload = match (segments.next(), segments.next(), segments.next(), segments.next()) {
            (Some(_), Some(payload), Some(_), None) => payload,
            _ => return Err(invalid("trust_mark is not a JWT in compact serialization")),
        };
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| invalid("the payload of trust_mark is not base64url encoded"))?;
        let claims: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| invalid("the payload of trust_mark is not a JSON object"))?;

        match claims.get("trust_mark_type").and_then(serde_json::Value::as_str) {
            Some(claimed) if claimed == self.trust_mark_type => Ok(()),
            Some(claimed) => Err(invalid(&format!(
                "the trust_mark_type claim of trust_mark is {claimed}, which differs from the entry"
            ))),
            None => Err(invalid("trust_mark has no trust_mark_type claim")),
        }
    }
}

/// Trust mark as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 6 Trust Marks
/// <https://openid.net/specs/openid-federation-1_0.html#name-trust-marks>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustMark {
    // TODO: exp should be OPTIONAL
    #[serde(flatten)]
    pub claims: JwtClaims,
    pub trust_mark_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<Url>,
    /// Optional reference URL to human-readable issuance details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<Url>,
    /// The string must represent a trust mark delegation JWT
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<String>,
}

/// Trusted issuers for each trust mark type.
///
/// This serializes as a JSON object whose member names are trust mark type
/// identifiers and whose values are arrays of trusted issuer entity IDs.
/// An empty issuer array means any issuer is trusted for that trust mark type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TrustMarkIssuers {
    #[serde(flatten)]
    pub by_type: HashMap<String, Vec<EntityId>>,
}

/// Trust mark owner metadata for a specific trust mark type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustMarkOwner {
    /// Identifier of the trust mark owner.
    pub sub: EntityId,
    /// Owner federation entity keys used for signing.
    pub jwks: JwkSet,
    /// Additional owner-specific members.
    #[serde(flatten, default)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Trust mark owners for each trust mark type.
///
/// This serializes as a JSON object whose member names are trust mark type
/// identifiers and whose values describe the owner of that trust mark type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TrustMarkOwners {
    #[serde(flatten)]
    pub by_type: HashMap<String, TrustMarkOwner>,
}

/// Policy Operators as defined in the OpenID Federation specification.
/// It's a struct, not an enum, to enable multiple operators to be used in combination as defined in the spec.
///
/// Reference: OpenID Federation 1.0 - Section 7 Metadata Policy
/// <https://openid.net/specs/openid-federation-1_0.html#name-metadata-policy>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyOperators {
    /// Essential policy operators
    #[serde(skip_serializing_if = "Option::is_none")]
    pub essential: Option<bool>,
    /// Default value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    /// One of values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_of: Option<Vec<serde_json::Value>>,
    /// Subset of values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subset_of: Option<Vec<serde_json::Value>>,
    /// Superset of values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superset_of: Option<Vec<serde_json::Value>>,
    /// Add values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add: Option<serde_json::Value>,
    /// Value operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// Constraints a Superior places on the Subordinates below it, carried in the `constraints` claim
/// of a Subordinate Statement.
///
/// Reference: OpenID Federation 1.0 - Section 6.2 Constraints
/// <https://openid.net/specs/openid-federation-1_0.html#chain_constraints>
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Constraints {
    /// The most Intermediate Entities a Trust Chain may have between this statement and the
    /// Trust Chain subject. It MUST be 0 or more, which `u32` guarantees.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2.1 Max Path Length Constraint
    /// <https://openid.net/specs/openid-federation-1_0.html#section-6.2.1>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<u32>,
    /// The hosts and domains the Entity Identifiers of Subordinates in a Trust Chain must, or must
    /// not, be in.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2.2 Naming Constraints
    /// <https://openid.net/specs/openid-federation-1_0.html#section-6.2.2>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub naming_constraints: Option<NamingConstraints>,
    /// The Entity Types acceptable for Subordinate Entities in a Trust Chain. Absent, any Entity
    /// Type is allowed; `federation_entity` is always allowed and never listed.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2.3 Entity Type Constraints
    /// <https://openid.net/specs/openid-federation-1_0.html#entity_type_constraints>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_entity_types: Option<Vec<EntityType>>,
}

impl Constraints {
    /// Checks the constraints a Superior may publish: the naming constraints pass
    /// [`NamingConstraints::validate`].
    ///
    /// # Errors
    ///
    /// The errors of [`NamingConstraints::validate`].
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2 Constraints
    /// <https://openid.net/specs/openid-federation-1_0.html#chain_constraints>
    pub fn validate(&self) -> FederationResult<()> {
        if let Some(naming_constraints) = &self.naming_constraints {
            naming_constraints.validate()?;
        }
        Ok(())
    }
}

/// The hosts and domains the Entity Identifiers of Subordinates in a Trust Chain must be in
/// (`permitted`) or must not be in (`excluded`), as domain name constraints of RFC 5280,
/// Section 4.2.1.10, matched against the host of the Entity Identifier.
///
/// - `host.example.com` names that host only.
/// - `.example.com` names every host below `example.com`, such as `host.example.com` and
///   `my.host.example.com`, but not `example.com` itself.
/// - A host that matches an `excluded` name is not permitted, whatever `permitted` says.
/// - When `permitted` is present, a host must match one of its names.
///
/// Names compare without regard to case, as DNS names do. Write internationalized domain names
/// as A-labels (`xn--…`), the form the host of a parsed Entity Identifier takes.
///
/// A name without a leading period names one host. RFC 5280 lets such a name also cover the
/// hosts below it; OpenID Federation 1.0 does not, and the specification decides here.
///
/// Reference: OpenID Federation 1.0 - Section 6.2.2 Naming Constraints
/// <https://openid.net/specs/openid-federation-1_0.html#section-6.2.2>
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamingConstraints {
    /// The hosts and domains Subordinates must be in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permitted: Option<Vec<String>>,
    /// The hosts and domains Subordinates must not be in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded: Option<Vec<String>>,
}

impl NamingConstraints {
    /// Checks that the naming constraints can be published: `permitted` or `excluded` is present,
    /// neither is the empty array, and every name is a fully qualified domain name, optionally
    /// with a leading period, without a scheme, port, path or trailing period.
    ///
    /// A name is a sequence of labels separated by periods; each label has 1 to 63 ASCII letters,
    /// digits and hyphens, and neither starts nor ends with a hyphen; the whole name has at most
    /// 253 characters. RFC 5280 requires at least one of the two lists, each with at least one
    /// name.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidSubordinateStatement`] naming the list and the name that fails.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2.2 Naming Constraints
    /// <https://openid.net/specs/openid-federation-1_0.html#section-6.2.2> and RFC 5280,
    /// Section 4.2.1.10 (<https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10>)
    pub fn validate(&self) -> FederationResult<()> {
        if self.permitted.is_none() && self.excluded.is_none() {
            return Err(FederationError::InvalidSubordinateStatement(
                "naming_constraints must contain permitted, excluded or both".to_string(),
            ));
        }
        for (list, names) in [("permitted", &self.permitted), ("excluded", &self.excluded)] {
            let Some(names) = names else { continue };
            if names.is_empty() {
                return Err(FederationError::InvalidSubordinateStatement(format!(
                    "naming_constraints {list} must not be the empty array"
                )));
            }
            if let Some(name) = names.iter().find(|name| !is_domain_name_constraint(name)) {
                return Err(FederationError::InvalidSubordinateStatement(format!(
                    "naming_constraints {list} entry {name:?} is not a fully qualified domain name, \
                     such as \"host.example.com\" or \".example.com\""
                )));
            }
        }
        Ok(())
    }

    /// Whether the host of `entity_id` satisfies these naming constraints: it matches no
    /// `excluded` name, and, when `permitted` is present, it matches a `permitted` name. An
    /// Entity Identifier without a host is never permitted.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2.2 Naming Constraints
    /// <https://openid.net/specs/openid-federation-1_0.html#section-6.2.2>
    pub fn permits(&self, entity_id: &EntityId) -> bool {
        let Some(host) = entity_id.as_url().host_str() else {
            return false;
        };
        let matches_any = |names: &Option<Vec<String>>| {
            names
                .iter()
                .flatten()
                .any(|name| domain_name_constraint_matches(name, host))
        };
        if matches_any(&self.excluded) {
            return false;
        }
        self.permitted.is_none() || matches_any(&self.permitted)
    }
}

/// Whether `name` is a domain name constraint of RFC 5280, Section 4.2.1.10: a fully qualified
/// domain name, optionally with a leading period.
fn is_domain_name_constraint(name: &str) -> bool {
    let domain = name.strip_prefix('.').unwrap_or(name);
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Whether `host` satisfies the domain name constraint `name`: `.example.com` is satisfied by
/// any host below `example.com`, `host.example.com` by that host only (Section 6.2.2).
fn domain_name_constraint_matches(name: &str, host: &str) -> bool {
    if name.starts_with('.') {
        host.len() > name.len()
            && host
                .get(host.len() - name.len()..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(name))
    } else {
        host.eq_ignore_ascii_case(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference: OpenID Federation 1.0 - Section 2.2 Entity Types
    /// <https://openid.net/specs/openid-federation-1_0.html#name-entity-types>
    #[test]
    fn entity_type_identifiers_follow_the_specification() {
        let identifiers = [
            (EntityType::FederationEntity, "federation_entity"),
            (EntityType::OpenIdProvider, "openid_provider"),
            (EntityType::OpenIdRelyingParty, "openid_relying_party"),
            (EntityType::OauthAuthorizationServer, "oauth_authorization_server"),
            (EntityType::OauthResource, "oauth_resource"),
            (EntityType::OauthClient, "oauth_client"),
        ];
        for (entity_type, identifier) in identifiers {
            let json = format!("\"{identifier}\"");
            assert_eq!(serde_json::to_string(&entity_type).unwrap(), json);
            assert_eq!(serde_json::from_str::<EntityType>(&json).unwrap(), entity_type);
        }
    }

    /// Reference: OpenID Federation 1.0 - Section 5.1 Entity Type Identifiers
    /// <https://openid.net/specs/openid-federation-1_0.html#entity_types>
    #[test]
    fn entity_type_keeps_an_additional_identifier() {
        let json = r#""https://wallet.example/entity-types/wallet_provider""#;
        let entity_type: EntityType = serde_json::from_str(json).unwrap();
        assert_eq!(
            entity_type,
            EntityType::Other("https://wallet.example/entity-types/wallet_provider".to_string())
        );
        assert_eq!(serde_json::to_string(&entity_type).unwrap(), json);
    }

    #[test]
    fn constraints_accept_the_specifications_entity_types() {
        let constraints: Constraints = serde_json::from_str(
            r#"{"max_path_length":2,"allowed_entity_types":["openid_provider","openid_relying_party"]}"#,
        )
        .unwrap();
        assert_eq!(
            constraints.allowed_entity_types,
            Some(vec![EntityType::OpenIdProvider, EntityType::OpenIdRelyingParty])
        );

        let constraints: Constraints =
            serde_json::from_str(r#"{"allowed_entity_types":["openid_relying_party","wallet_provider"]}"#).unwrap();
        assert_eq!(
            constraints.allowed_entity_types,
            Some(vec![
                EntityType::OpenIdRelyingParty,
                EntityType::Other("wallet_provider".to_string())
            ])
        );
    }

    #[test]
    fn entity_id_keeps_the_spelling_it_was_parsed_from() {
        for spelling in [
            "https://ta.example.org",
            "https://ta.example.org/",
            "https://example.org/federation",
        ] {
            let entity_id = EntityId::parse(spelling).unwrap();

            assert_eq!(entity_id.as_str(), spelling);
            assert_eq!(entity_id.to_string(), spelling);
            let json = serde_json::to_string(&entity_id).unwrap();
            assert_eq!(json, format!("\"{spelling}\""));
            assert_eq!(serde_json::from_str::<EntityId>(&json).unwrap().as_str(), spelling);
        }
    }

    /// RFC 3986, Section 6.2.3: an empty path is equivalent to `/` for `https` URLs.
    #[test]
    fn entity_ids_that_are_equivalent_urls_are_equal() {
        let without_slash = EntityId::parse("https://ta.example.org").unwrap();
        let with_slash = EntityId::parse("https://ta.example.org/").unwrap();

        assert_eq!(without_slash, with_slash);
        assert!(std::collections::HashSet::from([without_slash]).contains(&with_slash));

        assert_ne!(
            EntityId::parse("https://example.org/federation").unwrap(),
            EntityId::parse("https://example.org/federation/").unwrap()
        );
        assert_ne!(
            EntityId::parse("https://example.org/a").unwrap(),
            EntityId::parse("https://example.org/b").unwrap()
        );
    }

    #[test]
    fn entity_id_rejects_what_is_not_a_url() {
        assert!(EntityId::parse("ta.example.org").is_err());
        assert!(serde_json::from_str::<EntityId>("\"not a url\"").is_err());
    }
}
