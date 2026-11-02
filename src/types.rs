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

/// A metadata policy, the `metadata_policy` claim of a Subordinate Statement: per Entity Type
/// Identifier, the metadata parameter policies of that Entity Type, per metadata parameter name.
///
/// Reference: OpenID Federation 1.0 - Section 6.1.2 Structure
/// <https://openid.net/specs/openid-federation-1_0.html#section-6.1.2>
pub type MetadataPolicy = HashMap<String, HashMap<String, PolicyOperators>>;

/// The standard metadata policy operators, in their order of application (Section 6.1.3.1).
pub(crate) const STANDARD_POLICY_OPERATORS: &[&str] = &[
    "value",
    "add",
    "default",
    "one_of",
    "subset_of",
    "superset_of",
    "essential",
];

/// A metadata parameter policy: the operators that check or modify one metadata parameter.
///
/// The seven standard operators are fields. `value: Some(Value::Null)` is the operator `value`
/// set to `null`, which removes the parameter; `None` is the operator being absent. Any other
/// operator, which a federation may define (Section 6.1.3.2), is kept in
/// [`additional`](Self::additional) under its name, so it round-trips and a verifier can tell
/// that a critical one was present.
///
/// [`PolicyOperators::validate`] checks the operator values and combinations the specification
/// allows.
///
/// Reference: OpenID Federation 1.0 - Section 6.1.3 Operators
/// <https://openid.net/specs/openid-federation-1_0.html#section-6.1.3>
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PolicyOperators {
    /// `value`: the parameter is assigned this value, or removed when it is `null`
    /// (Section 6.1.3.1.1).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub value: Option<serde_json::Value>,
    /// `add`: these values are added to the parameter (Section 6.1.3.1.2).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub add: Option<serde_json::Value>,
    /// `default`: the parameter is set to this value when it is absent (Section 6.1.3.1.3).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub default: Option<serde_json::Value>,
    /// `one_of`: the parameter must be one of these values (Section 6.1.3.1.4).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub one_of: Option<Vec<serde_json::Value>>,
    /// `subset_of`: the parameter is narrowed to the values it shares with these
    /// (Section 6.1.3.1.5).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub subset_of: Option<Vec<serde_json::Value>>,
    /// `superset_of`: the parameter must contain these values (Section 6.1.3.1.6).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub superset_of: Option<Vec<serde_json::Value>>,
    /// `essential`: when `true`, the parameter must be present (Section 6.1.3.1.7).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub essential: Option<bool>,
    /// Operators other than the standard ones, by name (Section 6.1.3.2).
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Deserializes a member that is present, keeping a JSON `null` as `Some(Value::Null)` for
/// `serde_json::Value` and refusing it for the other types, instead of reading it as absent.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

impl PolicyOperators {
    /// Checks the operator values and combinations the specification allows, the policy
    /// errors of Sections 6.1.3.1.1 to 6.1.3.1.7:
    ///
    /// - `value` is a string, number, boolean, array or `null`; `default` a string, number,
    ///   boolean or array; `add`, `one_of`, `subset_of` and `superset_of` arrays of strings,
    ///   numbers or objects.
    /// - `one_of` combines only with `value`, `default` and `essential`.
    /// - `value` is among `one_of`, its values are a subset of `subset_of` and a superset of
    ///   `superset_of` and of `add`; a `null` `value` has no values.
    /// - `value: null` combines neither with `default` nor with `essential: true`.
    /// - `add` is a subset of `subset_of`, and `subset_of` a superset of `superset_of`.
    /// - An additional operator does not take the name of a standard one.
    ///
    /// Values compare as JSON values. Additional operators are not checked: their rules are the
    /// federation's.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidMetadata`] naming the rule that fails.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.1.3.1 Standard Operators
    /// <https://openid.net/specs/openid-federation-1_0.html#section-6.1.3.1>
    pub fn validate(&self) -> FederationResult<()> {
        if let Some(name) = self
            .additional
            .keys()
            .find(|name| STANDARD_POLICY_OPERATORS.contains(&name.as_str()))
        {
            return Err(policy_error(format!(
                "the additional operator {name:?} has the name of a standard operator"
            )));
        }

        if let Some(value) = &self.value {
            if value.is_object() {
                return Err(policy_error(
                    "value must be a string, number, boolean, array or null".to_string(),
                ));
            }
        }
        if let Some(default) = &self.default {
            if default.is_object() || default.is_null() {
                return Err(policy_error(
                    "default must be a string, number, boolean or array".to_string(),
                ));
            }
        }
        let add = match &self.add {
            Some(serde_json::Value::Array(add)) => Some(add),
            Some(_) => return Err(policy_error("add must be an array".to_string())),
            None => None,
        };
        for (name, values) in [
            ("add", add),
            ("one_of", self.one_of.as_ref()),
            ("subset_of", self.subset_of.as_ref()),
            ("superset_of", self.superset_of.as_ref()),
        ] {
            if let Some(element) = values
                .into_iter()
                .flatten()
                .find(|element| !(element.is_string() || element.is_number() || element.is_object()))
            {
                return Err(policy_error(format!(
                    "{name} must be an array of strings, numbers or objects, but contains {element}"
                )));
            }
        }

        if self.one_of.is_some() {
            for (name, present) in [
                ("add", self.add.is_some()),
                ("subset_of", self.subset_of.is_some()),
                ("superset_of", self.superset_of.is_some()),
            ] {
                if present {
                    return Err(policy_error(format!("one_of must not be combined with {name}")));
                }
            }
        }

        if let Some(value) = &self.value {
            let values = values_of(value);
            if value.is_null() {
                if self.default.is_some() {
                    return Err(policy_error("value null must not be combined with default".to_string()));
                }
                if self.essential == Some(true) {
                    return Err(policy_error(
                        "value null must not be combined with essential true".to_string(),
                    ));
                }
            }
            if let Some(one_of) = &self.one_of {
                if !one_of.contains(value) {
                    return Err(policy_error(format!("value {value} must be among the one_of values")));
                }
            }
            if let Some(subset_of) = &self.subset_of {
                if !is_subset(&values, subset_of) {
                    return Err(policy_error(
                        "the values of value must be a subset of the values of subset_of".to_string(),
                    ));
                }
            }
            if let Some(superset_of) = &self.superset_of {
                if !is_subset(superset_of, &values) {
                    return Err(policy_error(
                        "the values of value must be a superset of the values of superset_of".to_string(),
                    ));
                }
            }
            if let Some(add) = add {
                if !is_subset(add, &values) {
                    return Err(policy_error(
                        "the values of add must be a subset of the values of value".to_string(),
                    ));
                }
            }
        }

        if let (Some(add), Some(subset_of)) = (add, &self.subset_of) {
            if !is_subset(add, subset_of) {
                return Err(policy_error(
                    "the values of add must be a subset of the values of subset_of".to_string(),
                ));
            }
        }
        if let (Some(subset_of), Some(superset_of)) = (&self.subset_of, &self.superset_of) {
            if !is_subset(superset_of, subset_of) {
                return Err(policy_error(
                    "the values of subset_of must be a superset of the values of superset_of".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Whether no operator, standard or additional, is present.
    fn is_empty(&self) -> bool {
        self.value.is_none()
            && self.add.is_none()
            && self.default.is_none()
            && self.one_of.is_none()
            && self.subset_of.is_none()
            && self.superset_of.is_none()
            && self.essential.is_none()
            && self.additional.is_empty()
    }
}

/// Checks a whole metadata policy: every level has at least one member (Section 6.1.2), every
/// metadata parameter policy passes [`PolicyOperators::validate`], and no operator named in
/// `critical_operators` is used.
///
/// `critical_operators` are the operators named in `metadata_policy_crit` that the caller does
/// not understand. A verifier resolving a Trust Chain passes the critical operators it collected
/// from the chain minus those it implements, since a policy that uses a critical operator it
/// cannot process makes the Trust Chain invalid (Sections 6.1.3.2 and 6.1.4.1). This crate
/// implements no additional operator. A producer passes `&[]`: it publishes its own operators.
///
/// # Errors
///
/// [`FederationError::InvalidMetadata`] naming the Entity Type, the metadata parameter and the
/// rule that fails.
///
/// Reference: OpenID Federation 1.0 - Section 6.1.4.1 Resolution
/// <https://openid.net/specs/openid-federation-1_0.html#section-6.1.4.1>
pub fn validate_metadata_policy(policy: &MetadataPolicy, critical_operators: &[String]) -> FederationResult<()> {
    if policy.is_empty() {
        return Err(policy_error(
            "a metadata policy must contain a policy for at least one Entity Type".to_string(),
        ));
    }
    for (entity_type, parameters) in policy {
        if parameters.is_empty() {
            return Err(policy_error(format!(
                "the metadata policy for {entity_type} must contain at least one metadata parameter policy"
            )));
        }
        for (parameter, operators) in parameters {
            let in_context = |error: FederationError| match error {
                FederationError::InvalidMetadata(message) => {
                    FederationError::InvalidMetadata(format!("{entity_type}.{parameter}: {message}"))
                }
                other => other,
            };
            if operators.is_empty() {
                return Err(in_context(policy_error(
                    "a metadata parameter policy must contain at least one operator".to_string(),
                )));
            }
            operators.validate().map_err(in_context)?;
            if let Some(operator) = operators
                .additional
                .keys()
                .find(|name| critical_operators.contains(name))
            {
                return Err(in_context(policy_error(format!(
                    "the critical operator {operator:?} is not understood"
                ))));
            }
        }
    }
    Ok(())
}

fn policy_error(message: String) -> FederationError {
    FederationError::InvalidMetadata(format!("metadata policy error: {message}"))
}

/// The values of a `value` operator: the elements of an array, none for `null`, or the value
/// itself.
fn values_of(value: &serde_json::Value) -> Vec<serde_json::Value> {
    match value {
        serde_json::Value::Array(values) => values.clone(),
        serde_json::Value::Null => Vec::new(),
        single => vec![single.clone()],
    }
}

/// Whether every element of `subset` is in `superset`.
fn is_subset(subset: &[serde_json::Value], superset: &[serde_json::Value]) -> bool {
    subset.iter().all(|element| superset.contains(element))
}

/// Constraints a Superior places on the Subordinates below it, carried in the `constraints` claim
/// of a Subordinate Statement.
///
/// Reference: OpenID Federation 1.0 - Section 6.2 Constraints
/// <https://openid.net/specs/openid-federation-1_0.html#chain_constraints>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraints {
    /// Maximum path length for trust chains
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<u32>,
    /// Naming constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub naming_constraints: Option<HashMap<String, serde_json::Value>>,
    /// The Entity Types acceptable for Subordinate Entities in a Trust Chain. Absent, any Entity
    /// Type is allowed; `federation_entity` is always allowed and never listed.
    ///
    /// Reference: OpenID Federation 1.0 - Section 6.2.3 Entity Type Constraints
    /// <https://openid.net/specs/openid-federation-1_0.html#entity_type_constraints>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_entity_types: Option<Vec<EntityType>>,
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
