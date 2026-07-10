//! Common types used throughout the OpenID Federation implementation.

use crate::{jwt::JwtClaims, JwkSet};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Entity identifier - a URL that uniquely identifies an entity in the federation.
///
/// Reference: OpenID Federation 1.0 - Section 2.1 Entity Identifier
/// https://openid.net/specs/openid-federation-1_0.html#name-entity-identifier
pub type EntityId = Url;

/// JSON Web Key Set as defined in RFC 7517.
/// Note: This is a type alias for the raw JWKS structure.
/// Use the `JwkSet` struct from the `jwk` module for full functionality.
pub type RawJwkSet = HashMap<String, serde_json::Value>;

/// Generic metadata type for flexibility.
pub type Metadata = HashMap<String, serde_json::Value>;

/// Entity types as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 2.2 Entity Types
/// https://openid.net/specs/openid-federation-1_0.html#name-entity-types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    /// Federation entity
    FederationEntity,
    /// OpenID Connect Provider
    OpenkConnectProvider,
    /// OpenID Connect Relying Party
    OpenkConnectRelyingParty,
    /// OAuth Authorization Server
    OauthAuthorizationServer,
    /// OAuth Protected Resource
    OauthProtectedResource,
    /// OAuth Client
    OauthClient,
}

/// Trust mark as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 6 Trust Marks
/// https://openid.net/specs/openid-federation-1_0.html#name-trust-marks
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

/// Policy language as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 7 Metadata Policy
/// https://openid.net/specs/openid-federation-1_0.html#name-metadata-policy
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyLanguage {
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

/// Federation entity configuration constraints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraints {
    /// Maximum path length for trust chains
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<u32>,
    /// Naming constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub naming_constraints: Option<HashMap<String, serde_json::Value>>,
    /// Allowed leaf entity types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_leaf_entity_types: Option<Vec<EntityType>>,
}
