//! Common types used throughout the OpenID Federation implementation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Entity identifier - a URL that uniquely identifies an entity in the federation.
pub type EntityId = Url;

/// JSON Web Key Set as defined in RFC 7517.
/// Note: This is a type alias for the raw JWKS structure.
/// Use the `JwkSet` struct from the `jwk` module for full functionality.
pub type RawJwkSet = HashMap<String, serde_json::Value>;

/// Generic metadata type for flexibility.
pub type Metadata = HashMap<String, serde_json::Value>;

/// Authority hints - URLs of immediate superior entities.
pub type AuthorityHints = Vec<EntityId>;

/// Entity types as defined in the OpenID Federation specification.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustMark {
    /// Trust mark identifier
    pub id: String,
    /// Trust mark issuer
    pub trust_mark_issuer: EntityId,
    /// Trust mark subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<EntityId>,
    /// Issued at timestamp
    pub iat: DateTime<Utc>,
    /// Expiration timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<DateTime<Utc>>,
}

/// Policy language as defined in the OpenID Federation specification.
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
