//! Metadata structures for OpenID Federation entities.

use crate::jwk::JwkSet;
use crate::EntityType;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Federation entity metadata as defined in the OpenID Federation specification.
/// 
/// Reference: OpenID Federation 1.0 - Section 5.1 Federation Entity Metadata
/// https://openid.net/specs/openid-federation-1_0.html#name-federation-entity-metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationEntityMetadata {
    /// Organization name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    /// Homepage URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage_uri: Option<Url>,
    /// Policy URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<Url>,
    /// Logo URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<Url>,
    /// Administrative contacts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    /// Federation fetch endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_fetch_endpoint: Option<Url>,
    /// Federation list endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_list_endpoint: Option<Url>,
    /// Federation resolve endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_resolve_endpoint: Option<Url>,
    /// Federation trust mark status endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_trust_mark_status_endpoint: Option<Url>,
    /// Federation historical keys endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_historical_keys_endpoint: Option<Url>,
}

/// OpenID Connect Provider metadata.
/// 
/// Reference: OpenID Federation 1.0 - Section 5.2 OpenID Provider Metadata
/// https://openid.net/specs/openid-federation-1_0.html#name-openid-provider-metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenIdConnectProviderMetadata {
    /// Issuer identifier
    pub issuer: Url,
    /// Authorization endpoint
    pub authorization_endpoint: Url,
    /// Token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,
    /// UserInfo endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<Url>,
    /// JWK Set URI
    pub jwks_uri: Url,
    /// Registration endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<Url>,
    /// Supported scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// Supported response types
    pub response_types_supported: Vec<String>,
    /// Supported response modes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,
    /// Supported grant types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    /// Supported ACR values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,
    /// Supported subject types
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported ID token encryption algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    /// Supported ID token encryption encoding algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    /// Supported UserInfo signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported UserInfo encryption algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    /// Supported UserInfo encryption encoding algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    /// Supported request object signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported request object encryption algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    /// Supported request object encryption encoding algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    /// Supported token endpoint authentication methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported token endpoint authentication signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported display values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_values_supported: Option<Vec<String>>,
    /// Supported claim types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_types_supported: Option<Vec<String>>,
    /// Supported claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    /// Service documentation URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<Url>,
    /// Claims locales supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_locales_supported: Option<Vec<String>>,
    /// UI locales supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,
    /// Claims parameter supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_parameter_supported: Option<bool>,
    /// Request parameter supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_parameter_supported: Option<bool>,
    /// Request URI parameter supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_parameter_supported: Option<bool>,
    /// Require request URI registration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_request_uri_registration: Option<bool>,
    /// Operation policy URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<Url>,
    /// Operation terms of service URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<Url>,
}

/// OpenID Connect Relying Party metadata.
/// 
/// Reference: OpenID Federation 1.0 - Section 5.3 Relying Party Metadata
/// https://openid.net/specs/openid-federation-1_0.html#name-relying-party-metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenIdConnectRelyingPartyMetadata {
    /// Redirect URIs
    pub redirect_uris: Vec<Url>,
    /// Response types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,
    /// Grant types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,
    /// Application type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    /// Administrative contacts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    /// Client name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Logo URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<Url>,
    /// Client URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<Url>,
    /// Policy URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<Url>,
    /// Terms of service URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<Url>,
    /// JWK Set URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,
    /// JWK Set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<JwkSet>,
    /// Sector identifier URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<Url>,
    /// Subject type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    /// ID token signed response algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
    /// ID token encrypted response algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,
    /// ID token encrypted response encoding algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,
    /// UserInfo signed response algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,
    /// UserInfo encrypted response algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,
    /// UserInfo encrypted response encoding algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,
    /// Request object signing algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,
    /// Request object encryption algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,
    /// Request object encryption encoding algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,
    /// Token endpoint authentication method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    /// Token endpoint authentication signing algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,
    /// Default maximum age
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<u64>,
    /// Require authentication time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,
    /// Default ACR values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_acr_values: Option<Vec<String>>,
    /// Initiate login URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<Url>,
    /// Request URIs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<Vec<Url>>,
}

/// OAuth Authorization Server metadata.
/// 
/// Reference: OpenID Federation 1.0 - Section 5.4 OAuth Authorization Server Metadata
/// https://openid.net/specs/openid-federation-1_0.html#name-oauth-authorization-server-
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OauthAuthorizationServerMetadata {
    /// Issuer identifier
    pub issuer: Url,
    /// Authorization endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<Url>,
    /// Token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,
    /// JWK Set URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,
    /// Registration endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<Url>,
    /// Supported scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// Supported response types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types_supported: Option<Vec<String>>,
    /// Supported response modes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,
    /// Supported grant types
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,
    /// Supported token endpoint authentication methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported token endpoint authentication signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Service documentation URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<Url>,
    /// UI locales supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,
    /// Operation policy URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<Url>,
    /// Operation terms of service URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<Url>,
    /// Revocation endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<Url>,
    /// Supported revocation endpoint authentication methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported revocation endpoint authentication signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Introspection endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<Url>,
    /// Supported introspection endpoint authentication methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported introspection endpoint authentication signing algorithms
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported code challenge methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Comprehensive metadata structure that can contain metadata for any entity type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityMetadata {
    /// Federation entity metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_entity: Option<FederationEntityMetadata>,
    /// OpenID Connect Provider metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openid_provider: Option<OpenIdConnectProviderMetadata>,
    /// OpenID Connect Relying Party metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openid_relying_party: Option<OpenIdConnectRelyingPartyMetadata>,
    /// OAuth Authorization Server metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_authorization_server: Option<OauthAuthorizationServerMetadata>,
    /// OAuth Protected Resource metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_resource: Option<HashMap<String, serde_json::Value>>,
    /// OAuth Client metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_client: Option<HashMap<String, serde_json::Value>>,
    /// Custom metadata extensions
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

impl EntityMetadata {
    /// Create a new empty EntityMetadata.
    pub fn new() -> Self {
        Self {
            federation_entity: None,
            openid_provider: None,
            openid_relying_party: None,
            oauth_authorization_server: None,
            oauth_resource: None,
            oauth_client: None,
            extensions: HashMap::new(),
        }
    }

    /// Check if the metadata contains information for a specific entity type.
    pub fn has_entity_type(&self, entity_type: &EntityType) -> bool {
        match entity_type {
            EntityType::FederationEntity => self.federation_entity.is_some(),
            EntityType::OpenkConnectProvider => self.openid_provider.is_some(),
            EntityType::OpenkConnectRelyingParty => self.openid_relying_party.is_some(),
            EntityType::OauthAuthorizationServer => self.oauth_authorization_server.is_some(),
            EntityType::OauthProtectedResource => self.oauth_resource.is_some(),
            EntityType::OauthClient => self.oauth_client.is_some(),
        }
    }
}

impl Default for EntityMetadata {
    fn default() -> Self {
        Self::new()
    }
}
