//! Metadata structures for OpenID Federation entities.

use crate::jwk::JwkSet;
use crate::{EntityType, FederationError, FederationResult, UrlValidator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Federation entity metadata as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 5.1.1 Federation Entity
/// <https://openid.net/specs/openid-federation-1_0.html#name-federation-entity> and
/// Section 5.2.2 Informational Metadata Parameters
/// <https://openid.net/specs/openid-federation-1_0.html#name-informational-metadata-para>
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FederationEntityMetadata {
    /// Organization name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    /// Display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Keywords
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    /// Administrative contacts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,
    /// Logo URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<Url>,
    /// Policy URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<Url>,
    /// Information URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<Url>,
    /// Organization URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_uri: Option<Url>,
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
    /// Trust Marked Entities Listing endpoint (Section 8.5)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_trust_mark_list_endpoint: Option<Url>,
    /// Trust Mark endpoint (Section 8.6)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_trust_mark_endpoint: Option<Url>,
    /// JWS `alg` values supported for `private_key_jwt` client authentication at the federation
    /// endpoints (Section 8.8); `none` is not allowed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// Client authentication methods of the fetch endpoint (Section 8.8.1); absent means `["none"]`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_fetch_endpoint_auth_methods: Option<Vec<String>>,
    /// Client authentication methods of the list endpoint (Section 8.8.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_list_endpoint_auth_methods: Option<Vec<String>>,
    /// Client authentication methods of the resolve endpoint (Section 8.8.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_resolve_endpoint_auth_methods: Option<Vec<String>>,
    /// Client authentication methods of the Trust Mark Status endpoint (Section 8.8.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_trust_mark_status_endpoint_auth_methods: Option<Vec<String>>,
    /// Client authentication methods of the Trust Marked Entities Listing endpoint (Section 8.8.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_trust_mark_list_endpoint_auth_methods: Option<Vec<String>>,
    /// Client authentication methods of the Trust Mark endpoint (Section 8.8.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_trust_mark_endpoint_auth_methods: Option<Vec<String>>,
    /// Client authentication methods of the historical keys endpoint (Section 8.8.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_historical_keys_endpoint_auth_methods: Option<Vec<String>>,
    /// Additional Federation Entity properties, which Section 5.1.1 allows; kept so they survive
    /// a round trip
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl FederationEntityMetadata {
    /// The federation endpoints this entity publishes, by metadata parameter name.
    pub fn endpoints(&self) -> Vec<(&'static str, &Url)> {
        [
            ("federation_fetch_endpoint", &self.federation_fetch_endpoint),
            ("federation_list_endpoint", &self.federation_list_endpoint),
            ("federation_resolve_endpoint", &self.federation_resolve_endpoint),
            (
                "federation_trust_mark_status_endpoint",
                &self.federation_trust_mark_status_endpoint,
            ),
            (
                "federation_trust_mark_list_endpoint",
                &self.federation_trust_mark_list_endpoint,
            ),
            ("federation_trust_mark_endpoint", &self.federation_trust_mark_endpoint),
            (
                "federation_historical_keys_endpoint",
                &self.federation_historical_keys_endpoint,
            ),
        ]
        .into_iter()
        .filter_map(|(name, url)| url.as_ref().map(|url| (name, url)))
        .collect()
    }

    /// Checks the rules Section 5.1.1 sets for these parameters: every federation endpoint uses
    /// `https` and has no fragment, and `endpoint_auth_signing_alg_values_supported` does not
    /// list `none`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 5.1.1 Federation Entity
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.1>)
    pub fn validate(&self) -> FederationResult<()> {
        for (name, url) in self.endpoints() {
            UrlValidator::validate_endpoint_url(url)
                .map_err(|err| FederationError::InvalidMetadata(format!("{name} {url}: {err}")))?;
        }
        if self
            .endpoint_auth_signing_alg_values_supported
            .iter()
            .flatten()
            .any(|alg| alg == "none")
        {
            return Err(FederationError::InvalidMetadata(
                "endpoint_auth_signing_alg_values_supported must not contain none".to_string(),
            ));
        }
        Ok(())
    }
}

/// OpenID Connect Provider metadata.
///
/// Reference: OpenID Federation 1.0 - Section 5.2 OpenID Provider Metadata
/// <https://openid.net/specs/openid-federation-1_0.html#name-openid-provider-metadata>
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
    /// Signed JWK Set URI (federation-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_jwks_uri: Option<Url>,
    /// Client registration types supported (federation-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_registration_types_supported: Option<Vec<String>>,
    /// Federation registration endpoint (federation-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_registration_endpoint: Option<Url>,
    /// Logo URI (federation-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<Url>,
}

/// OpenID Connect Relying Party metadata.
///
/// Reference: OpenID Federation 1.0 - Section 5.3 Relying Party Metadata
/// <https://openid.net/specs/openid-federation-1_0.html#name-relying-party-metadata>
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
/// <https://openid.net/specs/openid-federation-1_0.html#name-oauth-authorization-server->
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
            EntityType::OpenIdProvider => self.openid_provider.is_some(),
            EntityType::OpenIdRelyingParty => self.openid_relying_party.is_some(),
            EntityType::OauthAuthorizationServer => self.oauth_authorization_server.is_some(),
            EntityType::OauthResource => self.oauth_resource.is_some(),
            EntityType::OauthClient => self.oauth_client.is_some(),
            EntityType::Other(identifier) => self.extensions.contains_key(identifier),
        }
    }
}

impl Default for EntityMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_entity_type_follows_the_metadata_members() {
        let metadata: EntityMetadata = serde_json::from_value(serde_json::json!({
            "federation_entity": {},
            "openid_provider": {
                "issuer": "https://op.example",
                "authorization_endpoint": "https://op.example/authorize",
                "jwks_uri": "https://op.example/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["pairwise"],
                "id_token_signing_alg_values_supported": ["ES256"]
            },
            "openid_relying_party": { "redirect_uris": ["https://rp.example/callback"] },
            "oauth_authorization_server": { "issuer": "https://as.example" },
            "oauth_resource": {},
            "oauth_client": {},
            "wallet_provider": {}
        }))
        .unwrap();
        for entity_type in [
            EntityType::FederationEntity,
            EntityType::OpenIdProvider,
            EntityType::OpenIdRelyingParty,
            EntityType::OauthAuthorizationServer,
            EntityType::OauthResource,
            EntityType::OauthClient,
            EntityType::Other("wallet_provider".to_string()),
        ] {
            assert!(metadata.has_entity_type(&entity_type), "{entity_type:?}");
        }

        let empty = EntityMetadata::new();
        for entity_type in [
            EntityType::FederationEntity,
            EntityType::OpenIdProvider,
            EntityType::OpenIdRelyingParty,
            EntityType::OauthAuthorizationServer,
            EntityType::OauthResource,
            EntityType::OauthClient,
            EntityType::Other("wallet_provider".to_string()),
        ] {
            assert!(!empty.has_entity_type(&entity_type), "{entity_type:?}");
        }
    }
}

#[cfg(test)]
mod federation_entity_tests {
    use super::*;
    use serde_json::json;

    /// OpenID Federation 1.0, Section 5.1.1, Figure 5, plus the `*_auth_methods` parameter of
    /// Section 8.8.1, Figure 44.
    fn example() -> serde_json::Value {
        json!({
            "federation_fetch_endpoint": "https://amanita.caesarea.example.com/federation_fetch",
            "federation_list_endpoint": "https://amanita.caesarea.example.com/federation_list",
            "federation_trust_mark_status_endpoint": "https://amanita.caesarea.example.com/status",
            "federation_trust_mark_list_endpoint": "https://amanita.caesarea.example.com/trust_marked_list",
            "organization_name": "Ovulo Mushroom",
            "organization_uri": "https://amanita.caesarea.example.com",
            "federation_trust_mark_endpoint_auth_methods": ["private_key_jwt"]
        })
    }

    #[test]
    fn specification_example_deserializes_with_every_member_typed() {
        let metadata: FederationEntityMetadata = serde_json::from_value(example()).unwrap();
        assert_eq!(
            metadata.federation_trust_mark_list_endpoint.as_ref().map(Url::as_str),
            Some("https://amanita.caesarea.example.com/trust_marked_list")
        );
        assert_eq!(
            metadata.federation_trust_mark_endpoint_auth_methods,
            Some(vec!["private_key_jwt".to_string()])
        );
        assert!(metadata.additional.is_empty(), "{:?}", metadata.additional);
        metadata.validate().unwrap();
        assert_round_trip(&metadata);
    }

    /// `Url` writes a host-only URL with a trailing `/`, so the comparison is on parsed values.
    fn assert_round_trip(metadata: &FederationEntityMetadata) {
        let again: FederationEntityMetadata = serde_json::from_value(serde_json::to_value(metadata).unwrap()).unwrap();
        assert_eq!(&again, metadata);
    }

    #[test]
    fn every_endpoint_and_auth_parameter_is_typed() {
        let mut value = json!({ "endpoint_auth_signing_alg_values_supported": ["ES256", "RS256"] });
        for endpoint in [
            "federation_fetch_endpoint",
            "federation_list_endpoint",
            "federation_resolve_endpoint",
            "federation_trust_mark_status_endpoint",
            "federation_trust_mark_list_endpoint",
            "federation_trust_mark_endpoint",
            "federation_historical_keys_endpoint",
        ] {
            value[endpoint] = json!(format!("https://ta.example.org/{endpoint}"));
            value[format!("{endpoint}_auth_methods")] = json!(["none"]);
        }
        let metadata: FederationEntityMetadata = serde_json::from_value(value.clone()).unwrap();
        assert!(metadata.additional.is_empty(), "{:?}", metadata.additional);
        assert_eq!(metadata.endpoints().len(), 7);
        metadata.validate().unwrap();
        assert_eq!(serde_json::to_value(&metadata).unwrap(), value);
    }

    #[test]
    fn additional_properties_round_trip() {
        let mut value = example();
        value["ecosystem_profile"] = json!({ "version": 2, "tags": ["a", "b"] });
        let metadata: FederationEntityMetadata = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(metadata.additional["ecosystem_profile"]["version"], json!(2));
        assert_round_trip(&metadata);
        assert_eq!(
            serde_json::to_value(&metadata).unwrap()["ecosystem_profile"],
            value["ecosystem_profile"]
        );
    }

    fn with_fetch_endpoint(url: &str) -> FederationEntityMetadata {
        FederationEntityMetadata {
            federation_fetch_endpoint: Some(Url::parse(url).unwrap()),
            ..Default::default()
        }
    }

    #[test]
    fn endpoint_with_fragment_fails() {
        let error = with_fetch_endpoint("https://ta.example.org/fetch#frag")
            .validate()
            .unwrap_err();
        assert!(error.to_string().contains("federation_fetch_endpoint"), "{error}");
        assert!(UrlValidator::validate_endpoint_url(&Url::parse("https://ta.example.org/x#frag").unwrap()).is_err());
    }

    #[test]
    fn endpoint_with_port_path_and_query_passes() {
        with_fetch_endpoint("https://ta.example.org:8443/federation/fetch?tenant=1")
            .validate()
            .unwrap();
    }

    #[test]
    fn endpoint_without_https_fails() {
        assert!(with_fetch_endpoint("http://ta.example.org/fetch").validate().is_err());
    }

    #[test]
    fn none_as_endpoint_auth_signing_alg_fails() {
        let metadata = FederationEntityMetadata {
            endpoint_auth_signing_alg_values_supported: Some(vec!["ES256".to_string(), "none".to_string()]),
            ..Default::default()
        };
        assert!(metadata.validate().is_err());
    }
}
