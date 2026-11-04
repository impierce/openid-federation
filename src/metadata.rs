//! Metadata structures for OpenID Federation entities.

use crate::jwk::JwkSet;
use crate::{EntityId, EntityType, FederationError, FederationResult, UrlValidator};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// The parameters `FederationEntityMetadata` has a field for. `additional` must not repeat them.
const FEDERATION_ENTITY_PARAMETERS: [&str; 24] = [
    "organization_name",
    "display_name",
    "description",
    "keywords",
    "contacts",
    "logo_uri",
    "policy_uri",
    "information_uri",
    "organization_uri",
    "federation_fetch_endpoint",
    "federation_list_endpoint",
    "federation_resolve_endpoint",
    "federation_trust_mark_status_endpoint",
    "federation_historical_keys_endpoint",
    "federation_trust_mark_list_endpoint",
    "federation_trust_mark_endpoint",
    "endpoint_auth_signing_alg_values_supported",
    "federation_fetch_endpoint_auth_methods",
    "federation_list_endpoint_auth_methods",
    "federation_resolve_endpoint_auth_methods",
    "federation_trust_mark_status_endpoint_auth_methods",
    "federation_trust_mark_list_endpoint_auth_methods",
    "federation_trust_mark_endpoint_auth_methods",
    "federation_historical_keys_endpoint_auth_methods",
];

/// The parameters `OpenIdConnectProviderMetadata` has a field for. `additional` must not repeat them.
const OPENID_PROVIDER_PARAMETERS: [&str; 39] = [
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "scopes_supported",
    "response_types_supported",
    "response_modes_supported",
    "grant_types_supported",
    "acr_values_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "id_token_encryption_alg_values_supported",
    "id_token_encryption_enc_values_supported",
    "userinfo_signing_alg_values_supported",
    "userinfo_encryption_alg_values_supported",
    "userinfo_encryption_enc_values_supported",
    "request_object_signing_alg_values_supported",
    "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc_values_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "display_values_supported",
    "claim_types_supported",
    "claims_supported",
    "service_documentation",
    "claims_locales_supported",
    "ui_locales_supported",
    "claims_parameter_supported",
    "request_parameter_supported",
    "request_uri_parameter_supported",
    "require_request_uri_registration",
    "op_policy_uri",
    "op_tos_uri",
    "signed_jwks_uri",
    "client_registration_types_supported",
    "federation_registration_endpoint",
    "logo_uri",
];

/// The parameters `OpenIdConnectRelyingPartyMetadata` has a field for. `additional` must not repeat them.
const OPENID_RELYING_PARTY_PARAMETERS: [&str; 30] = [
    "redirect_uris",
    "response_types",
    "grant_types",
    "application_type",
    "contacts",
    "client_name",
    "logo_uri",
    "client_uri",
    "policy_uri",
    "tos_uri",
    "jwks_uri",
    "jwks",
    "sector_identifier_uri",
    "subject_type",
    "id_token_signed_response_alg",
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc",
    "userinfo_signed_response_alg",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc",
    "request_object_signing_alg",
    "request_object_encryption_alg",
    "request_object_encryption_enc",
    "token_endpoint_auth_method",
    "token_endpoint_auth_signing_alg",
    "default_max_age",
    "require_auth_time",
    "default_acr_values",
    "initiate_login_uri",
    "request_uris",
];

/// The parameters `OauthAuthorizationServerMetadata` has a field for. `additional` must not repeat them.
const OAUTH_AUTHORIZATION_SERVER_PARAMETERS: [&str; 22] = [
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "registration_endpoint",
    "scopes_supported",
    "response_types_supported",
    "response_modes_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "service_documentation",
    "ui_locales_supported",
    "op_policy_uri",
    "op_tos_uri",
    "revocation_endpoint",
    "revocation_endpoint_auth_methods_supported",
    "revocation_endpoint_auth_signing_alg_values_supported",
    "introspection_endpoint",
    "introspection_endpoint_auth_methods_supported",
    "introspection_endpoint_auth_signing_alg_values_supported",
    "code_challenge_methods_supported",
];

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
    /// list `none`. `additional` must not repeat a parameter the struct has a field for, so a
    /// value placed there in code cannot bypass these checks or serialize as a duplicate member.
    ///
    /// Reference: OpenID Federation 1.0 - Section 5.1.1 Federation Entity
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.1>)
    pub fn validate(&self) -> FederationResult<()> {
        if let Some(name) = self
            .additional
            .keys()
            .find(|name| FEDERATION_ENTITY_PARAMETERS.contains(&name.as_str()))
        {
            return Err(FederationError::InvalidMetadata(format!(
                "{name} is a typed federation_entity parameter and must not appear in additional"
            )));
        }
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
    /// Issuer identifier, kept as spelled: OpenID Connect compares it with `iss` as an exact
    /// string, and a parsed URL would gain a trailing `/` after a bare host.
    pub issuer: EntityId,
    /// Authorization endpoint
    pub authorization_endpoint: Url,
    /// Token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<Url>,
    /// UserInfo endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<Url>,
    /// JWK Set URI. Optional: an OP may publish its keys with `jwks` or `signed_jwks_uri`
    /// instead (Section 5.2.1.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,
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
    /// Metadata parameters this struct has no field for, by name. Section 5.1.3 leaves the
    /// parameters of this Entity Type open, and Section 5.2 adds common ones; they are kept so
    /// that they survive a round trip and a metadata policy can apply to them.
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl OpenIdConnectProviderMetadata {
    /// Checks that [`additional`](Self::additional) repeats no parameter this struct has a field
    /// for. Deserialization never puts one there; code can, and the serialized metadata would
    /// then carry the parameter twice.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidMetadata`] naming the parameter.
    ///
    /// Reference: OpenID Federation 1.0 - Section 5.1.3
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.3>)
    pub fn validate(&self) -> FederationResult<()> {
        reject_typed_parameters_in_additional("openid_provider", &OPENID_PROVIDER_PARAMETERS, &self.additional)
    }
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
    /// Metadata parameters this struct has no field for, by name. Section 5.1.2 leaves the
    /// parameters of this Entity Type open, and Section 5.2 adds common ones; they are kept so
    /// that they survive a round trip and a metadata policy can apply to them.
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl OpenIdConnectRelyingPartyMetadata {
    /// Checks that [`additional`](Self::additional) repeats no parameter this struct has a field
    /// for. Deserialization never puts one there; code can, and the serialized metadata would
    /// then carry the parameter twice.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidMetadata`] naming the parameter.
    ///
    /// Reference: OpenID Federation 1.0 - Section 5.1.2
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.2>)
    pub fn validate(&self) -> FederationResult<()> {
        reject_typed_parameters_in_additional(
            "openid_relying_party",
            &OPENID_RELYING_PARTY_PARAMETERS,
            &self.additional,
        )
    }
}

/// OAuth Authorization Server metadata.
///
/// Reference: OpenID Federation 1.0 - Section 5.4 OAuth Authorization Server Metadata
/// <https://openid.net/specs/openid-federation-1_0.html#name-oauth-authorization-server->
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OauthAuthorizationServerMetadata {
    /// Issuer identifier, kept as spelled. It MUST match the Entity Identifier (Section 5.1.4),
    /// and a parsed URL would gain a trailing `/` after a bare host.
    pub issuer: EntityId,
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
    /// Metadata parameters this struct has no field for, by name. Section 5.1.4 leaves the
    /// parameters of this Entity Type open, and Section 5.2 adds common ones; they are kept so
    /// that they survive a round trip and a metadata policy can apply to them.
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl OauthAuthorizationServerMetadata {
    /// Checks that [`additional`](Self::additional) repeats no parameter this struct has a field
    /// for. Deserialization never puts one there; code can, and the serialized metadata would
    /// then carry the parameter twice.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidMetadata`] naming the parameter.
    ///
    /// Reference: OpenID Federation 1.0 - Section 5.1.4
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-5.1.4>)
    pub fn validate(&self) -> FederationResult<()> {
        reject_typed_parameters_in_additional(
            "oauth_authorization_server",
            &OAUTH_AUTHORIZATION_SERVER_PARAMETERS,
            &self.additional,
        )
    }
}

/// Refuses an `additional` map that repeats a parameter its struct has a field for: serialized,
/// the metadata would carry the parameter twice, which a JSON object must not (RFC 8259) and which
/// this crate refuses when it reads a statement.
fn reject_typed_parameters_in_additional(
    entity_type: &str,
    typed: &[&str],
    additional: &HashMap<String, serde_json::Value>,
) -> FederationResult<()> {
    match additional.keys().find(|name| typed.contains(&name.as_str())) {
        Some(name) => Err(FederationError::InvalidMetadata(format!(
            "{name} is a typed {entity_type} parameter and must not appear in additional"
        ))),
        None => Ok(()),
    }
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
    /// Refuses an `additional` member of a typed Entity Type that repeats one of its typed
    /// parameters. Serialized, it would replace the typed value.
    pub(crate) fn reject_typed_parameters_in_additional(&self) -> FederationResult<()> {
        if let Some(federation_entity) = &self.federation_entity {
            reject_typed_parameters_in_additional(
                "federation_entity",
                &FEDERATION_ENTITY_PARAMETERS,
                &federation_entity.additional,
            )?;
        }
        if let Some(openid_provider) = &self.openid_provider {
            reject_typed_parameters_in_additional(
                "openid_provider",
                &OPENID_PROVIDER_PARAMETERS,
                &openid_provider.additional,
            )?;
        }
        if let Some(openid_relying_party) = &self.openid_relying_party {
            reject_typed_parameters_in_additional(
                "openid_relying_party",
                &OPENID_RELYING_PARTY_PARAMETERS,
                &openid_relying_party.additional,
            )?;
        }
        if let Some(oauth_authorization_server) = &self.oauth_authorization_server {
            reject_typed_parameters_in_additional(
                "oauth_authorization_server",
                &OAUTH_AUTHORIZATION_SERVER_PARAMETERS,
                &oauth_authorization_server.additional,
            )?;
        }
        Ok(())
    }

    /// Runs `validate` on each typed Entity Type member: `federation_entity`, `openid_provider`,
    /// `openid_relying_party` and `oauth_authorization_server`. Each refuses an `additional`
    /// member that repeats one of its typed parameters, which would appear twice in signed JSON
    /// or, once serialized, replace the typed value.
    pub(crate) fn validate_typed_members(&self) -> FederationResult<()> {
        if let Some(federation_entity) = &self.federation_entity {
            federation_entity.validate()?;
        }
        if let Some(openid_provider) = &self.openid_provider {
            openid_provider.validate()?;
        }
        if let Some(openid_relying_party) = &self.openid_relying_party {
            openid_relying_party.validate()?;
        }
        if let Some(oauth_authorization_server) = &self.oauth_authorization_server {
            oauth_authorization_server.validate()?;
        }
        Ok(())
    }

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

    /// The Entity Types this metadata has a member for, the standard ones first, in the order of
    /// Section 5.1, then the others by name. A member whose value is not a JSON object is not
    /// metadata of an Entity Type and is left out.
    ///
    /// Reference: OpenID Federation 1.0 - Section 5.1 Entity Type Identifiers
    /// <https://openid.net/specs/openid-federation-1_0.html#section-5.1>
    pub fn entity_types(&self) -> Vec<EntityType> {
        let mut others: Vec<&String> = self
            .extensions
            .iter()
            .filter(|(_, metadata)| metadata.is_object())
            .map(|(name, _)| name)
            .collect();
        others.sort();
        [
            EntityType::FederationEntity,
            EntityType::OpenIdRelyingParty,
            EntityType::OpenIdProvider,
            EntityType::OauthAuthorizationServer,
            EntityType::OauthClient,
            EntityType::OauthResource,
        ]
        .into_iter()
        .filter(|entity_type| self.has_entity_type(entity_type))
        .chain(others.into_iter().map(|name| EntityType::Other(name.clone())))
        .collect()
    }

    /// Check if the metadata contains information for a specific entity type: a member named
    /// after it, with a JSON object as its value for an Entity Type defined elsewhere.
    pub fn has_entity_type(&self, entity_type: &EntityType) -> bool {
        match entity_type {
            EntityType::FederationEntity => self.federation_entity.is_some(),
            EntityType::OpenIdProvider => self.openid_provider.is_some(),
            EntityType::OpenIdRelyingParty => self.openid_relying_party.is_some(),
            EntityType::OauthAuthorizationServer => self.oauth_authorization_server.is_some(),
            EntityType::OauthResource => self.oauth_resource.is_some(),
            EntityType::OauthClient => self.oauth_client.is_some(),
            // The metadata of an Entity Type is a JSON object (Section 5).
            EntityType::Other(identifier) => self
                .extensions
                .get(identifier)
                .is_some_and(serde_json::Value::is_object),
        }
    }
}

impl Default for EntityMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// The `metadata` claim of an Entity Statement: per Entity Type, the metadata parameters the
/// statement states (Section 3.1.1).
///
/// A member need not hold every parameter its Entity Type requires. An Entity Configuration may
/// publish `{}` for an Entity Type whose Immediate Superior supplies the parameters, and a
/// Subordinate Statement may state only some parameters, which override the subject's own. Only
/// the Resolved Metadata of a Trust Chain, [`TrustChain::metadata`](crate::TrustChain::metadata),
/// is complete [`EntityMetadata`].
///
/// `federation_entity` is held as [`FederationEntityMetadata`], since all its parameters are
/// optional and discovery reads its endpoints. Every other member is held as the JSON object it
/// is; [`to_entity_metadata`](Self::to_entity_metadata) reads them as their types.
///
/// Reference: OpenID Federation 1.0 - Section 3.1.1
/// <https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StatementMetadata {
    federation_entity: Option<FederationEntityMetadata>,
    others: std::collections::BTreeMap<String, serde_json::Map<String, serde_json::Value>>,
}

impl StatementMetadata {
    /// Metadata without any Entity Type.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads the members of a `metadata` claim. Each must be a JSON object, and
    /// `federation_entity` must read as [`FederationEntityMetadata`].
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidMetadata`] naming the member that is not a JSON object or the
    /// `federation_entity` parameter that does not fit its type.
    pub fn from_json(members: serde_json::Map<String, serde_json::Value>) -> FederationResult<Self> {
        let mut metadata = Self::new();
        for (entity_type, parameters) in members {
            let serde_json::Value::Object(parameters) = parameters else {
                return Err(FederationError::InvalidMetadata(format!(
                    "the metadata of {entity_type} is not a JSON object"
                )));
            };
            metadata = metadata.with_entity_type(&entity_type, parameters)?;
        }
        Ok(metadata)
    }

    /// Sets the parameters of `entity_type`, replacing any it had.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidMetadata`] when `entity_type` is `federation_entity` and
    /// `parameters` do not read as [`FederationEntityMetadata`].
    pub fn with_entity_type(
        mut self,
        entity_type: &str,
        parameters: serde_json::Map<String, serde_json::Value>,
    ) -> FederationResult<Self> {
        if entity_type == "federation_entity" {
            let federation_entity = serde_json::from_value(serde_json::Value::Object(parameters))
                .map_err(|error| FederationError::InvalidMetadata(format!("federation_entity: {error}")))?;
            self.federation_entity = Some(federation_entity);
        } else {
            self.others.insert(entity_type.to_string(), parameters);
        }
        Ok(self)
    }

    /// Sets the `federation_entity` metadata.
    pub fn with_federation_entity(mut self, federation_entity: FederationEntityMetadata) -> Self {
        self.federation_entity = Some(federation_entity);
        self
    }

    /// The `federation_entity` metadata, if the statement has it.
    pub fn federation_entity(&self) -> Option<&FederationEntityMetadata> {
        self.federation_entity.as_ref()
    }

    /// The parameters stated for `entity_type`, if any.
    pub fn parameters(&self, entity_type: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
        if entity_type == "federation_entity" {
            return self.federation_entity.as_ref().map(federation_entity_json);
        }
        self.others.get(entity_type).cloned()
    }

    /// Whether the statement has a member for `entity_type`.
    pub fn has_entity_type(&self, entity_type: &EntityType) -> bool {
        match entity_type {
            EntityType::FederationEntity => self.federation_entity.is_some(),
            other => self.others.contains_key(&entity_type_identifier(other)),
        }
    }

    /// The Entity Types the statement has a member for, the standard ones first, in the order of
    /// Section 5.1, then the others by name.
    pub fn entity_types(&self) -> Vec<EntityType> {
        let standard = [
            EntityType::FederationEntity,
            EntityType::OpenIdRelyingParty,
            EntityType::OpenIdProvider,
            EntityType::OauthAuthorizationServer,
            EntityType::OauthClient,
            EntityType::OauthResource,
        ];
        let standard_names: Vec<String> = standard.iter().map(entity_type_identifier).collect();
        let others = self
            .others
            .keys()
            .filter(|name| !standard_names.contains(name))
            .map(|name| EntityType::Other(name.clone()));
        standard
            .iter()
            .filter(|entity_type| self.has_entity_type(entity_type))
            .cloned()
            .chain(others)
            .collect()
    }

    /// The metadata as a JSON object, one member per Entity Type.
    pub fn to_json(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut json = serde_json::Map::new();
        if let Some(federation_entity) = &self.federation_entity {
            json.insert(
                "federation_entity".to_string(),
                serde_json::Value::Object(federation_entity_json(federation_entity)),
            );
        }
        for (entity_type, parameters) in &self.others {
            json.insert(entity_type.clone(), serde_json::Value::Object(parameters.clone()));
        }
        json
    }

    /// Reads every member as its Entity Type's metadata.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidMetadata`] when a member does not fit its type, for example
    /// `openid_relying_party` metadata without `redirect_uris`, which a Subordinate Statement
    /// or an Entity Configuration whose Superior supplies it may well state.
    pub fn to_entity_metadata(&self) -> FederationResult<EntityMetadata> {
        serde_json::from_value(serde_json::Value::Object(self.to_json()))
            .map_err(|error| FederationError::InvalidMetadata(format!("the metadata is not complete: {error}")))
    }
}

/// `federation_entity` metadata as a JSON object.
fn federation_entity_json(federation_entity: &FederationEntityMetadata) -> serde_json::Map<String, serde_json::Value> {
    match serde_json::to_value(federation_entity) {
        Ok(serde_json::Value::Object(json)) => json,
        // A struct of optional fields and a map always serializes to an object.
        _ => serde_json::Map::new(),
    }
}

/// The Entity Type Identifier of `entity_type`, such as `openid_provider`.
pub(crate) fn entity_type_identifier(entity_type: &EntityType) -> String {
    match serde_json::to_value(entity_type) {
        Ok(serde_json::Value::String(identifier)) => identifier,
        _ => String::new(),
    }
}

impl TryFrom<EntityMetadata> for StatementMetadata {
    type Error = FederationError;

    /// The typed metadata as a statement states it. No typed member's `additional` may repeat one
    /// of its typed parameters, which would otherwise replace it. Rules on values, such as
    /// `https` federation endpoints, are checked when the statement is signed.
    fn try_from(metadata: EntityMetadata) -> FederationResult<Self> {
        metadata.reject_typed_parameters_in_additional()?;
        match serde_json::to_value(&metadata) {
            Ok(serde_json::Value::Object(members)) => Self::from_json(members),
            Ok(_) => Err(FederationError::InvalidMetadata(
                "metadata is not a JSON object".to_string(),
            )),
            Err(error) => Err(FederationError::InvalidMetadata(format!(
                "metadata does not serialize: {error}"
            ))),
        }
    }
}

impl Serialize for StatementMetadata {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StatementMetadata {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let members = serde_json::Map::deserialize(deserializer)?;
        Self::from_json(members).map_err(serde::de::Error::custom)
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
    fn every_endpoint_rejects_fragment_and_http() {
        for endpoint in [
            "federation_fetch_endpoint",
            "federation_list_endpoint",
            "federation_resolve_endpoint",
            "federation_trust_mark_status_endpoint",
            "federation_trust_mark_list_endpoint",
            "federation_trust_mark_endpoint",
            "federation_historical_keys_endpoint",
        ] {
            for bad in ["https://ta.example.org/x#frag", "http://ta.example.org/x"] {
                let mut value = json!({});
                value[endpoint] = json!(bad);
                let metadata: FederationEntityMetadata = serde_json::from_value(value).unwrap();
                let error = metadata.validate().unwrap_err();
                assert!(error.to_string().contains(endpoint), "{error}");
            }
        }
    }

    #[test]
    fn typed_parameter_in_additional_fails() {
        // Deserialization never puts a typed parameter into `additional`; code can.
        for name in FEDERATION_ENTITY_PARAMETERS {
            let mut metadata = FederationEntityMetadata::default();
            metadata
                .additional
                .insert(name.to_string(), json!("http://ta.example.org/x"));
            let error = metadata.validate().unwrap_err();
            assert!(error.to_string().contains(name), "{error}");
        }
    }

    #[test]
    fn every_field_is_a_listed_parameter() {
        // Keeps `FEDERATION_ENTITY_PARAMETERS` in step with the struct: a fully populated value
        // serializes to exactly the listed names.
        let mut value = json!({});
        for name in FEDERATION_ENTITY_PARAMETERS {
            value[name] = match name {
                "keywords" | "contacts" | "endpoint_auth_signing_alg_values_supported" => json!(["x"]),
                name if name.ends_with("_auth_methods") => json!(["none"]),
                name if name.ends_with("_uri") || name.ends_with("_endpoint") => json!("https://ta.example.org/x"),
                _ => json!("x"),
            };
        }
        let metadata: FederationEntityMetadata = serde_json::from_value(value).unwrap();
        assert!(metadata.additional.is_empty(), "{:?}", metadata.additional);
        let serialized = serde_json::to_value(&metadata).unwrap();
        assert_eq!(
            serialized.as_object().unwrap().len(),
            FEDERATION_ENTITY_PARAMETERS.len()
        );
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

#[cfg(test)]
mod typed_parameter_tests {
    use super::*;
    use serde_json::json;

    /// The smallest metadata of each typed Entity Type, with every required parameter.
    fn minimal(entity_type: &str) -> serde_json::Value {
        match entity_type {
            "openid_provider" => json!({
                "issuer": "https://op.example.org",
                "authorization_endpoint": "https://op.example.org/authorize",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["ES256"]
            }),
            "openid_relying_party" => json!({ "redirect_uris": ["https://rp.example.org/callback"] }),
            "oauth_authorization_server" => json!({ "issuer": "https://as.example.org" }),
            other => panic!("{other}"),
        }
    }

    fn parse<T: serde::de::DeserializeOwned>(
        entity_type: &str,
        name: &str,
        value: serde_json::Value,
    ) -> Result<T, serde_json::Error> {
        let mut json = minimal(entity_type);
        json[name] = value;
        serde_json::from_value(json)
    }

    #[test]
    fn every_listed_parameter_is_a_field() {
        // A JSON object fits none of the typed fields, so a listed name that is a field fails to
        // parse; a name that is not a field would land in `additional`.
        let probe = json!({ "probe": true });
        for name in OPENID_PROVIDER_PARAMETERS {
            assert!(
                parse::<OpenIdConnectProviderMetadata>("openid_provider", name, probe.clone()).is_err(),
                "{name}"
            );
        }
        for name in OPENID_RELYING_PARTY_PARAMETERS {
            assert!(
                parse::<OpenIdConnectRelyingPartyMetadata>("openid_relying_party", name, probe.clone()).is_err(),
                "{name}"
            );
        }
        for name in OAUTH_AUTHORIZATION_SERVER_PARAMETERS {
            assert!(
                parse::<OauthAuthorizationServerMetadata>("oauth_authorization_server", name, probe.clone()).is_err(),
                "{name}"
            );
        }
        let kept: OpenIdConnectProviderMetadata = parse("openid_provider", "organization_name", probe.clone()).unwrap();
        assert_eq!(kept.additional.get("organization_name"), Some(&probe));
    }

    #[test]
    fn typed_parameter_in_additional_fails() {
        // Deserialization never puts a typed parameter into `additional`; code can.
        let mut op: OpenIdConnectProviderMetadata = serde_json::from_value(minimal("openid_provider")).unwrap();
        op.validate().unwrap();
        op.additional
            .insert("issuer".to_string(), json!("https://other.example.org"));
        assert!(op
            .validate()
            .unwrap_err()
            .to_string()
            .contains("issuer is a typed openid_provider parameter"));

        let mut rp: OpenIdConnectRelyingPartyMetadata =
            serde_json::from_value(minimal("openid_relying_party")).unwrap();
        rp.additional.insert("scope".to_string(), json!("openid"));
        rp.validate().unwrap();
        rp.additional.insert("redirect_uris".to_string(), json!([]));
        assert!(rp.validate().unwrap_err().to_string().contains("redirect_uris"));

        let mut server: OauthAuthorizationServerMetadata =
            serde_json::from_value(minimal("oauth_authorization_server")).unwrap();
        server
            .additional
            .insert("token_endpoint".to_string(), json!("https://as.example.org/token"));
        assert!(server.validate().unwrap_err().to_string().contains("token_endpoint"));
    }

    /// The names of a struct's typed fields. The pattern names every field but `additional`, so
    /// a field added to the struct fails to compile here until it is named, and then
    /// `every_field_is_a_listed_parameter` fails until it is also listed.
    macro_rules! listed_fields {
        ($ty:ident { $($field:ident),* $(,)? }) => {{
            #[allow(dead_code)]
            fn exhaustive(value: $ty) {
                let $ty { $($field: _,)* additional: _ } = value;
            }
            [$(stringify!($field)),*]
        }};
    }

    fn assert_listed(entity_type: &str, listed: &[&str], fields: &[&str]) {
        let mut listed = listed.to_vec();
        let mut fields = fields.to_vec();
        listed.sort_unstable();
        fields.sort_unstable();
        assert_eq!(listed, fields, "{entity_type}");
    }

    #[test]
    fn every_field_is_a_listed_parameter() {
        // None of the structs renames a field, so a field name is its parameter name.
        assert_listed(
            "OpenIdConnectProviderMetadata",
            &OPENID_PROVIDER_PARAMETERS,
            &listed_fields!(OpenIdConnectProviderMetadata {
                issuer,
                authorization_endpoint,
                token_endpoint,
                userinfo_endpoint,
                jwks_uri,
                registration_endpoint,
                scopes_supported,
                response_types_supported,
                response_modes_supported,
                grant_types_supported,
                acr_values_supported,
                subject_types_supported,
                id_token_signing_alg_values_supported,
                id_token_encryption_alg_values_supported,
                id_token_encryption_enc_values_supported,
                userinfo_signing_alg_values_supported,
                userinfo_encryption_alg_values_supported,
                userinfo_encryption_enc_values_supported,
                request_object_signing_alg_values_supported,
                request_object_encryption_alg_values_supported,
                request_object_encryption_enc_values_supported,
                token_endpoint_auth_methods_supported,
                token_endpoint_auth_signing_alg_values_supported,
                display_values_supported,
                claim_types_supported,
                claims_supported,
                service_documentation,
                claims_locales_supported,
                ui_locales_supported,
                claims_parameter_supported,
                request_parameter_supported,
                request_uri_parameter_supported,
                require_request_uri_registration,
                op_policy_uri,
                op_tos_uri,
                signed_jwks_uri,
                client_registration_types_supported,
                federation_registration_endpoint,
                logo_uri,
            }),
        );
        assert_listed(
            "OpenIdConnectRelyingPartyMetadata",
            &OPENID_RELYING_PARTY_PARAMETERS,
            &listed_fields!(OpenIdConnectRelyingPartyMetadata {
                redirect_uris,
                response_types,
                grant_types,
                application_type,
                contacts,
                client_name,
                logo_uri,
                client_uri,
                policy_uri,
                tos_uri,
                jwks_uri,
                jwks,
                sector_identifier_uri,
                subject_type,
                id_token_signed_response_alg,
                id_token_encrypted_response_alg,
                id_token_encrypted_response_enc,
                userinfo_signed_response_alg,
                userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc,
                request_object_signing_alg,
                request_object_encryption_alg,
                request_object_encryption_enc,
                token_endpoint_auth_method,
                token_endpoint_auth_signing_alg,
                default_max_age,
                require_auth_time,
                default_acr_values,
                initiate_login_uri,
                request_uris,
            }),
        );
        assert_listed(
            "OauthAuthorizationServerMetadata",
            &OAUTH_AUTHORIZATION_SERVER_PARAMETERS,
            &listed_fields!(OauthAuthorizationServerMetadata {
                issuer,
                authorization_endpoint,
                token_endpoint,
                jwks_uri,
                registration_endpoint,
                scopes_supported,
                response_types_supported,
                response_modes_supported,
                grant_types_supported,
                token_endpoint_auth_methods_supported,
                token_endpoint_auth_signing_alg_values_supported,
                service_documentation,
                ui_locales_supported,
                op_policy_uri,
                op_tos_uri,
                revocation_endpoint,
                revocation_endpoint_auth_methods_supported,
                revocation_endpoint_auth_signing_alg_values_supported,
                introspection_endpoint,
                introspection_endpoint_auth_methods_supported,
                introspection_endpoint_auth_signing_alg_values_supported,
                code_challenge_methods_supported,
            }),
        );
    }
}
