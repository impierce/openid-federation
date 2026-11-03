//! Metadata parameters the typed Entity Type structs have no field for (OpenID Federation 1.0,
//! Sections 5.1.2 to 5.1.4 and 5.2): they are kept in `additional` and survive a round trip, and
//! a parameter a struct does define keeps its type.

use jsonwebtoken::Algorithm;
use openid_federation::{
    EntityConfiguration, EntityId, EntityMetadata, FederationError, InMemorySigner, Jwk, JwkSet,
    OauthAuthorizationServerMetadata, OpenIdConnectProviderMetadata, OpenIdConnectRelyingPartyMetadata,
    SubordinateStatement,
};
use serde_json::{json, Value};

/// Appendix A.2.8, Figure 69: the OP Resolved Metadata for https://op.umu.se.
fn figure_69() -> Value {
    json!({
        "authorization_endpoint": "https://op.umu.se/authorization",
        "contacts": ["ops@swamid.se", "ops@edugain.geant.org"],
        "federation_registration_endpoint": "https://op.umu.se/fedreg",
        "client_registration_types_supported": ["automatic", "explicit"],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        ],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "issuer": "https://op.umu.se",
        "signed_jwks_uri": "https://op.umu.se/jwks.jose",
        "logo_uri": "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
        "organization_name": "University of Umeå",
        "op_policy_uri": "https://www.umu.se/en/website/legal-information/",
        "request_parameter_supported": true,
        "response_types_supported": ["code", "code id_token", "token"],
        "subject_types_supported": ["pairwise"],
        "token_endpoint": "https://op.umu.se/token",
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_jwt"]
    })
}

/// Sections 5.1.3 and 5.2: the OP metadata of Appendix A.2.8 round-trips, its Section 5.2
/// common parameters included.
#[test]
fn appendix_a_2_8_op_metadata_round_trips() {
    let metadata: EntityMetadata = serde_json::from_value(json!({ "openid_provider": figure_69() })).unwrap();
    let op = metadata.openid_provider.as_ref().unwrap();
    assert_eq!(
        op.additional.get("organization_name"),
        Some(&json!("University of Umeå"))
    );
    assert_eq!(
        op.additional.get("contacts"),
        Some(&json!(["ops@swamid.se", "ops@edugain.geant.org"]))
    );
    assert!(
        !op.additional.contains_key("issuer") && !op.additional.contains_key("logo_uri"),
        "parameters with a field stay typed: {:?}",
        op.additional.keys()
    );

    assert_eq!(
        serde_json::to_value(&metadata).unwrap(),
        json!({ "openid_provider": figure_69() })
    );
}

/// Sections 5.1.2 and 5.2: an RP keeps `client_registration_types`, RFC 7591's `scope` and a
/// Section 5.2 common parameter.
#[test]
fn relying_party_keeps_parameters_it_has_no_field_for() {
    let json = json!({
        "redirect_uris": ["https://rp.example.org/callback"],
        "client_registration_types": ["automatic"],
        "scope": "openid email",
        "organization_name": "Example RP",
        "response_types": ["code"]
    });
    let rp: OpenIdConnectRelyingPartyMetadata = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(rp.response_types, Some(vec!["code".to_string()]));
    assert_eq!(
        rp.additional.get("client_registration_types"),
        Some(&json!(["automatic"]))
    );
    assert_eq!(rp.additional.get("scope"), Some(&json!("openid email")));
    assert_eq!(rp.additional.len(), 3, "{:?}", rp.additional.keys());
    assert_eq!(serde_json::to_value(&rp).unwrap(), json);
}

/// Section 5.1.4: an Authorization Server keeps the RFC 8414 parameters it has no field for.
#[test]
fn authorization_server_keeps_parameters_it_has_no_field_for() {
    let json = json!({
        "issuer": "https://as.example.org",
        "token_endpoint": "https://as.example.org/token",
        "dpop_signing_alg_values_supported": ["ES256"],
        "code_challenge_methods_supported": ["S256"]
    });
    let server: OauthAuthorizationServerMetadata = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(server.code_challenge_methods_supported, Some(vec!["S256".to_string()]));
    assert_eq!(
        server.additional.get("dpop_signing_alg_values_supported"),
        Some(&json!(["ES256"]))
    );
    assert_eq!(serde_json::to_value(&server).unwrap(), json);
}

/// A parameter a struct defines keeps its type: a wrong value fails to parse instead of being
/// kept in `additional`.
#[test]
fn a_defined_parameter_with_the_wrong_type_still_fails() {
    for (json, name) in [
        (
            json!({ "issuer": "https://op.example.org", "logo_uri": 42 }),
            "logo_uri",
        ),
        (json!({ "issuer": "not a URL" }), "issuer"),
    ] {
        let error = serde_json::from_value::<OpenIdConnectProviderMetadata>(json.clone()).unwrap_err();
        assert!(!error.to_string().is_empty(), "{name}: {json}");
    }
    let error = serde_json::from_value::<OpenIdConnectRelyingPartyMetadata>(
        json!({ "redirect_uris": ["https://rp.example.org/callback"], "response_types": "code" }),
    );
    assert!(error.is_err(), "response_types must be an array: {error:?}");
    let error = serde_json::from_value::<OpenIdConnectRelyingPartyMetadata>(json!({ "scope": "openid" }));
    assert!(error.is_err(), "redirect_uris stays required: {error:?}");
}

const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");

/// Signing refuses metadata whose `additional` repeats a typed parameter: the signed JSON would
/// carry the parameter twice, and this crate refuses such a statement when it reads one.
#[tokio::test]
async fn signing_refuses_a_typed_parameter_in_additional() {
    let signer = InMemorySigner::from_der(Algorithm::EdDSA, "op-key", ED25519_DER).unwrap();
    let mut key: Jwk = serde_json::from_str(ED25519_JWK).unwrap();
    key.kid = Some("op-key".to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    let now = chrono::Utc::now().timestamp();
    let op = EntityId::parse("https://op.umu.se").unwrap();

    let mut metadata: EntityMetadata = serde_json::from_value(json!({ "openid_provider": figure_69() })).unwrap();
    let mut configuration = EntityConfiguration::new(op.clone(), jwks.clone(), now + 3600, now);
    configuration.metadata = Some(metadata.clone());
    configuration.sign(&signer).await.unwrap();

    metadata
        .openid_provider
        .as_mut()
        .unwrap()
        .additional
        .insert("issuer".to_string(), json!("https://other.example.org"));
    configuration.metadata = Some(metadata.clone());
    let error = configuration.sign(&signer).await.unwrap_err();
    assert!(matches!(error, FederationError::InvalidMetadata(_)), "{error:?}");
    assert!(
        error
            .to_string()
            .contains("issuer is a typed openid_provider parameter"),
        "{error}"
    );

    let statement = SubordinateStatement::new(EntityId::parse("https://umu.se").unwrap(), op, now + 3600, now, jwks)
        .with_metadata(metadata);
    let error = statement.sign(&signer).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("issuer is a typed openid_provider parameter"),
        "{error}"
    );
}
