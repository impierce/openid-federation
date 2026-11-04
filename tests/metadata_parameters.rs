//! Metadata parameters the typed Entity Type structs have no field for (OpenID Federation 1.0,
//! Sections 5.1.2 to 5.1.4 and 5.2): they are kept in `additional` and survive a round trip, and
//! a parameter a struct does define keeps its type.

use jsonwebtoken::Algorithm;
use openid_federation::{
    apply_metadata_policy, EntityConfiguration, EntityId, EntityMetadata, FederationError, InMemorySigner, Jwk, JwkSet,
    MetadataPolicy, OauthAuthorizationServerMetadata, OpenIdConnectProviderMetadata, OpenIdConnectRelyingPartyMetadata,
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
    // Every required OP parameter present, so a failure comes from the parameter under test.
    let op = json!({
        "issuer": "https://op.example.org",
        "authorization_endpoint": "https://op.example.org/authorize",
        "response_types_supported": ["code"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["ES256"]
    });
    serde_json::from_value::<OpenIdConnectProviderMetadata>(op.clone()).unwrap();
    for (name, value) in [("logo_uri", json!(42)), ("issuer", json!("not a URL"))] {
        let mut json = op.clone();
        json[name] = value;
        let error = serde_json::from_value::<OpenIdConnectProviderMetadata>(json.clone());
        assert!(error.is_err(), "{name}: {json}");
    }
    let error = serde_json::from_value::<OpenIdConnectRelyingPartyMetadata>(
        json!({ "redirect_uris": ["https://rp.example.org/callback"], "response_types": "code" }),
    );
    assert!(error.is_err(), "response_types must be an array: {error:?}");
    let error = serde_json::from_value::<OpenIdConnectRelyingPartyMetadata>(json!({ "scope": "openid" }));
    assert!(error.is_err(), "redirect_uris stays required: {error:?}");
}

/// An RP with `scope` and `client_registration_types`, neither of which has a field.
fn relying_party() -> EntityMetadata {
    serde_json::from_value(json!({
        "openid_relying_party": {
            "redirect_uris": ["https://rp.example.org/callback"],
            "client_registration_types": ["automatic"],
            "scope": "openid email address"
        }
    }))
    .unwrap()
}

/// Section 6.1.3.1.5: a `subset_of` applies to an RP's `scope`, which is kept in `additional`.
#[test]
fn subset_of_applies_to_a_relying_party_scope() {
    let policy: MetadataPolicy = serde_json::from_value(json!({
        "openid_relying_party": { "scope": { "subset_of": ["openid", "email", "profile"] } }
    }))
    .unwrap();
    let resolved = apply_metadata_policy(&relying_party(), &policy).unwrap();
    let rp = resolved.openid_relying_party.unwrap();
    assert_eq!(rp.additional.get("scope"), Some(&json!("openid email")));
}

/// Section 6.1.3.1.7: an `essential` `client_registration_types` passes when the RP publishes
/// it, and fails when it does not.
#[test]
fn essential_client_registration_types_passes_when_published() {
    let policy: MetadataPolicy = serde_json::from_value(json!({
        "openid_relying_party": { "client_registration_types": { "essential": true } }
    }))
    .unwrap();
    let resolved = apply_metadata_policy(&relying_party(), &policy).unwrap();
    assert_eq!(
        resolved
            .openid_relying_party
            .unwrap()
            .additional
            .get("client_registration_types"),
        Some(&json!(["automatic"]))
    );

    let mut without = relying_party();
    without
        .openid_relying_party
        .as_mut()
        .unwrap()
        .additional
        .remove("client_registration_types");
    let error = apply_metadata_policy(&without, &policy).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("openid_relying_party.client_registration_types"),
        "{error}"
    );
}

/// Metadata of `entity_type` with every required parameter, and `parameter` set to `value` in
/// its `additional` map only, as code can do and parsing cannot.
fn with_typed_name_in_additional(entity_type: &str, parameter: &str, value: Value) -> EntityMetadata {
    let member = match entity_type {
        "federation_entity" => json!({ "federation_fetch_endpoint": "https://ta.example.org/fetch" }),
        "openid_provider" => json!({
            "issuer": "https://op.example.org",
            "authorization_endpoint": "https://op.example.org/authorize",
            "response_types_supported": ["code"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["ES256"]
        }),
        "openid_relying_party" => json!({ "redirect_uris": ["https://rp.example.org/callback"] }),
        "oauth_authorization_server" => json!({ "issuer": "https://as.example.org" }),
        other => panic!("{other}"),
    };
    let mut metadata = json!({ entity_type: member });
    metadata[entity_type]["additional_marker"] = json!(true);
    let mut metadata: EntityMetadata = serde_json::from_value(metadata).unwrap();
    let additional = match entity_type {
        "federation_entity" => &mut metadata.federation_entity.as_mut().unwrap().additional,
        "openid_provider" => &mut metadata.openid_provider.as_mut().unwrap().additional,
        "openid_relying_party" => &mut metadata.openid_relying_party.as_mut().unwrap().additional,
        _ => &mut metadata.oauth_authorization_server.as_mut().unwrap().additional,
    };
    additional.remove("additional_marker");
    additional.insert(parameter.to_string(), value);
    metadata
}

/// A typed parameter repeated in `additional` would replace the typed value once the metadata is
/// serialized, so applying a policy refuses it for every typed Entity Type, whatever the policy.
#[test]
fn applying_a_policy_refuses_a_typed_parameter_in_additional() {
    for (entity_type, parameter, value) in [
        (
            "federation_entity",
            "federation_fetch_endpoint",
            json!("https://other.example.org/fetch"),
        ),
        ("openid_provider", "issuer", json!("https://other.example.org")),
        (
            "openid_relying_party",
            "redirect_uris",
            json!(["https://other.example.org/callback"]),
        ),
        (
            "oauth_authorization_server",
            "token_endpoint",
            json!("https://other.example.org/token"),
        ),
    ] {
        let metadata = with_typed_name_in_additional(entity_type, parameter, value);
        let policies: [MetadataPolicy; 2] = [
            MetadataPolicy::new(),
            serde_json::from_value(json!({ entity_type: { parameter: { "essential": true } } })).unwrap(),
        ];
        for policy in policies {
            let error = apply_metadata_policy(&metadata, &policy).unwrap_err();
            assert!(matches!(error, FederationError::InvalidMetadata(_)), "{error:?}");
            assert!(
                error
                    .to_string()
                    .contains(&format!("{parameter} is a typed {entity_type} parameter")),
                "{entity_type}: {error}"
            );
        }
    }
}

/// An `additional` map that holds only names the struct has no field for keeps applying.
#[test]
fn applying_a_policy_keeps_unknown_names_in_additional() {
    for (entity_type, parameter) in [
        ("federation_entity", "example_extension"),
        ("openid_provider", "organization_name"),
        ("openid_relying_party", "client_registration_types"),
        ("oauth_authorization_server", "dpop_signing_alg_values_supported"),
    ] {
        let metadata = with_typed_name_in_additional(entity_type, parameter, json!(["x"]));
        let resolved = apply_metadata_policy(&metadata, &MetadataPolicy::new()).unwrap();
        let resolved = serde_json::to_value(&resolved).unwrap();
        assert_eq!(resolved[entity_type][parameter], json!(["x"]), "{entity_type}");
    }
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
    let jwt = configuration.sign(&signer).await.unwrap();
    let signed = EntityConfiguration::from_verified_jwt(&jwt, &op, &[]).unwrap();
    let signed = signed.metadata.unwrap().openid_provider.unwrap();
    assert_eq!(
        signed.additional.get("organization_name"),
        Some(&json!("University of Umeå"))
    );
    assert_eq!(signed.issuer.as_str(), "https://op.umu.se");

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

/// Signs `metadata` for https://rp.example.org in an Entity Configuration and in a Subordinate
/// Statement, and checks that both refuse it with `message`.
async fn assert_signing_refuses(metadata: EntityMetadata, message: &str) {
    let signer = InMemorySigner::from_der(Algorithm::EdDSA, "key", ED25519_DER).unwrap();
    let mut key: Jwk = serde_json::from_str(ED25519_JWK).unwrap();
    key.kid = Some("key".to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    let now = chrono::Utc::now().timestamp();
    let entity = EntityId::parse("https://rp.example.org").unwrap();

    let mut configuration = EntityConfiguration::new(entity.clone(), jwks.clone(), now + 3600, now);
    configuration.metadata = Some(metadata.clone());
    let error = configuration.sign(&signer).await.unwrap_err();
    assert!(matches!(error, FederationError::InvalidMetadata(_)), "{error:?}");
    assert!(error.to_string().contains(message), "{error}");

    let statement = SubordinateStatement::new(
        EntityId::parse("https://ta.example.org").unwrap(),
        entity,
        now + 3600,
        now,
        jwks,
    )
    .with_metadata(metadata);
    let error = statement.sign(&signer).await.unwrap_err();
    assert!(matches!(error, FederationError::InvalidMetadata(_)), "{error:?}");
    assert!(error.to_string().contains(message), "{error}");
}

/// The same refusal for a typed RP and Authorization Server parameter in `additional`.
#[tokio::test]
async fn signing_refuses_a_typed_rp_or_as_parameter_in_additional() {
    let mut rp = relying_party();
    rp.openid_relying_party.as_mut().unwrap().additional.insert(
        "redirect_uris".to_string(),
        json!(["https://other.example.org/callback"]),
    );
    assert_signing_refuses(rp, "redirect_uris is a typed openid_relying_party parameter").await;

    let mut server: EntityMetadata =
        serde_json::from_value(json!({ "oauth_authorization_server": { "issuer": "https://rp.example.org" } }))
            .unwrap();
    server
        .oauth_authorization_server
        .as_mut()
        .unwrap()
        .additional
        .insert("token_endpoint".to_string(), json!("https://other.example.org/token"));
    assert_signing_refuses(server, "token_endpoint is a typed oauth_authorization_server parameter").await;
}
