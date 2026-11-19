//! Resolving a Trust Chain subject's metadata in `TrustChain::try_new` (OpenID Federation 1.0,
//! Sections 6.1.4 and 10.2): the Immediate Superior's `metadata`, the `allowed_entity_types`
//! constraint and the chain's merged metadata policy, in that order.

use jsonwebtoken::Algorithm;
use openid_federation::{
    EntityConfiguration, FederationError, InMemorySigner, Jwk, JwkSet, SubordinateStatement, TrustChain,
};
use serde_json::{json, Value};

const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");

fn signer() -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::EdDSA, "key", ED25519_DER).unwrap()
}

/// The one key every entity in these chains uses, so the test signs each statement itself.
fn jwks() -> Value {
    let mut key: Jwk = serde_json::from_str(ED25519_JWK).unwrap();
    key.kid = Some("key".to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    serde_json::to_value(jwks).unwrap()
}

/// `claims` with fresh `iat` and `exp` and the test key as `jwks`.
fn with_test_claims(mut claims: Value) -> Value {
    let now = chrono::Utc::now().timestamp();
    claims["iat"] = json!(now);
    claims["exp"] = json!(now + 3600);
    claims["jwks"] = jwks();
    claims
}

async fn entity_configuration(claims: Value) -> String {
    let configuration: EntityConfiguration = serde_json::from_value(with_test_claims(claims)).unwrap();
    configuration.sign(&signer()).await.unwrap()
}

async fn subordinate_statement(claims: Value) -> String {
    let statement: SubordinateStatement = serde_json::from_value(with_test_claims(claims)).unwrap();
    statement.sign(&signer()).await.unwrap()
}

/// Sorts every array of strings in `value`, so arrays compare as sets: the specification does not
/// fix the order an operator leaves values in.
fn sorted(mut value: Value) -> Value {
    match &mut value {
        Value::Array(values) => {
            values.iter_mut().for_each(|value| *value = sorted(value.take()));
            values.sort_by_key(|value| value.to_string());
        }
        Value::Object(members) => members.values_mut().for_each(|value| *value = sorted(value.take())),
        _ => {}
    }
    value
}

/// Appendix A.2.1 to A.2.7: the Trust Chain from https://op.umu.se to https://edugain.geant.org.
async fn appendix_a_2_chain() -> Vec<String> {
    vec![
        // A.2.1, Figure 56.
        entity_configuration(json!({
            "authority_hints": ["https://umu.se"],
            "iss": "https://op.umu.se",
            "sub": "https://op.umu.se",
            "metadata": {
                "openid_provider": {
                    "issuer": "https://op.umu.se",
                    "signed_jwks_uri": "https://op.umu.se/jwks.jose",
                    "authorization_endpoint": "https://op.umu.se/authorization",
                    "client_registration_types_supported": ["automatic", "explicit"],
                    "request_parameter_supported": true,
                    "grant_types_supported": [
                        "authorization_code",
                        "implicit",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer"
                    ],
                    "id_token_signing_alg_values_supported": ["ES256", "RS256"],
                    "logo_uri": "https://www.umu.se/img/umu-logo-left-neg-SE.svg",
                    "op_policy_uri": "https://www.umu.se/en/website/legal-information/",
                    "response_types_supported": ["code", "code id_token", "token"],
                    "subject_types_supported": ["pairwise", "public"],
                    "token_endpoint": "https://op.umu.se/token",
                    "federation_registration_endpoint": "https://op.umu.se/fedreg",
                    "token_endpoint_auth_methods_supported": [
                        "client_secret_post",
                        "client_secret_basic",
                        "client_secret_jwt",
                        "private_key_jwt"
                    ]
                }
            }
        }))
        .await,
        // A.2.3, Figure 60.
        subordinate_statement(json!({
            "iss": "https://umu.se",
            "sub": "https://op.umu.se",
            "source_endpoint": "https://umu.se/openid/fedapi",
            "metadata_policy": {
                "openid_provider": {
                    "contacts": { "add": ["ops@swamid.se"] },
                    "organization_name": { "value": "University of Umeå" },
                    "subject_types_supported": { "value": ["pairwise"] },
                    "token_endpoint_auth_methods_supported": {
                        "default": ["private_key_jwt"],
                        "subset_of": ["private_key_jwt", "client_secret_jwt"],
                        "superset_of": ["private_key_jwt"]
                    }
                }
            }
        }))
        .await,
        // A.2.5, Figure 64.
        subordinate_statement(json!({
            "iss": "https://swamid.se",
            "sub": "https://umu.se",
            "source_endpoint": "https://swamid.se/fedapi",
            "metadata_policy": {
                "openid_provider": {
                    "id_token_signing_alg_values_supported": { "subset_of": ["RS256", "ES256", "ES384", "ES512"] },
                    "token_endpoint_auth_methods_supported": { "subset_of": ["client_secret_jwt", "private_key_jwt"] },
                    "userinfo_signing_alg_values_supported": { "subset_of": ["ES256", "ES384", "ES512"] }
                }
            }
        }))
        .await,
        // A.2.7, Figure 68.
        subordinate_statement(json!({
            "iss": "https://edugain.geant.org",
            "sub": "https://swamid.se",
            "source_endpoint": "https://edugain.geant.org/edugain/api",
            "metadata_policy": {
                "openid_provider": { "contacts": { "add": ["ops@edugain.geant.org"] } },
                "openid_relying_party": { "contacts": { "add": ["ops@edugain.geant.org"] } }
            }
        }))
        .await,
        // A.2.6, Figure 66.
        entity_configuration(json!({
            "iss": "https://edugain.geant.org",
            "sub": "https://edugain.geant.org",
            "metadata": {
                "federation_entity": { "federation_fetch_endpoint": "https://geant.org/edugain/api" }
            }
        }))
        .await,
    ]
}

/// Appendix A.2.8: the chain of Sections A.2.1 to A.2.7 resolves to the OP metadata of
/// Figure 69.
#[tokio::test]
async fn appendix_a_2_chain_resolves_to_figure_69() {
    let chain = TrustChain::try_new(appendix_a_2_chain().await, &[]).unwrap();
    let resolved = serde_json::to_value(chain.metadata()).unwrap();
    let figure_69 = json!({
        "openid_provider": {
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
        }
    });
    assert_eq!(sorted(resolved), sorted(figure_69));
}

/// A three-statement chain: `subject` under https://ta.example.org, whose Subordinate Statement
/// about it carries `superior`'s `metadata`, `constraints` and `metadata_policy` members.
async fn chain_under_anchor(subject_metadata: Value, superior: Value) -> Vec<String> {
    let mut statement = json!({ "iss": "https://ta.example.org", "sub": "https://rp.example.org" });
    for (name, value) in superior.as_object().unwrap() {
        statement[name] = value.clone();
    }
    vec![
        entity_configuration(json!({
            "authority_hints": ["https://ta.example.org"],
            "iss": "https://rp.example.org",
            "sub": "https://rp.example.org",
            "metadata": subject_metadata
        }))
        .await,
        subordinate_statement(statement).await,
        entity_configuration(json!({
            "iss": "https://ta.example.org",
            "sub": "https://ta.example.org",
            "metadata": {
                "federation_entity": {
                    "federation_fetch_endpoint": "https://ta.example.org/fetch",
                    "federation_list_endpoint": "https://ta.example.org/list"
                }
            }
        }))
        .await,
    ]
}

/// Section 3.1.1: the Immediate Superior's `metadata` overrides the subject's parameters, only
/// for the Entity Types the subject declares. It may supply what the subject leaves out, so the
/// subject's Entity Configuration may publish `{}`.
#[tokio::test]
async fn superior_metadata_applies_only_to_declared_entity_types() {
    let chain = chain_under_anchor(
        json!({
            "federation_entity": { "organization_name": "Example RP" },
            "openid_relying_party": {}
        }),
        json!({
            "metadata": {
                "federation_entity": { "organization_name": "Example RP, as registered" },
                "openid_relying_party": { "redirect_uris": ["https://rp.example.org/callback"] },
                "openid_provider": { "issuer": "https://rp.example.org" }
            }
        }),
    )
    .await;
    let resolved = TrustChain::try_new(chain, &[]).unwrap();
    let resolved = serde_json::to_value(resolved.metadata()).unwrap();
    assert_eq!(
        resolved,
        json!({
            "federation_entity": { "organization_name": "Example RP, as registered" },
            "openid_relying_party": { "redirect_uris": ["https://rp.example.org/callback"] }
        })
    );
}

/// Section 6.2.3: `allowed_entity_types: []` leaves only `federation_entity`, and it is applied
/// before the metadata policy, whose policy for a removed Entity Type then has nothing to check.
#[tokio::test]
async fn empty_allowed_entity_types_leaves_only_federation_entity() {
    let chain = chain_under_anchor(
        json!({
            "federation_entity": { "organization_name": "Example RP" },
            "openid_relying_party": { "redirect_uris": ["https://rp.example.org/callback"] },
            "oauth_client": {}
        }),
        json!({
            "constraints": { "allowed_entity_types": [] },
            "metadata_policy": { "openid_relying_party": { "client_name": { "essential": true } } }
        }),
    )
    .await;
    let resolved = TrustChain::try_new(chain, &[]).unwrap();
    assert_eq!(
        serde_json::to_value(resolved.metadata()).unwrap(),
        json!({ "federation_entity": { "organization_name": "Example RP" } })
    );
}

/// Section 6.2.3: an `allowed_entity_types` that lists an Entity Type keeps it.
#[tokio::test]
async fn allowed_entity_types_keeps_the_listed_entity_types() {
    let chain = chain_under_anchor(
        json!({
            "openid_relying_party": { "redirect_uris": ["https://rp.example.org/callback"] },
            "oauth_client": {}
        }),
        json!({ "constraints": { "allowed_entity_types": ["openid_relying_party"] } }),
    )
    .await;
    let resolved = TrustChain::try_new(chain, &[]).unwrap();
    assert_eq!(
        serde_json::to_value(resolved.metadata()).unwrap(),
        json!({ "openid_relying_party": { "redirect_uris": ["https://rp.example.org/callback"] } })
    );
}

/// Section 6.2.3: an ancestor's `allowed_entity_types` removes an Entity Type that the Immediate
/// Superior's `allowed_entity_types` lists.
#[tokio::test]
async fn ancestor_allowed_entity_types_removes_types_the_superior_allows() {
    let chain = vec![
        entity_configuration(json!({
            "authority_hints": ["https://ia.example.org"],
            "iss": "https://rp.example.org",
            "sub": "https://rp.example.org",
            "metadata": {
                "federation_entity": { "organization_name": "Example RP" },
                "openid_relying_party": { "redirect_uris": ["https://rp.example.org/callback"] }
            }
        }))
        .await,
        subordinate_statement(json!({
            "iss": "https://ia.example.org",
            "sub": "https://rp.example.org",
            "constraints": { "allowed_entity_types": ["openid_relying_party"] }
        }))
        .await,
        subordinate_statement(json!({
            "iss": "https://ta.example.org",
            "sub": "https://ia.example.org",
            "constraints": { "allowed_entity_types": ["openid_provider"] }
        }))
        .await,
        entity_configuration(json!({ "iss": "https://ta.example.org", "sub": "https://ta.example.org" })).await,
    ];
    let resolved = TrustChain::try_new(chain, &[]).unwrap();
    assert_eq!(
        serde_json::to_value(resolved.metadata()).unwrap(),
        json!({ "federation_entity": { "organization_name": "Example RP" } })
    );
}

/// Section 6.1.4.1: an Intermediate's policy that conflicts with the Trust Anchor's makes the
/// chain invalid.
#[tokio::test]
async fn conflicting_policies_make_the_chain_invalid() {
    let rp = json!({ "openid_relying_party": { "redirect_uris": ["https://rp.example.org/callback"] } });
    let chain = vec![
        entity_configuration(json!({
            "authority_hints": ["https://ia.example.org"],
            "iss": "https://rp.example.org",
            "sub": "https://rp.example.org",
            "metadata": rp
        }))
        .await,
        subordinate_statement(json!({
            "iss": "https://ia.example.org",
            "sub": "https://rp.example.org",
            "metadata_policy": { "openid_relying_party": { "client_name": { "value": "Intermediate's name" } } }
        }))
        .await,
        subordinate_statement(json!({
            "iss": "https://ta.example.org",
            "sub": "https://ia.example.org",
            "metadata_policy": { "openid_relying_party": { "client_name": { "value": "Trust Anchor's name" } } }
        }))
        .await,
        entity_configuration(json!({ "iss": "https://ta.example.org", "sub": "https://ta.example.org" })).await,
    ];
    let error = TrustChain::try_new(chain, &[]).unwrap_err();
    assert!(matches!(error, FederationError::TrustChainValidation(_)), "{error:?}");
    let message = error.to_string();
    assert!(message.contains("https://rp.example.org"), "{message}");
    assert!(
        message.contains("the metadata_policy issued by https://ia.example.org"),
        "{message}"
    );
    assert!(message.contains("openid_relying_party.client_name"), "{message}");
}

/// Section 6.1.4.2: Resolved Metadata that does not fit its Entity Type makes the chain invalid,
/// here an RP that no statement gives `redirect_uris`.
#[tokio::test]
async fn incomplete_resolved_metadata_makes_the_chain_invalid() {
    let chain = chain_under_anchor(json!({ "openid_relying_party": {} }), json!({})).await;
    let error = TrustChain::try_new(chain, &[]).unwrap_err();
    assert!(matches!(error, FederationError::TrustChainValidation(_)), "{error:?}");
    assert!(error.to_string().contains("openid_relying_party"), "{error}");
}
