//! The checks every Entity Statement passes when it is verified (OpenID Federation 1.0, Sections
//! 3.2.1, 10.2 and 13.4): `iat` is not in the future, the header's `kid` names the signing key
//! exactly, and every claim in `crit` is one the verifier understands.
//!
//! The keys in `tests/data/signer/` are test fixtures generated once for the signer suite. They
//! protect nothing.

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, Header};
use openid_federation::{
    sign_compact_jws, EntityConfiguration, EntityId, FederationClient, FederationResult, HttpClient, HttpResponse,
    InMemorySigner, Jwk, JwkSet, JwtArtifactType, SubordinateStatement, TrustChain,
};
use serde_json::{json, Value};
use url::Url;

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");

const LEAF: &str = "https://leaf.example.org";
const ANCHOR: &str = "https://ta.example.org";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn entity(id: &str) -> EntityId {
    EntityId::parse(id).unwrap()
}

/// The public EC P-256 key under `kid`, and the Ed25519 key under `other_kid` when given.
fn jwks(kid: &str, other_kid: Option<&str>) -> JwkSet {
    let mut jwks = JwkSet::new();
    let mut key: Jwk = serde_json::from_str(EC_P256_JWK).unwrap();
    key.kid = Some(kid.to_string());
    jwks.add_key(key);
    if let Some(other_kid) = other_kid {
        let mut other: Jwk = serde_json::from_str(ED25519_JWK).unwrap();
        other.kid = Some(other_kid.to_string());
        jwks.add_key(other);
    }
    jwks
}

/// `claims` signed with the EC P-256 key as an `entity-statement+jwt` whose header names `kid`.
async fn sign(claims: &Value, kid: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(JwtArtifactType::EntityStatement.header_value().to_string());
    header.kid = kid.map(str::to_string);
    let signer = InMemorySigner::from_der(Algorithm::ES256, "unused", EC_P256_DER).unwrap();
    sign_compact_jws(&header, claims, &signer).await.unwrap()
}

/// The claims of a statement by `iss` about `sub`, valid for an hour, with `jwks`, then `extra`.
fn claims(iss: &str, sub: &str, jwks: &JwkSet, extra: Value) -> Value {
    let mut claims = json!({
        "iss": iss,
        "sub": sub,
        "iat": now() - 60,
        "exp": now() + 3600,
        "jwks": jwks,
    });
    claims
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    claims
}

/// The leaf's Entity Configuration, published with the EC key as `k1`, signed under `kid`.
async fn configuration(extra: Value, kid: Option<&str>) -> String {
    sign(&claims(LEAF, LEAF, &jwks("k1", None), extra), kid).await
}

fn error_of<T: std::fmt::Debug>(result: FederationResult<T>) -> String {
    result.unwrap_err().to_string()
}

#[tokio::test]
async fn statement_issued_in_the_future_is_rejected_beyond_the_leeway() {
    let ahead = configuration(json!({ "iat": now() + 3600 }), Some("k1")).await;
    let error = error_of(EntityConfiguration::from_verified_jwt(&ahead, &entity(LEAF), &[]));
    assert!(error.contains("issued in the future"), "{error}");

    // Clocks may differ by up to 60 seconds.
    let within = configuration(json!({ "iat": now() + 30 }), Some("k1")).await;
    EntityConfiguration::from_verified_jwt(&within, &entity(LEAF), &[]).unwrap();

    let statement = sign(
        &claims(ANCHOR, LEAF, &jwks("k1", None), json!({ "iat": now() + 3600 })),
        Some("ta"),
    )
    .await;
    let error = error_of(SubordinateStatement::from_verified_jwt(
        &statement,
        &entity(ANCHOR),
        &entity(LEAF),
        &jwks("ta", None),
        &[],
    ));
    assert!(error.contains("issued in the future"), "{error}");
}

#[tokio::test]
async fn kid_must_name_a_key_of_the_jwks_exactly() {
    EntityConfiguration::from_verified_jwt(&configuration(json!({}), Some("k1")).await, &entity(LEAF), &[]).unwrap();

    for (kid, expected) in [
        (None, "has no kid"),
        (Some(""), "has an empty kid"),
        (Some("k2"), "no key in the jwks has the kid \"k2\""),
        // A DID URL whose fragment is the `kid` is not an exact match.
        (Some("did:web:leaf.example.org#k1"), "no key in the jwks has the kid"),
    ] {
        let jwt = configuration(json!({}), kid).await;
        let error = error_of(EntityConfiguration::from_verified_jwt(&jwt, &entity(LEAF), &[]));
        assert!(error.contains(expected), "{kid:?}: {error}");
    }
}

#[tokio::test]
async fn kid_names_the_only_key_tried() {
    // The statement is signed with the EC key but names the Ed25519 key, so it fails although the
    // jwks also holds the EC key that would verify it.
    let jwt = sign(&claims(LEAF, LEAF, &jwks("ec", Some("ed")), json!({})), Some("ed")).await;
    assert!(EntityConfiguration::from_verified_jwt(&jwt, &entity(LEAF), &[]).is_err());

    let jwt = sign(&claims(LEAF, LEAF, &jwks("ec", Some("ed")), json!({})), Some("ec")).await;
    EntityConfiguration::from_verified_jwt(&jwt, &entity(LEAF), &[]).unwrap();
}

#[tokio::test]
async fn crit_names_only_extension_claims_the_verifier_understands() {
    let critical = configuration(json!({ "crit": ["x"], "x": 1 }), Some("k1")).await;
    let error = error_of(EntityConfiguration::from_verified_jwt(&critical, &entity(LEAF), &[]));
    assert!(
        error.contains("\"x\", an extension claim that is not understood"),
        "{error}"
    );
    let error = error_of(EntityConfiguration::from_verified_jwt(&critical, &entity(LEAF), &["y"]));
    assert!(error.contains("not understood"), "{error}");
    EntityConfiguration::from_verified_jwt(&critical, &entity(LEAF), &["y", "x"]).unwrap();

    // A claim the specification defines is never an extension, whatever the verifier says.
    let defined = configuration(json!({ "crit": ["jwks"] }), Some("k1")).await;
    let error = error_of(EntityConfiguration::from_verified_jwt(
        &defined,
        &entity(LEAF),
        &["jwks"],
    ));
    assert!(error.contains("a claim the specification defines"), "{error}");

    let empty = configuration(json!({ "crit": [] }), Some("k1")).await;
    let error = error_of(EntityConfiguration::from_verified_jwt(&empty, &entity(LEAF), &["x"]));
    assert!(error.contains("must not be the empty array"), "{error}");

    let statement = sign(
        &claims(ANCHOR, LEAF, &jwks("k1", None), json!({ "crit": ["x"], "x": 1 })),
        Some("ta"),
    )
    .await;
    let verify = |understood: &[&str]| {
        SubordinateStatement::from_verified_jwt(
            &statement,
            &entity(ANCHOR),
            &entity(LEAF),
            &jwks("ta", None),
            understood,
        )
    };
    assert!(error_of(verify(&[])).contains("not understood"));
    verify(&["x"]).unwrap();
}

/// A chain whose every statement lists `x` in `crit`: the leaf's Entity Configuration, the
/// anchor's Subordinate Statement about the leaf, and the anchor's Entity Configuration, which
/// publishes its fetch endpoint.
async fn critical_chain() -> [String; 3] {
    let critical = json!({ "crit": ["x"], "x": 1 });
    let mut leaf = critical.clone();
    leaf["authority_hints"] = json!([ANCHOR]);
    let mut anchor = critical.clone();
    anchor["metadata"] = json!({ "federation_entity": { "federation_fetch_endpoint": format!("{ANCHOR}/fetch") } });
    [
        configuration(leaf, Some("k1")).await,
        sign(&claims(ANCHOR, LEAF, &jwks("k1", None), critical), Some("ta")).await,
        sign(&claims(ANCHOR, ANCHOR, &jwks("ta", None), anchor), Some("ta")).await,
    ]
}

#[tokio::test]
async fn trust_chain_checks_crit_of_every_statement() {
    let chain = critical_chain().await.to_vec();
    let error = error_of(TrustChain::try_new(chain.clone(), &[]));
    assert!(error.contains("not understood"), "{error}");
    TrustChain::try_new(chain, &["x"]).unwrap();

    // Each statement alone fails without `x`: the anchor's and the leaf's configurations and the
    // Subordinate Statement are each checked.
    let [leaf, statement, anchor] = critical_chain().await;
    let plain_leaf = configuration(json!({ "authority_hints": [ANCHOR] }), Some("k1")).await;
    let plain_statement = sign(&claims(ANCHOR, LEAF, &jwks("k1", None), json!({})), Some("ta")).await;
    let plain_anchor = sign(&claims(ANCHOR, ANCHOR, &jwks("ta", None), json!({})), Some("ta")).await;
    for chain in [
        vec![leaf, plain_statement.clone(), plain_anchor.clone()],
        vec![plain_leaf.clone(), statement, plain_anchor.clone()],
        vec![plain_leaf.clone(), plain_statement.clone(), anchor],
    ] {
        let error = error_of(TrustChain::try_new(chain, &[]));
        assert!(error.contains("not understood"), "{error}");
    }
    TrustChain::try_new(vec![plain_leaf, plain_statement, plain_anchor], &[]).unwrap();
}

/// Serves the leaf's and the anchor's Entity Configurations and the anchor's statement about the
/// leaf, by URL.
struct Federation([String; 3]);

#[async_trait]
impl HttpClient for Federation {
    async fn get(&self, url: Url) -> FederationResult<HttpResponse> {
        let [leaf, statement, anchor] = &self.0;
        let body = match (url.host_str(), url.path()) {
            (Some("leaf.example.org"), "/.well-known/openid-federation") => leaf,
            (Some("ta.example.org"), "/.well-known/openid-federation") => anchor,
            (Some("ta.example.org"), "/fetch") => statement,
            _ => return Ok(HttpResponse::new(404, None, "")),
        };
        Ok(HttpResponse::new(
            200,
            Some("application/entity-statement+jwt".to_string()),
            body.clone(),
        ))
    }
}

#[tokio::test]
async fn federation_client_verifies_with_the_claims_it_was_told_it_understands() {
    let anchors = [entity(ANCHOR)];

    let client = FederationClient::with_http_client(Federation(critical_chain().await));
    let error = error_of(client.resolve_entity_configuration(&entity(LEAF)).await);
    assert!(error.contains("not understood"), "{error}");
    let error = error_of(client.discover_trust_chain(&entity(LEAF), Some(&anchors)).await);
    assert!(error.contains("not understood"), "{error}");

    let client = FederationClient::with_http_client(Federation(critical_chain().await)).with_understood_claims(["x"]);
    client.resolve_entity_configuration(&entity(LEAF)).await.unwrap();
    let chain = client
        .discover_trust_chain(&entity(LEAF), Some(&anchors))
        .await
        .unwrap();
    assert_eq!(chain.len(), 3);
    assert_eq!(client.discover_all_trust_chains(&entity(LEAF)).await.unwrap().len(), 1);
}
