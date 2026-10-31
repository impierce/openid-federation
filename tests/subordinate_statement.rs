//! Issuing Subordinate Statements with `SubordinateStatement::builder` (OpenID Federation 1.0,
//! Sections 3.1.1, 3.1.3 and 13.4): the statement carries what the Superior registered, verifies
//! inside a Trust Chain, and the producer rules for `crit`, `metadata_policy_crit` and
//! `source_endpoint` hold.

use chrono::Duration;
use jsonwebtoken::Algorithm;
use openid_federation::{
    EntityConfiguration, EntityId, EntityMetadata, FederationEntityMetadata, InMemorySigner, Jwk, JwkSet,
    SubordinateStatement, SubordinateStatementBuilder, TrustChain,
};
use serde_json::json;
use url::Url;

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn jwks(kid: &str) -> JwkSet {
    let mut key: Jwk = serde_json::from_str(EC_P256_JWK).unwrap();
    key.kid = Some(kid.to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

fn anchor_id() -> EntityId {
    EntityId::parse("https://ta.example.org").unwrap()
}

fn leaf_id() -> EntityId {
    EntityId::parse("https://op.example.org").unwrap()
}

/// A statement the Trust Anchor issues about the leaf, valid for a day.
fn about_leaf() -> SubordinateStatementBuilder {
    SubordinateStatement::builder(anchor_id(), leaf_id(), jwks("op-key")).lifetime(Duration::days(1))
}

#[test]
fn builder_sets_what_the_superior_registered() {
    let source = Url::parse("https://ta.example.org/fetch").unwrap();
    let statement = about_leaf()
        .issued_at(now())
        .source_endpoint(source.clone())
        .extension_claim("https://example.org/claims/tier", json!("gold"))
        .crit(vec!["https://example.org/claims/tier".to_string()])
        .metadata_policy_crit(vec!["regexp".to_string()])
        .build()
        .unwrap();

    assert_eq!(statement.claims.iss, anchor_id());
    assert_eq!(statement.claims.sub, leaf_id());
    assert_eq!(statement.jwks, jwks("op-key"));
    assert_eq!(
        statement.claims.exp - statement.claims.iat,
        Duration::days(1).num_seconds()
    );
    assert_eq!(statement.source_endpoint.as_deref().map(Url::parse), Some(Ok(source)));
    assert_eq!(
        statement.claims.additional["https://example.org/claims/tier"],
        json!("gold")
    );
    assert!(statement.metadata.is_none(), "nothing is copied from the subject");
}

#[test]
fn builder_needs_an_expiry_after_iat() {
    let builder = SubordinateStatement::builder(anchor_id(), leaf_id(), jwks("op-key"));
    let error = builder.clone().build().unwrap_err();
    assert!(error.to_string().contains("expiry"), "{error}");

    let error = builder.issued_at(now()).expires_at(now() - 10).build().unwrap_err();
    assert!(error.to_string().contains("after iat"), "{error}");
}

#[test]
fn issuer_and_subject_differ() {
    let error = SubordinateStatement::builder(anchor_id(), anchor_id(), jwks("ta-key"))
        .lifetime(Duration::hours(1))
        .build()
        .unwrap_err();
    assert!(error.to_string().contains("self-signed"), "{error}");
}

#[test]
fn crit_follows_the_producer_rules() {
    let extension = "https://example.org/claims/tier";
    for (crit, expected) in [
        (vec![], "empty array"),
        (vec!["jwks".to_string()], "the specification defines"),
        (vec!["exp".to_string()], "the specification defines"),
        (
            vec!["https://example.org/claims/absent".to_string()],
            "not a claim of the statement",
        ),
        (vec![extension.to_string(), extension.to_string()], "more than once"),
    ] {
        let error = about_leaf()
            .extension_claim(extension, json!("gold"))
            .crit(crit.clone())
            .build()
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{crit:?}: {error}");
    }
}

#[tokio::test]
async fn extension_claims_never_take_a_specified_name() {
    // A `crit` passed as an extension claim would skip the `crit` rules above.
    for name in ["crit", "metadata_policy", "jwks", "exp"] {
        let error = about_leaf().extension_claim(name, json!(["jwks"])).build().unwrap_err();
        assert!(error.to_string().contains("specification defines"), "{name}: {error}");
    }

    let signer = InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap();
    let mut statement = about_leaf().build().unwrap();
    statement.claims.additional.insert("crit".to_string(), json!(["jwks"]));
    let error = statement.sign(&signer).await.unwrap_err();
    assert!(error.to_string().contains("specification defines"), "{error}");
}

#[test]
fn metadata_policy_crit_follows_the_producer_rules() {
    for (operators, expected) in [
        (vec![], "empty array"),
        (vec!["regexp".to_string(), "regexp".to_string()], "more than once"),
        (vec!["one_of".to_string()], "standard policy operator"),
    ] {
        let error = about_leaf()
            .metadata_policy_crit(operators.clone())
            .build()
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{operators:?}: {error}");
    }
}

#[test]
fn source_endpoint_is_an_endpoint_url() {
    for source in ["http://ta.example.org/fetch", "https://ta.example.org/fetch#frag"] {
        let error = about_leaf()
            .source_endpoint(Url::parse(source).unwrap())
            .build()
            .unwrap_err();
        assert!(error.to_string().contains("source_endpoint"), "{source}: {error}");
    }
}

#[tokio::test]
async fn signing_checks_the_producer_rules_too() {
    // A statement assembled without the builder is held to the same rules when it is signed.
    let signer = InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap();
    let mut statement = about_leaf().build().unwrap();
    statement.crit = Some(vec!["jwks".to_string()]);
    let error = statement.sign(&signer).await.unwrap_err();
    assert!(error.to_string().contains("crit"), "{error}");
}

#[tokio::test]
async fn built_statement_verifies_in_a_trust_chain() {
    let signer = InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap();
    let leaf_signer = InMemorySigner::from_der(Algorithm::ES256, "op-key", EC_P256_DER).unwrap();

    let mut anchor = EntityConfiguration::new(anchor_id(), jwks("ta-key"), now() + 3600, now());
    let mut anchor_metadata = EntityMetadata::new();
    anchor_metadata.federation_entity = Some(FederationEntityMetadata {
        federation_fetch_endpoint: Some(Url::parse("https://ta.example.org/fetch").unwrap()),
        federation_list_endpoint: Some(Url::parse("https://ta.example.org/list").unwrap()),
        ..Default::default()
    });
    anchor.metadata = Some(anchor_metadata);

    let mut leaf = EntityConfiguration::new(leaf_id(), jwks("op-key"), now() + 3600, now());
    leaf.authority_hints = Some(vec![anchor_id()]);

    let statement = about_leaf()
        .source_endpoint(Url::parse("https://ta.example.org/fetch").unwrap())
        .build()
        .unwrap();

    let chain = TrustChain::try_new(vec![
        leaf.sign(&leaf_signer).await.unwrap(),
        statement.sign(&signer).await.unwrap(),
        anchor.sign(&signer).await.unwrap(),
    ])
    .unwrap();

    let (id, _) = chain.trust_anchor_entity_id_and_configuration().unwrap();
    assert_eq!(id, anchor_id());
}
