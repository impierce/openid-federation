//! The Entity Configuration rules for Trust Anchors and Intermediate Entities (OpenID Federation
//! 1.0, Sections 3.1.2, 5.1.1, 8.1 and 8.2), checked with `validate_as_trust_anchor` and
//! `validate_as_intermediate`, and an Entity Configuration that passes them signed and verified
//! inside a Trust Chain.

use jsonwebtoken::Algorithm;
use openid_federation::{
    EntityConfiguration, EntityId, EntityMetadata, FederationEntityMetadata, InMemorySigner, Jwk, JwkSet,
    SubordinateStatement, TrustChain,
};
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

fn endpoints(fetch: bool, list: bool) -> EntityMetadata {
    let mut metadata = EntityMetadata::new();
    metadata.federation_entity = Some(FederationEntityMetadata {
        federation_fetch_endpoint: fetch.then(|| Url::parse("https://ta.example.org/fetch").unwrap()),
        federation_list_endpoint: list.then(|| Url::parse("https://ta.example.org/list").unwrap()),
        organization_name: Some("Example Federation".to_string()),
        ..Default::default()
    });
    metadata
}

/// A Trust Anchor configuration with both endpoints and no hints: valid for a Trust Anchor with no
/// Superiors.
fn anchor() -> EntityConfiguration {
    let mut configuration = EntityConfiguration::new(anchor_id(), jwks("ta-key"), now() + 3600, now());
    configuration.metadata = Some(endpoints(true, true));
    configuration
}

#[test]
fn trust_anchor_with_both_endpoints_and_no_hints_passes() {
    anchor().validate_as_trust_anchor(false).unwrap();
}

#[test]
fn trust_anchor_without_fetch_or_list_endpoint_fails() {
    for (fetch, list, missing) in [
        (false, true, "federation_fetch_endpoint"),
        (true, false, "federation_list_endpoint"),
    ] {
        let mut configuration = anchor();
        configuration.metadata = Some(endpoints(fetch, list));
        let error = configuration.validate_as_trust_anchor(false).unwrap_err();
        assert!(error.to_string().contains(missing), "{error}");
    }

    let mut configuration = anchor();
    configuration.metadata = None;
    assert!(configuration.validate_as_trust_anchor(false).is_err());
}

#[test]
fn trust_anchor_without_superiors_publishes_no_hints() {
    let superior = EntityId::parse("https://super.example.org").unwrap();

    let mut configuration = anchor();
    configuration.authority_hints = Some(vec![superior.clone()]);
    let error = configuration.validate_as_trust_anchor(false).unwrap_err();
    assert!(error.to_string().contains("authority_hints"), "{error}");

    let mut configuration = anchor();
    configuration.trust_anchor_hints = Some(vec![superior]);
    let error = configuration.validate_as_trust_anchor(false).unwrap_err();
    assert!(error.to_string().contains("trust_anchor_hints"), "{error}");
}

#[test]
fn trust_anchor_with_superiors_names_them() {
    // Section 4.1: a Trust Anchor can also be an Intermediate Entity in another federation.
    let mut configuration = anchor();
    assert!(configuration.validate_as_trust_anchor(true).is_err());

    configuration.authority_hints = Some(vec![EntityId::parse("https://super.example.org").unwrap()]);
    configuration.validate_as_trust_anchor(true).unwrap();
}

#[test]
fn intermediate_names_its_superiors_and_publishes_both_endpoints() {
    let id = EntityId::parse("https://intermediate.example.org").unwrap();
    let mut configuration = EntityConfiguration::new(id, jwks("int-key"), now() + 3600, now());
    configuration.metadata = Some(endpoints(true, true));
    assert!(configuration.validate_as_intermediate().is_err(), "no authority_hints");

    configuration.authority_hints = Some(vec![anchor_id()]);
    configuration.validate_as_intermediate().unwrap();

    configuration.metadata = Some(endpoints(true, false));
    let error = configuration.validate_as_intermediate().unwrap_err();
    assert!(error.to_string().contains("federation_list_endpoint"), "{error}");
}

#[test]
fn empty_hints_fail_for_every_entity() {
    // Section 3.1.2: neither claim may be the empty array, whatever the entity's role.
    let leaf_id = EntityId::parse("https://op.example.org").unwrap();
    let mut leaf = EntityConfiguration::new(leaf_id, jwks("op-key"), now() + 3600, now());
    leaf.validate().unwrap();

    leaf.authority_hints = Some(vec![]);
    let error = leaf.validate().unwrap_err();
    assert!(error.to_string().contains("authority_hints"), "{error}");

    leaf.authority_hints = Some(vec![anchor_id()]);
    leaf.trust_anchor_hints = Some(vec![]);
    let error = leaf.validate().unwrap_err();
    assert!(error.to_string().contains("trust_anchor_hints"), "{error}");
}

#[tokio::test]
async fn trust_anchor_configuration_verifies_in_a_trust_chain() {
    let signer = InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap();
    let leaf_signer = InMemorySigner::from_der(Algorithm::ES256, "op-key", EC_P256_DER).unwrap();
    let leaf_id = EntityId::parse("https://op.example.org").unwrap();

    let anchor = anchor();
    anchor.validate_as_trust_anchor(false).unwrap();

    let mut leaf = EntityConfiguration::new(leaf_id.clone(), jwks("op-key"), now() + 3600, now());
    leaf.authority_hints = Some(vec![anchor_id()]);
    let about_leaf = SubordinateStatement::new(anchor_id(), leaf_id, now() + 3600, now(), jwks("op-key"));

    let chain = TrustChain::try_new(vec![
        leaf.sign(&leaf_signer).await.unwrap(),
        about_leaf.sign(&signer).await.unwrap(),
        anchor.sign(&signer).await.unwrap(),
    ])
    .unwrap();

    let (id, configuration) = chain.trust_anchor_entity_id_and_configuration().unwrap();
    assert_eq!(id, anchor_id());
    configuration.validate_as_trust_anchor(false).unwrap();
}
