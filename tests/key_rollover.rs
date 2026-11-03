//! Rolling over a Trust Anchor's Federation Entity Keys with `FederationKeys` (OpenID Federation
//! 1.0, Sections 11.1 and 11.2): the four steps in order, with verifiers that hold the old and the
//! new Entity Configuration, and the invariants of the key set.

use jsonwebtoken::Algorithm;
use openid_federation::{
    EntityConfiguration, EntityId, FederationKeys, InMemoryKeyStore, InMemorySigner, Jwk, JwkSet, KeyState, KeyStore,
    Signer, SubordinateStatement,
};
use std::sync::Arc;

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");
const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");
const RSA_2048_JWK: &str = include_str!("data/signer/rsa-2048.public.jwk.json");

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn key(jwk: &str, kid: &str) -> Jwk {
    let mut key: Jwk = serde_json::from_str(jwk).unwrap();
    key.kid = Some(kid.to_string());
    key
}

fn old_key() -> (Arc<dyn Signer>, Jwk) {
    (
        Arc::new(InMemorySigner::from_der(Algorithm::ES256, "ta-2025", EC_P256_DER).unwrap()),
        key(EC_P256_JWK, "ta-2025"),
    )
}

fn new_key() -> (Arc<dyn Signer>, Jwk) {
    (
        Arc::new(InMemorySigner::from_der(Algorithm::EdDSA, "ta-2026", ED25519_DER).unwrap()),
        key(ED25519_JWK, "ta-2026"),
    )
}

fn anchor_id() -> EntityId {
    EntityId::parse("https://ta.example.org").unwrap()
}

fn leaf_id() -> EntityId {
    EntityId::parse("https://op.example.org").unwrap()
}

/// The Trust Anchor's Entity Configuration, signed with the active key and publishing `jwks`.
async fn configuration(keys: &FederationKeys) -> EntityConfiguration {
    let jwt = EntityConfiguration::new(anchor_id(), keys.jwks(), now() + 3600, now())
        .sign(keys.active_signer().as_ref())
        .await
        .unwrap();
    EntityConfiguration::from_verified_jwt(&jwt, &anchor_id(), &[]).unwrap()
}

/// A Subordinate Statement the Trust Anchor issues with its active key.
async fn statement(keys: &FederationKeys) -> String {
    let leaf_jwks = JwkSet {
        keys: vec![key(RSA_2048_JWK, "op-key")],
    };
    SubordinateStatement::builder(anchor_id(), leaf_id(), leaf_jwks)
        .lifetime(chrono::Duration::hours(1))
        .build()
        .unwrap()
        .sign(keys.active_signer().as_ref())
        .await
        .unwrap()
}

fn accepts(verifier_jwks: &JwkSet, statement: &str) -> bool {
    SubordinateStatement::from_verified_jwt(statement, &anchor_id(), &leaf_id(), verifier_jwks, &[]).is_ok()
}

fn kids(jwks: &JwkSet) -> Vec<&str> {
    jwks.keys.iter().filter_map(|key| key.kid.as_deref()).collect()
}

fn active_count(keys: &FederationKeys) -> usize {
    keys.records()
        .iter()
        .filter(|record| record.state == KeyState::Active)
        .count()
}

#[tokio::test]
async fn trust_anchor_rolls_over_its_keys_in_the_four_steps_of_section_11_2() {
    let (old_signer, old_public) = old_key();
    let mut keys = FederationKeys::new(old_signer, old_public).unwrap();
    // A verifier that fetched the configuration before the rollover began.
    let old_configuration = configuration(&keys).await;
    assert_eq!(kids(&old_configuration.jwks), ["ta-2025"]);

    // Step 1: add the new key to jwks. The old key still signs.
    let (new_signer, new_public) = new_key();
    keys.add_next(new_signer, new_public).unwrap();
    assert_eq!(active_count(&keys), 1);
    let new_configuration = configuration(&keys).await;
    assert_eq!(kids(&new_configuration.jwks), ["ta-2025", "ta-2026"]);

    // Step 2: keep signing with the old key. Both verifiers accept.
    let before_switch = statement(&keys).await;
    assert!(accepts(&old_configuration.jwks, &before_switch));
    assert!(accepts(&new_configuration.jwks, &before_switch));

    // Step 3: switch to the new key. A verifier holding the new configuration accepts; one that
    // never re-fetched would not, which is why step 2 waits for every configuration to expire.
    keys.activate("ta-2026").unwrap();
    assert_eq!(active_count(&keys), 1);
    assert_eq!(keys.active().kid(), "ta-2026");
    assert_eq!(keys.active_signer().kid(), "ta-2026");
    let after_switch = statement(&keys).await;
    assert!(accepts(&new_configuration.jwks, &after_switch));
    assert!(!accepts(&old_configuration.jwks, &after_switch));
    // The old key is still published, so the statements it signed keep verifying.
    let switched_configuration = configuration(&keys).await;
    assert_eq!(kids(&switched_configuration.jwks), ["ta-2025", "ta-2026"]);
    assert!(accepts(&switched_configuration.jwks, &before_switch));

    // Step 4: remove the old key from jwks.
    keys.retire("ta-2025", now()).unwrap();
    assert_eq!(active_count(&keys), 1);
    let final_configuration = configuration(&keys).await;
    assert_eq!(
        kids(&final_configuration.jwks),
        ["ta-2026"],
        "a retired key is not in jwks"
    );
    assert!(accepts(&final_configuration.jwks, &statement(&keys).await));
    assert!(accepts(&new_configuration.jwks, &statement(&keys).await));
    let retired: Vec<_> = keys.retired().map(|record| record.kid()).collect();
    assert_eq!(retired, ["ta-2025"]);
}

#[test]
fn transitions_keep_exactly_one_active_key() {
    let (old_signer, old_public) = old_key();
    let mut keys = FederationKeys::new(old_signer, old_public).unwrap();

    let error = keys.retire("ta-2025", now()).unwrap_err();
    assert!(error.to_string().contains("is Active and cannot be retired"), "{error}");
    let error = keys.activate("ta-2025").unwrap_err();
    assert!(
        error.to_string().contains("is Active and cannot be activated"),
        "{error}"
    );
    let error = keys.activate("unknown").unwrap_err();
    assert!(error.to_string().contains("no key \"unknown\""), "{error}");

    let (new_signer, new_public) = new_key();
    keys.add_next(new_signer, new_public).unwrap();
    keys.activate("ta-2026").unwrap();
    let error = keys.activate("ta-2025").unwrap_err();
    assert!(
        error.to_string().contains("is Previous and cannot be activated"),
        "{error}"
    );
    keys.retire("ta-2025", 1).unwrap();
    let error = keys.retire("ta-2025", 2).unwrap_err();
    assert!(
        error.to_string().contains("is Retired and cannot be retired"),
        "{error}"
    );
    assert_eq!(keys.retired().next().unwrap().retired_at, Some(1));
    assert_eq!(active_count(&keys), 1);
}

#[test]
fn next_key_can_be_retired_to_abandon_a_rollover() {
    let (old_signer, old_public) = old_key();
    let mut keys = FederationKeys::new(old_signer, old_public).unwrap();
    let (new_signer, new_public) = new_key();
    keys.add_next(new_signer, new_public).unwrap();

    keys.retire("ta-2026", now()).unwrap();

    assert_eq!(kids(&keys.jwks()), ["ta-2025"]);
    assert_eq!(keys.active().kid(), "ta-2025");
}

#[test]
fn keys_that_cannot_be_published_are_refused() {
    let (old_signer, old_public) = old_key();
    let mut keys = FederationKeys::new(old_signer, old_public).unwrap();

    let (new_signer, mut mismatched) = new_key();
    mismatched.kid = Some("other".to_string());
    let error = keys.add_next(new_signer.clone(), mismatched).unwrap_err();
    assert!(error.to_string().contains("differs from the signer's kid"), "{error}");

    let (old_signer, old_public) = old_key();
    let error = keys.add_next(old_signer, old_public).unwrap_err();
    assert!(error.to_string().contains("already in the key set"), "{error}");

    let (_, mut private) = new_key();
    private.d = Some("private".to_string());
    let error = keys.add_next(new_signer, private).unwrap_err();
    assert!(error.to_string().contains("private key material"), "{error}");
    assert_eq!(kids(&keys.jwks()), ["ta-2025"], "nothing was added");
}

#[tokio::test]
async fn key_store_persists_records_and_signers_are_supplied_on_load() {
    let (old_signer, old_public) = old_key();
    let mut keys = FederationKeys::new(old_signer, old_public).unwrap();
    let (new_signer, new_public) = new_key();
    keys.add_next(new_signer, new_public).unwrap();
    keys.activate("ta-2026").unwrap();
    let store = InMemoryKeyStore::new();
    store.save(keys.records()).await.unwrap();

    let records = store.load().await.unwrap();
    let (new_signer, _) = new_key();
    let restored = FederationKeys::from_records(records.clone(), [new_signer]).unwrap();
    assert_eq!(restored.records(), keys.records());
    assert_eq!(restored.active_signer().kid(), "ta-2026");

    let error = FederationKeys::from_records(records.clone(), []).unwrap_err();
    assert!(
        error.to_string().contains("no signer for the key \"ta-2026\""),
        "{error}"
    );

    let mut two_active = records;
    for record in &mut two_active {
        record.state = KeyState::Active;
    }
    let (old_signer, _) = old_key();
    let (new_signer, _) = new_key();
    let error = FederationKeys::from_records(two_active, [old_signer, new_signer]).unwrap_err();
    assert!(error.to_string().contains("exactly one active key"), "{error}");

    let json = serde_json::to_value(keys.records()).unwrap();
    assert_eq!(json[0]["state"], "previous");
    assert_eq!(json[1]["state"], "active");
}

/// A restart in the middle of a rollover, between steps 1 and 3: the next key's signer is
/// restored with it, so the rollover can continue.
#[test]
fn restored_next_key_can_be_activated() {
    let (old_signer, old_public) = old_key();
    let mut keys = FederationKeys::new(old_signer, old_public).unwrap();
    let (new_signer, new_public) = new_key();
    keys.add_next(new_signer, new_public).unwrap();
    let records = keys.records().to_vec();

    let (old_signer, _) = old_key();
    let (new_signer, _) = new_key();
    let mut restored = FederationKeys::from_records(records, [old_signer, new_signer]).unwrap();
    restored.activate("ta-2026").unwrap();

    assert_eq!(restored.active_signer().kid(), "ta-2026");
}

#[test]
fn two_signers_for_one_kid_are_refused_on_restore() {
    let (old_signer, old_public) = old_key();
    let keys = FederationKeys::new(old_signer, old_public).unwrap();
    let records = keys.records().to_vec();

    let (first, _) = old_key();
    let (second, _) = old_key();
    let error = FederationKeys::from_records(records, [first, second]).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("more than one signer for the kid \"ta-2025\""),
        "{error}"
    );
}

#[test]
fn key_without_key_material_is_refused() {
    let (old_signer, old_public) = old_key();
    let mut keys = FederationKeys::new(old_signer, old_public).unwrap();
    let (new_signer, mut incomplete) = new_key();
    incomplete.x = None;

    assert!(keys.add_next(new_signer, incomplete.clone()).is_err());
    assert_eq!(kids(&keys.jwks()), ["ta-2025"], "nothing was added");

    let (new_signer, _) = new_key();
    assert!(FederationKeys::new(new_signer.clone(), incomplete.clone()).is_err());

    // A stored record without key material is refused on restore too.
    let mut records = keys.records().to_vec();
    records[0].public_key.x = None;
    records[0].public_key.y = None;
    let (old_signer, _) = old_key();
    assert!(FederationKeys::from_records(records, [old_signer]).is_err());
}
