//! Publishing an entity's historical keys (OpenID Federation 1.0, Section 8.7): the types of the
//! response and the example of Section 8.7.2, the signed `jwk-set+jwt`, and the endpoint serving
//! the keys a rollover retired and revoked.

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use openid_federation::{
    sign_federation_jwt, EntityId, ErrorCode, ErrorResponse, FederationError, FederationKeys, HistoricalKey,
    HistoricalKeys, HistoricalKeysEndpoint, InMemoryKeyStore, InMemorySigner, Jwk, JwtArtifactType, KeyRecord,
    KeyRevocation, KeyStore, RevocationReason, Signer, StoreError,
};
use serde_json::json;
use std::sync::Arc;

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");
const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");
const RSA_2048_DER: &[u8] = include_bytes!("data/signer/rsa-2048.pkcs1.der");
const RSA_2048_JWK: &str = include_str!("data/signer/rsa-2048.public.jwk.json");

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn key(jwk: &str, kid: &str) -> Jwk {
    let mut key: Jwk = serde_json::from_str(jwk).unwrap();
    key.kid = Some(kid.to_string());
    key
}

fn signer(alg: Algorithm, kid: &str, der: &[u8]) -> Arc<dyn Signer> {
    Arc::new(InMemorySigner::from_der(alg, kid, der).unwrap())
}

fn anchor_id() -> EntityId {
    EntityId::parse("https://trust-anchor.federation.example.com").unwrap()
}

/// A Trust Anchor that rolled over from `ta-2024` to `ta-2025` and is now adding `ta-2026`.
fn rolled_over_keys() -> FederationKeys {
    let mut keys = activated_keys();
    keys.retire("ta-2024", 1_700_000_000).unwrap();
    keys
}

/// A Trust Anchor that activated `ta-2025` and still publishes `ta-2024` as its previous key.
fn activated_keys() -> FederationKeys {
    let mut keys = FederationKeys::new(
        signer(Algorithm::ES256, "ta-2024", EC_P256_DER),
        key(EC_P256_JWK, "ta-2024"),
    )
    .unwrap();
    keys.add_next(
        signer(Algorithm::EdDSA, "ta-2025", ED25519_DER),
        key(ED25519_JWK, "ta-2025"),
    )
    .unwrap();
    keys.activate("ta-2025").unwrap();
    keys
}

#[test]
fn section_8_7_2_example_deserializes() {
    // The example of Section 8.7.2, without the trailing comma that makes it invalid JSON.
    let claims = json!({
        "iss": "https://trust-anchor.federation.example.com",
        "iat": 1666335600,
        "keys": [
            {
                "kty": "RSA",
                "n": "5s4qi ...",
                "e": "AQAB",
                "kid": "2HnoFS3YnC9tjiCaivhWLVUJ3AxwGGz_98uRFaqMEEs",
                "iat": 1661151600,
                "exp": 1677052800
            },
            {
                "kty": "RSA",
                "n": "ng5jr ...",
                "e": "AQAB",
                "kid": "8KnoFS3YnC9tjiCaivhWLVUJ3AxwGGz_98uRFaqMJJr",
                "iat": 1647932400,
                "exp": 1663830000,
                "revoked": {
                    "revoked_at": 1661151600,
                    "reason": "compromised"
                }
            }
        ]
    });

    let keys: HistoricalKeys = serde_json::from_value(claims.clone()).unwrap();

    assert_eq!(keys.iss, anchor_id());
    assert_eq!(keys.iat, 1666335600);
    assert_eq!(keys.keys[0].exp, 1677052800);
    assert_eq!(keys.keys[0].iat, Some(1661151600));
    assert_eq!(keys.keys[0].key.kty, "RSA");
    assert!(keys.keys[0].revoked.is_none());
    let revoked = keys.keys[1].revoked.as_ref().unwrap();
    assert_eq!(revoked.revoked_at, 1661151600);
    assert_eq!(revoked.reason, Some(RevocationReason::Compromised));
    keys.validate().unwrap();
    assert_eq!(serde_json::to_value(&keys).unwrap(), claims, "the claims round-trip");
}

#[test]
fn historical_key_without_exp_fails() {
    let without_exp = json!({ "kty": "RSA", "n": "5s4qi", "e": "AQAB", "kid": "old" });
    let error = serde_json::from_value::<HistoricalKey>(without_exp).unwrap_err();
    assert!(error.to_string().contains("exp"), "{error}");

    let without_kid = HistoricalKeys::new(
        anchor_id(),
        now(),
        vec![HistoricalKey::new(key(RSA_2048_JWK, ""), now())],
    );
    assert!(without_kid.validate().unwrap_err().to_string().contains("no kid"));
}

#[test]
fn revocation_reasons_keep_their_spelling() {
    for (reason, spelling) in [
        (RevocationReason::Unspecified, "unspecified"),
        (RevocationReason::Compromised, "compromised"),
        (RevocationReason::Superseded, "superseded"),
        (
            RevocationReason::Other("key_ceremony_failed".to_string()),
            "key_ceremony_failed",
        ),
    ] {
        assert_eq!(serde_json::to_value(&reason).unwrap(), json!(spelling));
        assert_eq!(
            serde_json::from_value::<RevocationReason>(json!(spelling)).unwrap(),
            reason
        );
    }
}

#[tokio::test]
async fn signed_set_is_a_jwk_set_jwt_that_verifies_with_the_current_jwks() {
    let keys = rolled_over_keys();
    let jwt = HistoricalKeys::new(anchor_id(), now(), keys.historical_keys())
        .sign(keys.active_signer().as_ref())
        .await
        .unwrap();

    let header = jsonwebtoken::decode_header(&jwt).unwrap();
    assert_eq!(header.typ.as_deref(), Some("jwk-set+jwt"));
    assert_eq!(header.kid.as_deref(), Some("ta-2025"));
    let verified = HistoricalKeys::from_verified_jwt(&jwt, &anchor_id(), &keys.jwks()).unwrap();
    assert_eq!(verified.keys, keys.historical_keys());

    let other = EntityId::parse("https://other.example.org").unwrap();
    assert!(HistoricalKeys::from_verified_jwt(&jwt, &other, &keys.jwks()).is_err());
}

#[tokio::test]
async fn endpoint_serves_the_key_a_rollover_retired_with_its_exp() {
    let keys = rolled_over_keys();
    let store = Arc::new(InMemoryKeyStore::new());
    store.save(keys.records()).await.unwrap();
    let endpoint = HistoricalKeysEndpoint::new(anchor_id(), store, keys.active_signer());

    let response = endpoint.handle().await;

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, "application/jwk-set+jwt");
    let published = HistoricalKeys::from_verified_jwt(&response.body, &anchor_id(), &keys.jwks()).unwrap();
    assert_eq!(published.keys.len(), 1, "only the retired key, not the published ones");
    let old = &published.keys[0];
    assert_eq!(old.key, key(EC_P256_JWK, "ta-2024"));
    assert_eq!(old.exp, 1_700_000_000, "exp is when the key was retired");
    assert!(old.revoked.is_none());
}

#[tokio::test]
async fn revoked_key_carries_revoked_at_and_reason() {
    let mut keys = rolled_over_keys();
    // The retired, long-expired key turns out to have been compromised.
    keys.revoke("ta-2024", 1_750_000_000, Some(RevocationReason::Compromised))
        .unwrap();
    // A next key is revoked before it was ever used, which also retires it.
    keys.add_next(
        signer(Algorithm::PS256, "ta-2026", RSA_2048_DER),
        key(RSA_2048_JWK, "ta-2026"),
    )
    .unwrap();
    keys.revoke("ta-2026", 1_760_000_000, None).unwrap();
    assert_eq!(keys.jwks().keys.len(), 1, "a revoked key is not published");

    let store = Arc::new(InMemoryKeyStore::new());
    store.save(keys.records()).await.unwrap();
    let response = HistoricalKeysEndpoint::new(anchor_id(), store, keys.active_signer())
        .handle()
        .await;
    let published = HistoricalKeys::from_verified_jwt(&response.body, &anchor_id(), &keys.jwks()).unwrap();

    let compromised = published
        .keys
        .iter()
        .find(|key| key.key.kid.as_deref() == Some("ta-2024"))
        .unwrap();
    let revocation = compromised.revoked.as_ref().unwrap();
    assert_eq!(revocation.revoked_at, 1_750_000_000);
    assert_eq!(revocation.reason, Some(RevocationReason::Compromised));
    assert_eq!(compromised.exp, 1_700_000_000, "revoking keeps the key's exp");

    let unused = published
        .keys
        .iter()
        .find(|key| key.key.kid.as_deref() == Some("ta-2026"))
        .unwrap();
    assert_eq!(unused.exp, 1_760_000_000);
    assert_eq!(unused.revoked.as_ref().unwrap().reason, None);
}

#[test]
fn active_key_cannot_be_revoked_and_a_key_is_revoked_once() {
    let mut keys = rolled_over_keys();
    let error = keys.revoke("ta-2025", now(), None).unwrap_err();
    assert!(error.to_string().contains("is Active and cannot be revoked"), "{error}");

    keys.revoke("ta-2024", now(), None).unwrap();
    let error = keys.revoke("ta-2024", now(), None).unwrap_err();
    assert!(error.to_string().contains("already revoked"), "{error}");
}

#[tokio::test]
async fn additional_member_repeating_a_published_one_is_refused() {
    let keys = rolled_over_keys();
    let signer = keys.active_signer();
    let sign = |historical: HistoricalKey| {
        let signer = signer.clone();
        async move {
            HistoricalKeys::new(anchor_id(), now(), vec![historical])
                .sign(signer.as_ref())
                .await
        }
    };
    let retired = || keys.historical_keys().remove(0);

    let mut historical = retired();
    historical.key.additional.insert("exp".to_string(), json!(1));
    let error = sign(historical).await.unwrap_err();
    assert!(error.to_string().contains("repeats the exp member"), "{error}");

    // `iat` is published once when the historical key has none of its own.
    let mut historical = retired();
    historical.key.additional.insert("iat".to_string(), json!(1));
    sign(historical.clone()).await.unwrap();
    historical.iat = Some(2);
    let error = sign(historical).await.unwrap_err();
    assert!(error.to_string().contains("repeats the iat member"), "{error}");

    let mut historical = retired();
    let mut revocation = KeyRevocation::new(1_750_000_000, None);
    revocation.additional.insert("reason".to_string(), json!("lost"));
    historical.revoked = Some(revocation.clone());
    sign(historical.clone()).await.unwrap();
    revocation.additional.insert("revoked_at".to_string(), json!(1));
    historical.revoked = Some(revocation);
    let error = sign(historical).await.unwrap_err();
    assert!(error.to_string().contains("revocation of historical key"), "{error}");
}

#[tokio::test]
async fn verified_set_that_cannot_be_published_is_refused() {
    let keys = rolled_over_keys();
    let mut historical = keys.historical_keys();
    // A second key under the same `kid`, signed without `HistoricalKeys::sign`'s check.
    historical.push(historical[0].clone());
    let jwt = sign_federation_jwt(
        &HistoricalKeys::new(anchor_id(), now(), historical),
        JwtArtifactType::SignedJwkSet,
        keys.active_signer().as_ref(),
    )
    .await
    .unwrap();

    assert!(HistoricalKeys::from_verified_jwt(&jwt, &anchor_id(), &keys.jwks()).is_err());
}

#[test]
fn record_revoked_but_not_retired_is_refused() {
    let keys = activated_keys();
    for kid in ["ta-2024", "ta-2025"] {
        // `ta-2024` is previous, `ta-2025` active.
        let mut records = keys.records().to_vec();
        let record = records.iter_mut().find(|record| record.kid() == kid).unwrap();
        record.revoked = Some(KeyRevocation::new(now(), Some(RevocationReason::Compromised)));

        let error = FederationKeys::from_records(records, [keys.active_signer()])
            .err()
            .unwrap();
        assert!(error.to_string().contains("revoked but not retired"), "{kid}: {error}");
    }
}

#[tokio::test]
async fn revoking_a_previous_key_retires_and_publishes_it() {
    let mut keys = activated_keys();
    keys.revoke("ta-2024", 1_750_000_000, Some(RevocationReason::Compromised))
        .unwrap();
    assert_eq!(keys.jwks().keys.len(), 1, "a revoked key is not published");

    let store = Arc::new(InMemoryKeyStore::new());
    store.save(keys.records()).await.unwrap();
    let response = HistoricalKeysEndpoint::new(anchor_id(), store, keys.active_signer())
        .handle()
        .await;
    let published = HistoricalKeys::from_verified_jwt(&response.body, &anchor_id(), &keys.jwks()).unwrap();
    assert_eq!(published.keys.len(), 1);
    let revoked = &published.keys[0];
    assert_eq!(revoked.key.kid.as_deref(), Some("ta-2024"));
    assert_eq!(revoked.exp, 1_750_000_000, "revoking a previous key retires it then");
    assert_eq!(
        revoked.revoked.as_ref().unwrap().reason,
        Some(RevocationReason::Compromised)
    );
}

#[tokio::test]
async fn key_that_would_not_parse_or_decode_is_refused() {
    let keys = rolled_over_keys();
    let sign = |historical: HistoricalKey| {
        let signer = keys.active_signer();
        async move {
            HistoricalKeys::new(anchor_id(), now(), vec![historical])
                .sign(signer.as_ref())
                .await
        }
    };

    // An `nbf` that is not a NumericDate, which a verifier would read as the typed `nbf`.
    let mut historical = keys.historical_keys().remove(0);
    historical.key.additional.insert("nbf".to_string(), json!("soon"));
    let error = sign(historical).await.unwrap_err();
    assert!(error.to_string().contains("would not parse"), "{error}");

    // An RSA key without its modulus.
    let mut rsa = key(RSA_2048_JWK, "ta-2023");
    rsa.n = None;
    let error = sign(HistoricalKey::new(rsa, 1_600_000_000)).await.unwrap_err();
    assert!(!error.to_string().contains("would not parse"), "{error}");
}

/// A key store whose database is down.
struct UnreachableStore;

#[async_trait]
impl KeyStore for UnreachableStore {
    async fn load(&self) -> Result<Vec<KeyRecord>, StoreError> {
        Err(StoreError::msg("database unreachable"))
    }

    async fn save(&self, _: &[KeyRecord]) -> Result<(), StoreError> {
        Err(StoreError::msg("database unreachable"))
    }
}

#[tokio::test]
async fn store_failure_or_a_stale_signer_is_a_server_error() {
    let keys = rolled_over_keys();
    let endpoint = HistoricalKeysEndpoint::new(anchor_id(), Arc::new(UnreachableStore), keys.active_signer());
    let response = endpoint.handle().await;
    assert_eq!(response.status, 500);
    let error: ErrorResponse = serde_json::from_str(&response.body).unwrap();
    assert_eq!(error.error, ErrorCode::ServerError);
    assert!(matches!(
        endpoint.try_handle().await.unwrap_err(),
        FederationError::Store(_)
    ));

    // The signer of the retired key is no longer the active one.
    let store = Arc::new(InMemoryKeyStore::new());
    store.save(keys.records()).await.unwrap();
    let stale = HistoricalKeysEndpoint::new(
        anchor_id(),
        store.clone(),
        signer(Algorithm::ES256, "ta-2024", EC_P256_DER),
    );
    let response = stale.handle().await;
    assert_eq!(response.status, 500);
    let error: ErrorResponse = serde_json::from_str(&response.body).unwrap();
    assert_eq!(error.error, ErrorCode::ServerError);
    let error = stale.try_handle().await.unwrap_err();
    assert!(error.to_string().contains("is not the active key"), "{error}");

    // A signer under the active `kid` whose key is not the active public key.
    let mismatched = HistoricalKeysEndpoint::new(
        anchor_id(),
        store.clone(),
        signer(Algorithm::ES256, "ta-2025", EC_P256_DER),
    );
    assert_eq!(mismatched.handle().await.status, 500);
    let error = mismatched.try_handle().await.unwrap_err();
    assert!(
        matches!(error, FederationError::Configuration(_))
            && error.to_string().contains("does not sign for the active public key"),
        "{error}"
    );

    // A retired record without `retired_at`, which `FederationKeys::from_records` refuses, is not
    // left out of the set.
    let mut records = keys.records().to_vec();
    let retired = records.iter_mut().find(|record| record.kid() == "ta-2024").unwrap();
    retired.retired_at = None;
    store.save(&records).await.unwrap();
    let endpoint = HistoricalKeysEndpoint::new(anchor_id(), store, keys.active_signer());
    assert_eq!(endpoint.handle().await.status, 500);
    let error = endpoint.try_handle().await.unwrap_err();
    assert!(error.to_string().contains("\"ta-2024\" has no retired_at"), "{error}");
}
