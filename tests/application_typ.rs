//! Signing and verifying an application's own federation artifacts under a `typ` it defines,
//! with the checks the specification's artifacts get: `typ` before decoding, the `kid` lookup in
//! the issuer's `jwks`, the signature and the time claims (OpenID Federation 1.0, Section 3.1.1;
//! RFC 8725, Section 3.11).

use jsonwebtoken::{Algorithm, EncodingKey};
use openid_federation::{sign_federation_jwt_with_typ, FederationError, InMemorySigner, Jwk, JwkSet, JwtProcessor};
use serde_json::{json, Value};

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_OTHER_DER: &[u8] = include_bytes!("data/signer/ec-p256-other.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");
const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");

const LIST_TYP: &str = "example-list+jwt";

fn jwks(jwk: &str, kid: &str) -> JwkSet {
    let mut key: Jwk = serde_json::from_str(jwk).unwrap();
    key.kid = Some(kid.to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

fn claims() -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": "https://ta.example.org",
        "sub": "https://ta.example.org",
        "iat": now,
        "exp": now + 3600,
        "entries": ["https://rp.example.org"]
    })
}

async fn signed(claims: &Value, typ: &str) -> String {
    let signer = InMemorySigner::from_der(Algorithm::ES256, "key", EC_P256_DER).unwrap();
    sign_federation_jwt_with_typ(claims, typ, &signer).await.unwrap()
}

fn verify(jwt: &str) -> Result<Value, FederationError> {
    JwtProcessor::new().verify_jwt_with_jwks_typ(jwt, &jwks(EC_P256_JWK, "key"), LIST_TYP)
}

/// A JWT signed under an application `typ` carries it and the signer's `kid`, and verifies
/// against the signer's `jwks`.
#[tokio::test]
async fn application_artifact_round_trips() {
    let claims = claims();
    let jwt = signed(&claims, LIST_TYP).await;
    let header = jsonwebtoken::decode_header(&jwt).unwrap();
    assert_eq!(header.typ.as_deref(), Some(LIST_TYP));
    assert_eq!(header.kid.as_deref(), Some("key"));
    assert_eq!(verify(&jwt).unwrap(), claims);
}

/// A JWT under another `typ` fails before its signature is checked; so do a missing `kid` in the
/// set, a tampered payload and a signature made with another key.
#[tokio::test]
async fn application_artifact_checks_typ_kid_and_signature() {
    let claims = claims();

    let other_typ = signed(&claims, "other-list+jwt").await;
    let error = verify(&other_typ).unwrap_err();
    assert!(matches!(error, FederationError::InvalidJwtHeaderTyp(_)), "{error:?}");

    let jwt = signed(&claims, LIST_TYP).await;
    let error = JwtProcessor::new()
        .verify_jwt_with_jwks_typ::<Value>(&jwt, &jwks(EC_P256_JWK, "other-key"), LIST_TYP)
        .unwrap_err();
    assert!(error.to_string().contains("no key in the jwks has the kid"), "{error}");

    let mut parts: Vec<String> = jwt.split('.').map(str::to_string).collect();
    let mut tampered = claims.clone();
    tampered["entries"] = json!(["https://attacker.example.org"]);
    parts[1] = base64_url(&serde_json::to_vec(&tampered).unwrap());
    assert!(verify(&parts.join(".")).is_err());

    let other_key = InMemorySigner::from_der(Algorithm::ES256, "key", EC_P256_OTHER_DER).unwrap();
    let forged = sign_federation_jwt_with_typ(&claims, LIST_TYP, &other_key)
        .await
        .unwrap();
    assert!(verify(&forged).is_err());
}

/// The `typ` of one of the specification's artifacts is refused as an application `typ`, with
/// or without the `application/` prefix and in any case, when signing and when verifying.
#[tokio::test]
async fn specification_typ_is_refused() {
    let signer = InMemorySigner::from_der(Algorithm::ES256, "key", EC_P256_DER).unwrap();
    let jwt = signed(&claims(), LIST_TYP).await;
    let key = EncodingKey::from_ed_der(ED25519_DER);
    for typ in [
        "entity-statement+jwt",
        "application/entity-statement+jwt",
        "Trust-Mark+JWT",
        "jwk-set+jwt",
        "",
    ] {
        let error = sign_federation_jwt_with_typ(&claims(), typ, &signer).await.unwrap_err();
        assert!(matches!(error, FederationError::Configuration(_)), "{typ:?}: {error:?}");
        let error = JwtProcessor::new()
            .sign_jwt_with_typ(&claims(), &key, Algorithm::EdDSA, typ, Some("key".to_string()))
            .unwrap_err();
        assert!(matches!(error, FederationError::Configuration(_)), "{typ:?}: {error:?}");
        let error = JwtProcessor::new()
            .verify_jwt_with_jwks_typ::<Value>(&jwt, &jwks(EC_P256_JWK, "key"), typ)
            .unwrap_err();
        assert!(matches!(error, FederationError::Configuration(_)), "{typ:?}: {error:?}");
    }
}

/// `exp` is required and checked, as is `nbf`, as for the specification's artifacts. A
/// non-integer NumericDate is read as `verify_jwt` reads it.
#[tokio::test]
async fn application_artifact_checks_time_claims() {
    let now = chrono::Utc::now().timestamp();

    let mut expired = claims();
    expired["exp"] = json!(now - 3600);
    let error = verify(&signed(&expired, LIST_TYP).await).unwrap_err();
    assert!(error.to_string().to_lowercase().contains("expired"), "{error}");

    let mut immature = claims();
    immature["nbf"] = json!(now + 3600);
    let error = verify(&signed(&immature, LIST_TYP).await).unwrap_err();
    assert!(error.to_string().to_lowercase().contains("immature"), "{error}");

    let mut without_exp = claims();
    without_exp.as_object_mut().unwrap().remove("exp");
    let error = verify(&signed(&without_exp, LIST_TYP).await).unwrap_err();
    assert!(error.to_string().contains("exp"), "{error}");

    let mut fractional = claims();
    fractional["exp"] = json!(now as f64 + 3600.5);
    verify(&signed(&fractional, LIST_TYP).await).unwrap();
    fractional["exp"] = json!(now as f64 - 3600.5);
    assert!(verify(&signed(&fractional, LIST_TYP).await).is_err());
}

/// `JwtProcessor::sign_jwt_with_typ` and `verify_jwt_with_typ` do the same with keys at hand.
#[test]
fn processor_signs_and_verifies_with_keys() {
    let claims = claims();
    let processor = JwtProcessor::new();
    let jwt = processor
        .sign_jwt_with_typ(
            &claims,
            &EncodingKey::from_ed_der(ED25519_DER),
            Algorithm::EdDSA,
            LIST_TYP,
            Some("key".to_string()),
        )
        .unwrap();
    let key = jwks(ED25519_JWK, "key").keys[0].to_decoding_key().unwrap();
    let verified: Value = processor
        .verify_jwt_with_typ(&jwt, &key, Algorithm::EdDSA, LIST_TYP)
        .unwrap();
    assert_eq!(verified, claims);
    let error = processor
        .verify_jwt_with_typ::<Value>(&jwt, &key, Algorithm::EdDSA, "other-list+jwt")
        .unwrap_err();
    assert!(matches!(error, FederationError::InvalidJwtHeaderTyp(_)), "{error:?}");
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(bytes)
}
