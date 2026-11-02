//! The Trust Mark Status endpoint (OpenID Federation 1.0, Section 8.4): a Trust Mark Issuer
//! reports, as a signed `trust-mark-status-response+jwt`, whether a Trust Mark it recorded in its
//! `TrustMarkStore` is active, expired, revoked or invalid, and answers `404` for one it does
//! not know.
//!
//! The keys in `tests/data/signer/` are test fixtures generated once for the signer suite. They
//! protect nothing.

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use openid_federation::{
    sign_federation_jwt, EndpointRequest, EndpointResponse, EntityId, ErrorCode, ErrorResponse, FederationError,
    InMemorySigner, InMemoryTrustMarkStore, IssuedTrustMark, Jwk, JwkSet, JwtArtifactType, StoreError, TrustMark,
    TrustMarkStatus, TrustMarkStatusEndpoint, TrustMarkStatusResponse, TrustMarkStore,
    TRUST_MARK_STATUS_RESPONSE_CONTENT_TYPE,
};
use std::sync::Arc;

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");
const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");

const SIRTFI: &str = "https://refeds.org/sirtfi";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn entity(id: &str) -> EntityId {
    EntityId::parse(id).unwrap()
}

fn issuer() -> EntityId {
    entity("https://tmi.example.org")
}

fn subject() -> EntityId {
    entity("https://op.example.org")
}

fn signer() -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::ES256, "tmi-key", EC_P256_DER).unwrap()
}

fn issuer_keys() -> JwkSet {
    let mut key: Jwk = serde_json::from_str(EC_P256_JWK).unwrap();
    key.kid = Some("tmi-key".to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

/// A Trust Mark of `trust_mark_type` that the issuer signs for `subject`, valid until `exp`.
async fn sign_trust_mark(subject: EntityId, trust_mark_type: &str, exp: Option<i64>) -> String {
    let trust_mark = TrustMark {
        exp,
        ..TrustMark::new(issuer(), subject, trust_mark_type, now() - 3600)
    };
    // Signed without `TrustMark::sign`, which refuses an expired Trust Mark.
    sign_federation_jwt(&trust_mark, JwtArtifactType::TrustMark, &signer())
        .await
        .unwrap()
}

fn endpoint(store: Arc<dyn TrustMarkStore>) -> TrustMarkStatusEndpoint {
    TrustMarkStatusEndpoint::new(issuer(), store, Arc::new(signer()))
}

fn status_request(trust_mark: &str) -> EndpointRequest {
    EndpointRequest::post(&format!("trust_mark={trust_mark}"))
}

/// The verified status response in `response`, which must be about `trust_mark`.
fn status_of(response: &EndpointResponse, trust_mark: &str) -> TrustMarkStatus {
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.content_type, TRUST_MARK_STATUS_RESPONSE_CONTENT_TYPE);
    let header = jsonwebtoken::decode_header(&response.body).unwrap();
    assert_eq!(header.typ.as_deref(), Some("trust-mark-status-response+jwt"));
    assert_eq!(header.kid.as_deref(), Some("tmi-key"));
    let verified = TrustMarkStatusResponse::from_verified_jwt(&response.body, &issuer(), &issuer_keys()).unwrap();
    assert_eq!(verified.trust_mark, trust_mark);
    assert!((now() - verified.iat).abs() < 60, "{}", verified.iat);
    verified.status
}

fn assert_error(response: &EndpointResponse, code: ErrorCode, status: u16) {
    assert_eq!(response.status, status, "{}", response.body);
    let error: ErrorResponse = serde_json::from_str(&response.body).unwrap();
    assert_eq!(error.error, code);
}

#[tokio::test]
async fn issued_trust_mark_is_active_until_it_expires_or_is_revoked() {
    let store = Arc::new(InMemoryTrustMarkStore::new());
    let active = sign_trust_mark(subject(), SIRTFI, Some(now() + 3600)).await;
    let without_exp = sign_trust_mark(entity("https://rp.example.org"), SIRTFI, None).await;
    let expired = sign_trust_mark(entity("https://old.example.org"), SIRTFI, Some(now() - 60)).await;
    for jwt in [&active, &without_exp, &expired] {
        store.insert(IssuedTrustMark::from_jwt(jwt.as_str()).unwrap());
    }
    let endpoint = endpoint(store.clone());

    for (jwt, status) in [
        (&active, TrustMarkStatus::Active),
        (&without_exp, TrustMarkStatus::Active),
        (&expired, TrustMarkStatus::Expired),
    ] {
        assert_eq!(status_of(&endpoint.handle(&status_request(jwt)).await, jwt), status);
    }

    // A revocation outranks expiry, and a later revocation keeps the first one.
    let revoked_at = now() - 10;
    assert!(store.revoke(&active, revoked_at));
    assert!(store.revoke(&expired, revoked_at));
    assert!(store.revoke(&active, revoked_at + 5));
    assert_eq!(
        store.trust_mark(&active).await.unwrap().unwrap().revoked_at,
        Some(revoked_at)
    );
    for jwt in [&active, &expired] {
        assert_eq!(
            status_of(&endpoint.handle(&status_request(jwt)).await, jwt),
            TrustMarkStatus::Revoked
        );
    }
    assert!(!store.revoke("eyJ.unknown.jwt", now()));
}

#[tokio::test]
async fn trust_mark_with_another_signature_is_invalid() {
    let store = Arc::new(InMemoryTrustMarkStore::new());
    let issued = sign_trust_mark(subject(), SIRTFI, None).await;
    store.insert(IssuedTrustMark::from_jwt(issued.as_str()).unwrap());

    // The same claims, signed under the issuer's `kid` with another key.
    let impostor = InMemorySigner::from_der(Algorithm::EdDSA, "tmi-key", ED25519_DER).unwrap();
    let claims = IssuedTrustMark::from_jwt(issued.as_str()).unwrap().claims;
    let forged = sign_federation_jwt(&claims, JwtArtifactType::TrustMark, &impostor)
        .await
        .unwrap();
    assert_ne!(forged, issued);

    let response = endpoint(store).handle(&status_request(&forged)).await;
    assert_eq!(status_of(&response, &forged), TrustMarkStatus::Invalid);
}

#[tokio::test]
async fn unknown_trust_mark_is_not_found() {
    let store = Arc::new(InMemoryTrustMarkStore::new());
    store.insert(IssuedTrustMark::from_jwt(sign_trust_mark(subject(), SIRTFI, None).await).unwrap());
    let endpoint = endpoint(store);

    // Not in the store: another subject, another type, or another issuer.
    let other_subject = sign_trust_mark(entity("https://rp.example.org"), SIRTFI, None).await;
    let other_type = sign_trust_mark(subject(), "https://refeds.org/other", None).await;
    let other_issuer = sign_federation_jwt(
        &TrustMark::new(entity("https://other-tmi.example.org"), subject(), SIRTFI, now()),
        JwtArtifactType::TrustMark,
        &signer(),
    )
    .await
    .unwrap();
    for jwt in [other_subject, other_type, other_issuer] {
        assert_error(&endpoint.handle(&status_request(&jwt)).await, ErrorCode::NotFound, 404);
    }
}

#[tokio::test]
async fn malformed_request_is_invalid_request() {
    let store = Arc::new(InMemoryTrustMarkStore::new());
    let issued = sign_trust_mark(subject(), SIRTFI, None).await;
    store.insert(IssuedTrustMark::from_jwt(issued.as_str()).unwrap());
    let endpoint = endpoint(store);
    let entity_statement = sign_federation_jwt(
        &TrustMark::new(issuer(), subject(), SIRTFI, now()),
        JwtArtifactType::EntityStatement,
        &signer(),
    )
    .await
    .unwrap();

    for request in [
        EndpointRequest::get(&format!("trust_mark={issued}")),
        EndpointRequest::post(""),
        EndpointRequest::post(&format!("trust_mark={issued}&trust_mark={issued}")),
        status_request("not-a-jwt"),
        status_request(&entity_statement),
    ] {
        assert_error(&endpoint.handle(&request).await, ErrorCode::InvalidRequest, 400);
    }

    // Parameters other than `trust_mark`, such as client authentication, are ignored.
    let request = EndpointRequest::post(&format!("client_assertion=x&trust_mark={issued}"));
    assert_eq!(
        status_of(&endpoint.handle(&request).await, &issued),
        TrustMarkStatus::Active
    );
}

/// A store that cannot be reached, or that answers with another Trust Mark than asked for.
struct BrokenStore {
    answer: Option<IssuedTrustMark>,
}

#[async_trait]
impl TrustMarkStore for BrokenStore {
    async fn trust_mark(&self, _jwt: &str) -> Result<Option<IssuedTrustMark>, StoreError> {
        match &self.answer {
            Some(answer) => Ok(Some(answer.clone())),
            None => Err(StoreError::new(std::io::Error::other("database unreachable"))),
        }
    }

    async fn trust_marks(&self, _trust_mark_type: &str) -> Result<Vec<IssuedTrustMark>, StoreError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn store_failure_is_a_server_error() {
    let issued = sign_trust_mark(subject(), SIRTFI, None).await;

    let unreachable = endpoint(Arc::new(BrokenStore { answer: None }));
    assert_error(
        &unreachable.handle(&status_request(&issued)).await,
        ErrorCode::ServerError,
        500,
    );
    assert!(matches!(
        unreachable.try_handle(&status_request(&issued)).await,
        Err(FederationError::Store(_))
    ));

    let other = sign_trust_mark(entity("https://rp.example.org"), SIRTFI, None).await;
    let confused = endpoint(Arc::new(BrokenStore {
        answer: Some(IssuedTrustMark::from_jwt(other).unwrap()),
    }));
    assert!(matches!(
        confused.try_handle(&status_request(&issued)).await,
        Err(FederationError::Configuration(_))
    ));
}

#[tokio::test]
async fn issued_trust_mark_must_be_a_trust_mark_jwt() {
    let entity_statement = sign_federation_jwt(
        &TrustMark::new(issuer(), subject(), SIRTFI, now()),
        JwtArtifactType::EntityStatement,
        &signer(),
    )
    .await
    .unwrap();
    for jwt in [entity_statement.as_str(), "not-a-jwt"] {
        assert!(matches!(
            IssuedTrustMark::from_jwt(jwt),
            Err(FederationError::InvalidTrustMark(_))
        ));
    }

    let store = InMemoryTrustMarkStore::new();
    let sirtfi = sign_trust_mark(subject(), SIRTFI, None).await;
    let other = sign_trust_mark(subject(), "https://refeds.org/other", None).await;
    assert!(store
        .insert(IssuedTrustMark::from_jwt(sirtfi.as_str()).unwrap())
        .is_none());
    assert!(store.insert(IssuedTrustMark::from_jwt(other).unwrap()).is_none());
    assert!(store
        .insert(IssuedTrustMark::from_jwt(sirtfi.as_str()).unwrap())
        .is_some());
    let of_type = store.trust_marks(SIRTFI).await.unwrap();
    assert_eq!(of_type.len(), 1);
    assert_eq!(of_type[0].jwt, sirtfi);
}

/// Figures 36 and 37, and a status value a federation defines.
#[test]
fn section_8_4_2_examples_deserialize() {
    for (status, expected) in [
        ("active", TrustMarkStatus::Active),
        ("revoked", TrustMarkStatus::Revoked),
        ("expired", TrustMarkStatus::Expired),
        ("invalid", TrustMarkStatus::Invalid),
        ("suspended", TrustMarkStatus::Other("suspended".to_string())),
    ] {
        let response: TrustMarkStatusResponse = serde_json::from_value(serde_json::json!({
            "iss": "https://www.agid.gov.it",
            "trust_mark": "eyJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9.e30.c2ln",
            "iat": 1759897995,
            "status": status,
        }))
        .unwrap();
        assert_eq!(response.status, expected);
        assert_eq!(serde_json::to_value(&response).unwrap()["status"], status);
    }
}

#[tokio::test]
async fn status_response_is_checked_before_signing_and_after_verifying() {
    let signer = signer();
    let mut empty = TrustMarkStatusResponse::new(issuer(), now(), "", TrustMarkStatus::Active);
    assert!(matches!(
        empty.sign(&signer).await,
        Err(FederationError::InvalidTrustMark(_))
    ));
    empty.trust_mark = "eyJ.a.b".to_string();
    empty.status = TrustMarkStatus::Other(String::new());
    assert!(matches!(
        empty.sign(&signer).await,
        Err(FederationError::InvalidTrustMark(_))
    ));

    let mut repeated = TrustMarkStatusResponse::new(issuer(), now(), "eyJ.a.b", TrustMarkStatus::Active);
    repeated.additional.insert("status".to_string(), "revoked".into());
    assert!(matches!(
        repeated.sign(&signer).await,
        Err(FederationError::InvalidTrustMark(_))
    ));

    let future = TrustMarkStatusResponse::new(issuer(), now() + 3600, "eyJ.a.b", TrustMarkStatus::Active);
    assert!(matches!(
        future.sign(&signer).await,
        Err(FederationError::InvalidTrustMark(_))
    ));

    let http = TrustMarkStatusResponse::new(
        entity("http://tmi.example.org"),
        now(),
        "eyJ.a.b",
        TrustMarkStatus::Active,
    );
    assert!(matches!(
        http.sign(&signer).await,
        Err(FederationError::Configuration(_))
    ));

    let jwt = TrustMarkStatusResponse::new(issuer(), now(), "eyJ.a.b", TrustMarkStatus::Active)
        .sign(&signer)
        .await
        .unwrap();
    assert!(matches!(
        TrustMarkStatusResponse::from_verified_jwt(&jwt, &entity("https://other.example.org"), &issuer_keys()),
        Err(FederationError::InvalidTrustMark(_))
    ));
    // A Trust Mark is not a status response.
    let trust_mark = sign_trust_mark(subject(), SIRTFI, None).await;
    assert!(TrustMarkStatusResponse::from_verified_jwt(&trust_mark, &issuer(), &issuer_keys()).is_err());
}
