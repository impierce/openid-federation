//! The Trust Marked Entities Listing endpoint (OpenID Federation 1.0, Section 8.5) and the Trust
//! Mark endpoint (Section 8.6) over a `TrustMarkStore`: the subjects of the active Trust Marks of
//! a type, the Trust Mark a subject holds, `404` when it holds none, and malformed requests.
//!
//! The keys in `tests/data/signer/` are test fixtures generated once for the signer suite. They
//! protect nothing.

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use openid_federation::{
    sign_federation_jwt, EndpointRequest, EndpointResponse, EntityId, ErrorCode, ErrorResponse, FederationError,
    InMemorySigner, InMemoryTrustMarkStore, IssuedTrustMark, JwtArtifactType, StoreError, TrustMark, TrustMarkEndpoint,
    TrustMarkStore, TrustMarkedEntitiesEndpoint, JSON_CONTENT_TYPE, TRUST_MARK_CONTENT_TYPE,
};
use std::sync::Arc;

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");

const SIRTFI: &str = "https://refeds.org/sirtfi";
const OTHER: &str = "https://refeds.org/other";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn entity(id: &str) -> EntityId {
    EntityId::parse(id).unwrap()
}

/// A Trust Mark of `trust_mark_type` that the issuer signed for `subject` at `iat`, valid until
/// `exp`.
async fn sign_trust_mark(subject: &str, trust_mark_type: &str, iat: i64, exp: Option<i64>) -> String {
    let trust_mark = TrustMark {
        exp,
        ..TrustMark::new(entity("https://tmi.example.org"), entity(subject), trust_mark_type, iat)
    };
    let signer = InMemorySigner::from_der(Algorithm::ES256, "tmi-key", EC_P256_DER).unwrap();
    // Signed without `TrustMark::sign`, which refuses an expired Trust Mark.
    sign_federation_jwt(&trust_mark, JwtArtifactType::TrustMark, &signer)
        .await
        .unwrap()
}

/// The store, and the JWTs it holds by name.
struct Issued {
    store: Arc<InMemoryTrustMarkStore>,
    op: String,
    op_renewed: String,
    op_other: String,
    rp: String,
    expired: String,
    revoked: String,
    future: String,
}

/// SIRTFI Trust Marks: two active ones for the OP, one without `exp` for the RP spelled with a
/// trailing slash, an expired one, a revoked one, and two issued an hour from now, one for the OP
/// and one for an entity that holds no other; and an active Trust Mark of another type for the OP.
async fn issued() -> Issued {
    let store = Arc::new(InMemoryTrustMarkStore::new());
    let issued = Issued {
        op: sign_trust_mark("https://op.example.org", SIRTFI, now() - 7200, Some(now() + 3600)).await,
        op_renewed: sign_trust_mark("https://op.example.org/", SIRTFI, now() - 60, Some(now() + 7200)).await,
        op_other: sign_trust_mark("https://op.example.org", OTHER, now() - 60, None).await,
        rp: sign_trust_mark("https://rp.example.org/", SIRTFI, now() - 60, None).await,
        expired: sign_trust_mark("https://old.example.org", SIRTFI, now() - 7200, Some(now() - 60)).await,
        revoked: sign_trust_mark("https://revoked.example.org", SIRTFI, now() - 7200, None).await,
        future: sign_trust_mark("https://future.example.org", SIRTFI, now() + 3600, None).await,
        store,
    };
    // Issued later than the OP's others, so it would be served first if it counted as active.
    let op_future = sign_trust_mark("https://op.example.org", SIRTFI, now() + 3600, None).await;
    issued.store.insert(IssuedTrustMark::from_jwt(op_future).unwrap());
    for jwt in [
        &issued.op,
        &issued.op_renewed,
        &issued.op_other,
        &issued.rp,
        &issued.expired,
        &issued.revoked,
        &issued.future,
    ] {
        issued.store.insert(IssuedTrustMark::from_jwt(jwt.as_str()).unwrap());
    }
    assert!(issued.store.revoke(&issued.revoked, now() - 10));
    issued
}

async fn listed(endpoint: &TrustMarkedEntitiesEndpoint, query: &str) -> Vec<String> {
    let response = endpoint.handle(&EndpointRequest::get(query)).await;
    assert_eq!(response.status, 200, "{query:?}: {}", response.body);
    assert_eq!(response.content_type, JSON_CONTENT_TYPE);
    serde_json::from_str(&response.body).unwrap()
}

fn query(trust_mark_type: &str, sub: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("trust_mark_type", trust_mark_type);
    if let Some(sub) = sub {
        query.append_pair("sub", sub);
    }
    query.finish()
}

fn assert_error(response: &EndpointResponse, code: ErrorCode, status: u16) {
    assert_eq!(response.status, status, "{}", response.body);
    assert_eq!(response.content_type, JSON_CONTENT_TYPE);
    let error: ErrorResponse = serde_json::from_str(&response.body).unwrap();
    assert_eq!(error.error, code);
}

/// Answers every query with every Trust Mark in `inner`, as a store with a broken query would.
struct BroadStore(Arc<InMemoryTrustMarkStore>);

#[async_trait]
impl TrustMarkStore for BroadStore {
    async fn trust_mark(&self, jwt: &str) -> Result<Option<IssuedTrustMark>, StoreError> {
        self.0.trust_mark(jwt).await
    }

    async fn trust_marks(&self, _: Option<&str>, _: Option<&EntityId>) -> Result<Vec<IssuedTrustMark>, StoreError> {
        self.0.trust_marks(None, None).await
    }
}

struct BrokenStore;

#[async_trait]
impl TrustMarkStore for BrokenStore {
    async fn trust_mark(&self, _: &str) -> Result<Option<IssuedTrustMark>, StoreError> {
        Err(StoreError::msg("database unreachable"))
    }

    async fn trust_marks(&self, _: Option<&str>, _: Option<&EntityId>) -> Result<Vec<IssuedTrustMark>, StoreError> {
        Err(StoreError::msg("database unreachable"))
    }
}

#[tokio::test]
async fn listing_names_each_subject_of_an_active_trust_mark_of_the_type_once() {
    let issued = issued().await;
    let endpoint = TrustMarkedEntitiesEndpoint::new(issued.store.clone());

    // The OP holds two, spelled two ways, and is listed once, under the spelling sorted first.
    assert_eq!(
        listed(&endpoint, &query(SIRTFI, None)).await,
        ["https://op.example.org", "https://rp.example.org/"]
    );
    assert_eq!(listed(&endpoint, &query(OTHER, None)).await, ["https://op.example.org"]);
    assert!(listed(&endpoint, &query("https://refeds.org/never-issued", None))
        .await
        .is_empty());
}

#[tokio::test]
async fn listing_sub_keeps_only_that_entity_however_it_is_spelled() {
    let issued = issued().await;
    let endpoint = TrustMarkedEntitiesEndpoint::new(issued.store.clone());

    for sub in ["https://rp.example.org", "https://rp.example.org/"] {
        assert_eq!(
            listed(&endpoint, &query(SIRTFI, Some(sub))).await,
            ["https://rp.example.org/"],
            "{sub}"
        );
    }
    for sub in [
        "https://old.example.org",
        "https://revoked.example.org",
        "https://future.example.org",
        "https://unknown.example.org",
    ] {
        assert!(listed(&endpoint, &query(SIRTFI, Some(sub))).await.is_empty(), "{sub}");
    }
    assert!(listed(&endpoint, &query(OTHER, Some("https://rp.example.org")))
        .await
        .is_empty());
}

#[tokio::test]
async fn trust_mark_endpoint_serves_the_latest_active_trust_mark() {
    let issued = issued().await;
    let endpoint = TrustMarkEndpoint::new(issued.store.clone());

    for (trust_mark_type, sub, jwt) in [
        (SIRTFI, "https://op.example.org", &issued.op_renewed),
        (SIRTFI, "https://op.example.org/", &issued.op_renewed),
        (OTHER, "https://op.example.org", &issued.op_other),
        (SIRTFI, "https://rp.example.org", &issued.rp),
    ] {
        let response = endpoint
            .handle(&EndpointRequest::get(&query(trust_mark_type, Some(sub))))
            .await;
        assert_eq!(response.status, 200, "{sub}: {}", response.body);
        assert_eq!(response.content_type, TRUST_MARK_CONTENT_TYPE);
        assert_eq!(&response.body, jwt, "{trust_mark_type} {sub}");
    }

    // Once the newer one is revoked, the older one is the latest active one.
    assert!(issued.store.revoke(&issued.op_renewed, now()));
    let response = endpoint
        .handle(&EndpointRequest::get(&query(SIRTFI, Some("https://op.example.org"))))
        .await;
    assert_eq!(response.body, issued.op);
}

#[tokio::test]
async fn trust_mark_endpoint_answers_not_found_without_an_active_trust_mark() {
    let issued = issued().await;
    let endpoint = TrustMarkEndpoint::new(issued.store.clone());

    for (trust_mark_type, sub) in [
        (SIRTFI, "https://old.example.org"),
        (SIRTFI, "https://revoked.example.org"),
        (SIRTFI, "https://future.example.org"),
        (SIRTFI, "https://unknown.example.org"),
        (OTHER, "https://rp.example.org"),
        ("https://refeds.org/never-issued", "https://op.example.org"),
    ] {
        assert_error(
            &endpoint
                .handle(&EndpointRequest::get(&query(trust_mark_type, Some(sub))))
                .await,
            ErrorCode::NotFound,
            404,
        );
    }
}

#[tokio::test]
async fn records_a_store_returns_are_checked_against_the_request() {
    let issued = issued().await;
    let broad: Arc<dyn TrustMarkStore> = Arc::new(BroadStore(issued.store.clone()));

    let listing = TrustMarkedEntitiesEndpoint::new(broad.clone());
    assert_eq!(listed(&listing, &query(OTHER, None)).await, ["https://op.example.org"]);
    assert_eq!(
        listed(&listing, &query(SIRTFI, Some("https://rp.example.org"))).await,
        ["https://rp.example.org/"]
    );

    let trust_mark = TrustMarkEndpoint::new(broad);
    let response = trust_mark
        .handle(&EndpointRequest::get(&query(OTHER, Some("https://op.example.org"))))
        .await;
    assert_eq!(response.body, issued.op_other);
    assert_error(
        &trust_mark
            .handle(&EndpointRequest::get(&query(OTHER, Some("https://rp.example.org"))))
            .await,
        ErrorCode::NotFound,
        404,
    );
}

#[tokio::test]
async fn malformed_requests_are_invalid() {
    let issued = issued().await;
    let listing = TrustMarkedEntitiesEndpoint::new(issued.store.clone());
    let trust_mark = TrustMarkEndpoint::new(issued.store.clone());

    let type_ = format!("trust_mark_type={}", urlencode(SIRTFI));
    let malformed = [
        String::new(),
        "sub=https%3A%2F%2Fop.example.org".to_string(),
        format!("{type_}&{type_}&sub=https%3A%2F%2Fop.example.org"),
        format!("{type_}&sub=https%3A%2F%2Fop.example.org&sub=https%3A%2F%2Frp.example.org"),
        format!("{type_}&sub=http%3A%2F%2Fop.example.org"),
        format!("{type_}&sub=https%3A%2F%2Fop.example.org%23fragment"),
        format!("{type_}&sub=op.example.org"),
    ];
    for query in &malformed {
        let request = EndpointRequest::get(query);
        assert_error(&listing.handle(&request).await, ErrorCode::InvalidRequest, 400);
        assert_error(&trust_mark.handle(&request).await, ErrorCode::InvalidRequest, 400);
    }
    // The Trust Mark endpoint also requires `sub`.
    assert_error(
        &trust_mark.handle(&EndpointRequest::get(&type_)).await,
        ErrorCode::InvalidRequest,
        400,
    );
}

fn urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[tokio::test]
async fn unknown_parameters_are_ignored_and_post_reads_the_body() {
    let issued = issued().await;
    let body = format!(
        "{}&client_assertion=ignored",
        query(SIRTFI, Some("https://rp.example.org"))
    );

    let listing = TrustMarkedEntitiesEndpoint::new(issued.store.clone());
    let response = listing.handle(&EndpointRequest::post(&body)).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body, r#"["https://rp.example.org/"]"#);

    let trust_mark = TrustMarkEndpoint::new(issued.store.clone());
    let response = trust_mark.handle(&EndpointRequest::post(&body)).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(response.body, issued.rp);
}

#[tokio::test]
async fn store_failure_is_a_server_error() {
    let request = EndpointRequest::get(&query(SIRTFI, Some("https://op.example.org")));

    let listing = TrustMarkedEntitiesEndpoint::new(Arc::new(BrokenStore));
    assert_error(&listing.handle(&request).await, ErrorCode::ServerError, 500);
    assert!(matches!(
        listing.try_handle(&request).await,
        Err(FederationError::Store(_))
    ));

    let trust_mark = TrustMarkEndpoint::new(Arc::new(BrokenStore));
    assert_error(&trust_mark.handle(&request).await, ErrorCode::ServerError, 500);
    assert!(matches!(
        trust_mark.try_handle(&request).await,
        Err(FederationError::Store(_))
    ));
}
