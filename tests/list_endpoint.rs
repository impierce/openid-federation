//! Listing Immediate Subordinates with `ListEndpoint` over a `SubordinateStore` (OpenID Federation
//! 1.0, Sections 8, 8.2.1 and 8.2.2): every subordinate without a filter, the `entity_type` and
//! `intermediate` filters from the subordinate records, the Trust Mark filters from a
//! `TrustMarkStore` and `unsupported_parameter` for them without one, and a response
//! `FederationClient::list_entities` reads.
//!
//! The keys in `tests/data/signer/` are test fixtures generated once for the signer suite. They
//! protect nothing.

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use openid_federation::{
    sign_federation_jwt, EndpointRequest, EndpointResponse, EntityId, EntityType, ErrorCode, ErrorResponse,
    FederationClient, FederationError, InMemorySigner, InMemorySubordinateStore, InMemoryTrustMarkStore,
    IssuedTrustMark, JwkSet, JwtArtifactType, ListEndpoint, StoreError, Subordinate, SubordinateStore, TrustMark,
    TrustMarkStore,
};
use std::sync::Arc;
use url::Url;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

fn subordinate(id: &str, entity_types: Vec<EntityType>) -> Subordinate {
    Subordinate::new(EntityId::parse(id).unwrap(), JwkSet::new()).with_entity_types(entity_types)
}

/// An OP, an RP, an entity that is both, and an Intermediate Entity.
fn endpoint() -> ListEndpoint {
    let store = InMemorySubordinateStore::new();
    store.insert(subordinate(
        "https://op.example.org",
        vec![EntityType::FederationEntity, EntityType::OpenIdProvider],
    ));
    store.insert(subordinate(
        "https://rp.example.org/app",
        vec![EntityType::OpenIdRelyingParty],
    ));
    store.insert(subordinate(
        "https://both.example.org/",
        vec![EntityType::OpenIdProvider, EntityType::OpenIdRelyingParty],
    ));
    store.insert(
        subordinate("https://intermediate.example.org", vec![EntityType::FederationEntity]).with_intermediate(true),
    );
    ListEndpoint::new(Arc::new(store))
}

async fn listed(query: &str) -> Vec<String> {
    let response = endpoint().handle(&EndpointRequest::get(query)).await;
    assert_eq!(response.status, 200, "{query:?}: {}", response.body);
    assert_eq!(response.content_type, "application/json");
    serde_json::from_str(&response.body).unwrap()
}

fn error_code(response: &EndpointResponse) -> ErrorCode {
    assert_eq!(response.content_type, "application/json");
    serde_json::from_str::<ErrorResponse>(&response.body).unwrap().error
}

#[tokio::test]
async fn no_filter_lists_every_subordinate_as_it_spells_its_identifier() {
    assert_eq!(
        listed("").await,
        [
            "https://both.example.org/",
            "https://intermediate.example.org",
            "https://op.example.org",
            "https://rp.example.org/app",
        ]
    );
}

#[tokio::test]
async fn entity_type_filters_keep_subordinates_with_every_given_type() {
    assert_eq!(
        listed("entity_type=openid_provider").await,
        ["https://both.example.org/", "https://op.example.org"]
    );
    assert_eq!(
        listed("entity_type=openid_provider&entity_type=openid_relying_party").await,
        ["https://both.example.org/"]
    );
    assert!(listed("entity_type=oauth_resource").await.is_empty());
    assert_eq!(
        listed("entity_type=openid_provider&entity_type=openid_provider&entity_type=openid_relying_party").await,
        ["https://both.example.org/"],
        "a repeated type filters as one"
    );
}

#[tokio::test]
async fn entity_type_defined_elsewhere_filters_too() {
    let store = InMemorySubordinateStore::new();
    store.insert(subordinate(
        "https://wallet.example.org",
        vec![EntityType::Other("openid_wallet_provider".to_string())],
    ));
    store.insert(subordinate("https://op.example.org", vec![EntityType::OpenIdProvider]));
    let response = ListEndpoint::new(Arc::new(store))
        .handle(&EndpointRequest::get("entity_type=openid_wallet_provider"))
        .await;
    assert_eq!(response.body, r#"["https://wallet.example.org"]"#);
}

#[tokio::test]
async fn intermediate_true_keeps_only_intermediate_entities() {
    assert_eq!(listed("intermediate=true").await, ["https://intermediate.example.org"]);
    assert_eq!(
        listed("intermediate=true&entity_type=openid_provider").await,
        Vec::<String>::new()
    );
    assert_eq!(
        listed("intermediate=true&entity_type=federation_entity").await,
        ["https://intermediate.example.org"]
    );
    assert_eq!(listed("intermediate=false").await.len(), 4, "only true filters");
}

#[tokio::test]
async fn trust_mark_filters_are_unsupported_without_a_trust_mark_store() {
    for query in [
        "trust_marked=true",
        "trust_mark_type=https%3A%2F%2Fexample.org%2Fmarks%2Fcertified",
    ] {
        let response = endpoint().handle(&EndpointRequest::get(query)).await;
        assert_eq!(response.status, 400, "{query:?}");
        assert_eq!(error_code(&response), ErrorCode::UnsupportedParameter, "{query:?}");
    }
    assert_eq!(listed("trust_marked=false").await.len(), 4, "only true filters");
}

const SIRTFI: &str = "https://refeds.org/sirtfi";
const OTHER: &str = "https://refeds.org/other";

/// A Trust Mark of `trust_mark_type` for `subject`, valid until `exp`, recorded in `store`.
async fn issue(store: &InMemoryTrustMarkStore, subject: &str, trust_mark_type: &str, exp: Option<i64>) -> String {
    let now = chrono::Utc::now().timestamp();
    let trust_mark = TrustMark {
        exp: exp.map(|exp| now + exp),
        ..TrustMark::new(
            EntityId::parse("https://tmi.example.org").unwrap(),
            EntityId::parse(subject).unwrap(),
            trust_mark_type,
            now - 7200,
        )
    };
    let signer = InMemorySigner::from_der(
        Algorithm::ES256,
        "tmi-key",
        include_bytes!("data/signer/ec-p256.pkcs8.der"),
    )
    .unwrap();
    // Signed without `TrustMark::sign`, which refuses an expired Trust Mark.
    let jwt = sign_federation_jwt(&trust_mark, JwtArtifactType::TrustMark, &signer)
        .await
        .unwrap();
    store.insert(IssuedTrustMark::from_jwt(jwt.as_str()).unwrap());
    jwt
}

/// Active SIRTFI Trust Marks for the OP, spelled with a trailing slash, and for the entity that is
/// both, spelled without; an active Trust Mark of another type for the RP; an expired and a
/// revoked one for the Intermediate Entity; and an active one for an entity that is no
/// subordinate.
async fn trust_marks() -> Arc<InMemoryTrustMarkStore> {
    let store = Arc::new(InMemoryTrustMarkStore::new());
    issue(&store, "https://op.example.org/", SIRTFI, Some(3600)).await;
    issue(&store, "https://both.example.org", SIRTFI, None).await;
    issue(&store, "https://rp.example.org/app", OTHER, None).await;
    issue(&store, "https://intermediate.example.org", SIRTFI, Some(-60)).await;
    let revoked = issue(&store, "https://intermediate.example.org", OTHER, None).await;
    assert!(store.revoke(&revoked, 0));
    issue(&store, "https://stranger.example.org", SIRTFI, None).await;
    store
}

async fn listed_with(endpoint: &ListEndpoint, query: &str) -> Vec<String> {
    let response = endpoint.handle(&EndpointRequest::get(query)).await;
    assert_eq!(response.status, 200, "{query:?}: {}", response.body);
    serde_json::from_str(&response.body).unwrap()
}

#[tokio::test]
async fn trust_mark_filters_keep_subordinates_with_an_active_trust_mark() {
    let endpoint = endpoint().with_trust_marks(trust_marks().await);
    let sirtfi = format!("trust_mark_type={}", SIRTFI.replace(':', "%3A").replace('/', "%2F"));
    let other = format!("trust_mark_type={}", OTHER.replace(':', "%3A").replace('/', "%2F"));

    for (query, expected) in [
        (
            "trust_marked=true".to_string(),
            &[
                "https://both.example.org/",
                "https://op.example.org",
                "https://rp.example.org/app",
            ][..],
        ),
        (sirtfi.clone(), &["https://both.example.org/", "https://op.example.org"]),
        (other.clone(), &["https://rp.example.org/app"]),
        (
            format!("{sirtfi}&trust_marked=false"),
            &["https://both.example.org/", "https://op.example.org"],
        ),
        (
            format!("{sirtfi}&trust_marked=true"),
            &["https://both.example.org/", "https://op.example.org"],
        ),
        (
            "trust_marked=true&entity_type=openid_relying_party".to_string(),
            &["https://both.example.org/", "https://rp.example.org/app"],
        ),
        (format!("{other}&intermediate=true"), &[]),
        (
            "trust_mark_type=https%3A%2F%2Frefeds.org%2Fnever-issued".to_string(),
            &[],
        ),
    ] {
        assert_eq!(listed_with(&endpoint, &query).await, expected, "{query}");
    }
    assert_eq!(listed_with(&endpoint, "trust_marked=false").await.len(), 4);
}

#[tokio::test]
async fn trust_mark_filters_check_the_records_the_store_returns() {
    /// Answers every query with every Trust Mark, as a store with a broken query would.
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

    let endpoint = endpoint().with_trust_marks(Arc::new(BroadStore(trust_marks().await)));
    assert_eq!(
        listed_with(&endpoint, "trust_mark_type=https%3A%2F%2Frefeds.org%2Fother").await,
        ["https://rp.example.org/app"]
    );
}

#[tokio::test]
async fn trust_mark_store_failure_is_a_server_error() {
    struct UnreachableTrustMarks;

    #[async_trait]
    impl TrustMarkStore for UnreachableTrustMarks {
        async fn trust_mark(&self, _: &str) -> Result<Option<IssuedTrustMark>, StoreError> {
            Err(StoreError::msg("database unreachable"))
        }

        async fn trust_marks(&self, _: Option<&str>, _: Option<&EntityId>) -> Result<Vec<IssuedTrustMark>, StoreError> {
            Err(StoreError::msg("database unreachable"))
        }
    }

    let endpoint = endpoint().with_trust_marks(Arc::new(UnreachableTrustMarks));
    let request = EndpointRequest::get("trust_marked=true");
    let response = endpoint.handle(&request).await;
    assert_eq!(response.status, 500);
    assert_eq!(error_code(&response), ErrorCode::ServerError);
    let error = endpoint.try_handle(&request).await.unwrap_err();
    assert!(matches!(error, FederationError::Store(_)), "{error:?}");

    // A request without a Trust Mark filter does not ask the Trust Mark store.
    assert_eq!(listed_with(&endpoint, "").await.len(), 4);
}

#[tokio::test]
async fn malformed_boolean_or_repeated_filter_is_an_invalid_request() {
    for query in [
        "intermediate=yes",
        "intermediate=true&intermediate=true",
        "trust_marked=1",
    ] {
        let response = endpoint().handle(&EndpointRequest::get(query)).await;
        assert_eq!(response.status, 400, "{query:?}");
        assert_eq!(error_code(&response), ErrorCode::InvalidRequest, "{query:?}");
    }

    let endpoint = endpoint().with_trust_marks(Arc::new(InMemoryTrustMarkStore::new()));
    for query in [
        "trust_marked=yes",
        "trust_marked=true&trust_marked=true",
        "trust_mark_type=a&trust_mark_type=b",
    ] {
        let response = endpoint.handle(&EndpointRequest::get(query)).await;
        assert_eq!(response.status, 400, "{query:?}");
        assert_eq!(error_code(&response), ErrorCode::InvalidRequest, "{query:?}");
    }
}

#[tokio::test]
async fn unknown_parameters_are_ignored_and_post_reads_the_body() {
    assert_eq!(listed("sub=https%3A%2F%2Fop.example.org&x=1&x=2").await.len(), 4);
    let response = endpoint()
        .handle(&EndpointRequest::post("intermediate=true&client_assertion=eyJ"))
        .await;
    assert_eq!(response.body, r#"["https://intermediate.example.org"]"#);
}

/// A store whose database is down.
struct UnreachableStore;

#[async_trait]
impl SubordinateStore for UnreachableStore {
    async fn subordinate(&self, _: &EntityId) -> Result<Option<Subordinate>, StoreError> {
        Err(StoreError::msg("database unreachable"))
    }

    async fn subordinates(&self) -> Result<Vec<Subordinate>, StoreError> {
        Err(StoreError::msg("database unreachable"))
    }
}

#[tokio::test]
async fn store_failure_is_a_server_error() {
    let endpoint = ListEndpoint::new(Arc::new(UnreachableStore));
    let request = EndpointRequest::get("");

    let response = endpoint.handle(&request).await;
    assert_eq!(response.status, 500);
    assert_eq!(error_code(&response), ErrorCode::ServerError);
    assert!(
        !response.body.contains("database"),
        "the cause stays private: {}",
        response.body
    );

    let error = endpoint.try_handle(&request).await.unwrap_err();
    assert!(matches!(error, FederationError::Store(_)), "{error:?}");
}

/// Mounts a `ListEndpoint` on a wiremock server.
struct Mounted(Arc<ListEndpoint>);

impl Respond for Mounted {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let endpoint = self.0.clone();
        let request = EndpointRequest::get(request.url.query().unwrap_or_default());
        // `Respond` is synchronous, so the handler runs to completion on a runtime of its own.
        let response = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(endpoint.handle(&request))
        })
        .join()
        .unwrap();
        ResponseTemplate::new(response.status).set_body_raw(response.body, &response.content_type)
    }
}

#[tokio::test]
async fn list_entities_reads_the_response() {
    let server = MockServer::start().await;
    Mock::given(path("/list"))
        .respond_with(Mounted(Arc::new(endpoint())))
        .mount(&server)
        .await;
    let mut list_endpoint = Url::parse(&format!("{}/list", server.uri())).unwrap();
    list_endpoint.set_query(Some("entity_type=openid_relying_party"));

    let entities = FederationClient::new().list_entities(&list_endpoint).await.unwrap();

    let spelled: Vec<&str> = entities.iter().map(EntityId::as_str).collect();
    assert_eq!(spelled, ["https://both.example.org/", "https://rp.example.org/app"]);
}
