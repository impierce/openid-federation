//! Listing Immediate Subordinates with `ListEndpoint` over a `SubordinateStore` (OpenID Federation
//! 1.0, Sections 8, 8.2.1 and 8.2.2): every subordinate without a filter, the `entity_type` and
//! `intermediate` filters from the subordinate records, `unsupported_parameter` for the Trust Mark
//! filters, and a response `FederationClient::list_entities` reads.

use async_trait::async_trait;
use openid_federation::{
    EndpointRequest, EndpointResponse, EntityId, EntityType, ErrorCode, ErrorResponse, FederationClient,
    FederationError, InMemorySubordinateStore, JwkSet, ListEndpoint, StoreError, Subordinate, SubordinateStore,
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
    assert_eq!(listed("intermediate=false").await.len(), 4, "only true filters");
}

#[tokio::test]
async fn trust_mark_filters_are_unsupported() {
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
