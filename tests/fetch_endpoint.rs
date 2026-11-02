//! Serving Subordinate Statements with `FetchEndpoint` over a `SubordinateStore` (OpenID
//! Federation 1.0, Sections 8, 8.1.1 and 8.1.2): mounted on wiremock servers, the fetched
//! statement completes a Trust Chain that `FederationClient` discovers and authenticates, and
//! every request the endpoint cannot answer with a statement gets the recommended error.

use async_trait::async_trait;
use chrono::Duration;
use jsonwebtoken::Algorithm;
use openid_federation::{
    EndpointRequest, EndpointResponse, EntityConfiguration, EntityId, EntityMetadata, ErrorCode, ErrorResponse,
    FederationClient, FederationEntityMetadata, FederationError, FederationResult, FetchEndpoint, HttpClient,
    HttpResponse, InMemorySigner, InMemorySubordinateStore, Jwk, JwkSet, PolicyOperators, ReqwestHttpClient, SignError,
    Signer, StoreError, Subordinate, SubordinateStatement, SubordinateStore,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");
const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn jwks(jwk: &str, kid: &str) -> JwkSet {
    let mut key: Jwk = serde_json::from_str(jwk).unwrap();
    key.kid = Some(kid.to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

fn anchor_id() -> EntityId {
    EntityId::parse("https://ta.example.org").unwrap()
}

fn anchor_jwks() -> JwkSet {
    jwks(EC_P256_JWK, "ta-key")
}

fn anchor_signer() -> Arc<InMemorySigner> {
    Arc::new(InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap())
}

fn fetch_url() -> Url {
    Url::parse("https://ta.example.org/fetch").unwrap()
}

fn leaf_id() -> EntityId {
    EntityId::parse("https://op.example.org").unwrap()
}

fn leaf_jwks() -> JwkSet {
    jwks(ED25519_JWK, "op-key")
}

fn leaf_signer() -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::EdDSA, "op-key", ED25519_DER).unwrap()
}

/// The Trust Anchor's store, with the leaf registered under a metadata policy.
fn store() -> Arc<InMemorySubordinateStore> {
    let policy: PolicyOperators = serde_json::from_value(json!({ "value": ["pairwise"] })).unwrap();
    let store = InMemorySubordinateStore::new();
    store.insert(
        Subordinate::new(leaf_id(), leaf_jwks()).with_metadata_policy(HashMap::from([(
            "openid_provider".to_string(),
            HashMap::from([("subject_types_supported".to_string(), policy)]),
        )])),
    );
    Arc::new(store)
}

fn endpoint(subordinates: Arc<dyn SubordinateStore>) -> FetchEndpoint {
    FetchEndpoint::new(anchor_id(), fetch_url(), subordinates, anchor_signer())
}

fn error_code(response: &EndpointResponse) -> ErrorCode {
    assert_eq!(response.content_type, "application/json");
    serde_json::from_str::<ErrorResponse>(&response.body).unwrap().error
}

/// Mounts a `FetchEndpoint` on a wiremock server: the request goes to the handler as an
/// `EndpointRequest`, and its `EndpointResponse` comes back as the HTTP response.
struct Mounted(Arc<FetchEndpoint>);

impl Respond for Mounted {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let endpoint = self.0.clone();
        let request = if request.method.as_str() == "POST" {
            EndpointRequest::post(&String::from_utf8_lossy(&request.body))
        } else {
            EndpointRequest::get(request.url.query().unwrap_or_default())
        };
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

/// Sends requests for the `https` Entity Identifiers of the federation to the wiremock server
/// that stands in for each host.
struct Hosts {
    servers: HashMap<String, Url>,
    inner: ReqwestHttpClient,
}

#[async_trait]
impl HttpClient for Hosts {
    async fn get(&self, mut url: Url) -> FederationResult<HttpResponse> {
        let server = &self.servers[url.host_str().unwrap()];
        url.set_scheme("http").unwrap();
        url.set_host(server.host_str()).unwrap();
        url.set_port(server.port()).unwrap();
        self.inner.get(url).await
    }
}

async fn serve_configuration(server: &MockServer, jwt: String) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-federation"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(jwt, "application/entity-statement+jwt"))
        .mount(server)
        .await;
}

#[tokio::test]
async fn discovery_authenticates_a_trust_chain_through_a_fetched_statement() {
    let anchor_server = MockServer::start().await;
    let leaf_server = MockServer::start().await;

    let mut metadata = EntityMetadata::new();
    metadata.federation_entity = Some(FederationEntityMetadata {
        federation_fetch_endpoint: Some(fetch_url()),
        federation_list_endpoint: Some(Url::parse("https://ta.example.org/list").unwrap()),
        ..Default::default()
    });
    let anchor_configuration = EntityConfiguration::new(anchor_id(), anchor_jwks(), now() + 3600, now())
        .with_metadata(metadata)
        .sign(anchor_signer().as_ref())
        .await
        .unwrap();
    serve_configuration(&anchor_server, anchor_configuration).await;
    Mock::given(path("/fetch"))
        .respond_with(Mounted(Arc::new(endpoint(store()))))
        .mount(&anchor_server)
        .await;

    let leaf_configuration = EntityConfiguration::new(leaf_id(), leaf_jwks(), now() + 3600, now())
        .with_authority_hints(vec![anchor_id()])
        .sign(&leaf_signer())
        .await
        .unwrap();
    serve_configuration(&leaf_server, leaf_configuration).await;

    let client = FederationClient::with_http_client(Hosts {
        servers: HashMap::from([
            ("ta.example.org".to_string(), Url::parse(&anchor_server.uri()).unwrap()),
            ("op.example.org".to_string(), Url::parse(&leaf_server.uri()).unwrap()),
        ]),
        inner: ReqwestHttpClient::new(),
    });

    let chain = client
        .discover_trust_chain(&leaf_id(), Some(&[anchor_id()]))
        .await
        .unwrap();

    assert_eq!(chain.len(), 3);
    assert_eq!(chain.trust_anchor_entity_id_and_configuration().unwrap().0, anchor_id());
    assert_eq!(chain.leaf_entity_id_and_configuration().unwrap().0, leaf_id());
}

#[tokio::test]
async fn statement_carries_what_the_superior_registered() {
    let response = endpoint(store())
        .with_lifetime(Duration::hours(2))
        .handle(&EndpointRequest::get("sub=https%3A%2F%2Fop.example.org"))
        .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, "application/entity-statement+jwt");
    let statement =
        SubordinateStatement::from_verified_jwt(&response.body, &anchor_id(), &leaf_id(), &anchor_jwks()).unwrap();
    assert_eq!(statement.jwks, leaf_jwks());
    assert_eq!(statement.source_endpoint.as_deref(), Some(fetch_url().as_str()));
    assert_eq!(
        statement.claims.exp - statement.claims.iat,
        Duration::hours(2).num_seconds()
    );
    assert!(statement.metadata_policy.unwrap().contains_key("openid_provider"));
}

#[tokio::test]
async fn sub_is_found_with_and_without_a_trailing_slash() {
    let endpoint = endpoint(store());
    for sub in ["https://op.example.org", "https://op.example.org/"] {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("sub", sub)
            .finish();
        let response = endpoint.handle(&EndpointRequest::get(&query)).await;
        assert_eq!(response.status, 200, "{sub}");
        let statement =
            SubordinateStatement::from_verified_jwt(&response.body, &anchor_id(), &leaf_id(), &anchor_jwks()).unwrap();
        assert_eq!(
            statement.claims.sub.as_str(),
            "https://op.example.org",
            "spelled as registered"
        );
    }
}

#[tokio::test]
async fn unknown_sub_is_not_found() {
    let response = endpoint(store())
        .handle(&EndpointRequest::get("sub=https%3A%2F%2Frp.example.org"))
        .await;
    assert_eq!(response.status, 404);
    assert_eq!(error_code(&response), ErrorCode::NotFound);
}

#[tokio::test]
async fn sub_naming_the_issuer_is_an_invalid_request() {
    for sub in ["https%3A%2F%2Fta.example.org", "https%3A%2F%2Fta.example.org%2F"] {
        let response = endpoint(store())
            .handle(&EndpointRequest::get(&format!("sub={sub}")))
            .await;
        assert_eq!(response.status, 400, "{sub}");
        assert_eq!(error_code(&response), ErrorCode::InvalidRequest);
    }
}

#[tokio::test]
async fn missing_repeated_or_malformed_sub_is_an_invalid_request() {
    for query in [
        "",
        "iss=https%3A%2F%2Fta.example.org",
        "sub=https%3A%2F%2Fop.example.org&sub=https%3A%2F%2Fop.example.org",
        "sub=not+a+url",
    ] {
        let response = endpoint(store()).handle(&EndpointRequest::get(query)).await;
        assert_eq!(response.status, 400, "{query:?}");
        assert_eq!(error_code(&response), ErrorCode::InvalidRequest, "{query:?}");
    }
}

#[tokio::test]
async fn unknown_parameters_are_ignored() {
    let response = endpoint(store())
        .handle(&EndpointRequest::get(
            "trust_anchor=https%3A%2F%2Fother.example.org&sub=https%3A%2F%2Fop.example.org&x=1&x=2",
        ))
        .await;
    assert_eq!(response.status, 200);
}

#[tokio::test]
async fn post_reads_sub_from_the_body() {
    let response = endpoint(store())
        .handle(&EndpointRequest::post(
            "sub=https%3A%2F%2Fop.example.org&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=eyJ",
        ))
        .await;
    assert_eq!(response.status, 200);
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

/// A store that answers every lookup with the same subordinate.
struct WrongStore;

#[async_trait]
impl SubordinateStore for WrongStore {
    async fn subordinate(&self, _: &EntityId) -> Result<Option<Subordinate>, StoreError> {
        Ok(Some(Subordinate::new(leaf_id(), leaf_jwks())))
    }

    async fn subordinates(&self) -> Result<Vec<Subordinate>, StoreError> {
        Ok(vec![Subordinate::new(leaf_id(), leaf_jwks())])
    }
}

/// A signer whose backend fails, like an unreachable HSM.
struct FailingSigner;

#[async_trait]
impl Signer for FailingSigner {
    fn alg(&self) -> Algorithm {
        Algorithm::ES256
    }

    fn kid(&self) -> &str {
        "ta-key"
    }

    async fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::msg("HSM unreachable"))
    }
}

fn request_for_leaf() -> EndpointRequest {
    EndpointRequest::get("sub=https%3A%2F%2Fop.example.org")
}

#[tokio::test]
async fn store_failure_is_a_server_error() {
    let endpoint = endpoint(Arc::new(UnreachableStore));

    let response = endpoint.handle(&request_for_leaf()).await;
    assert_eq!(response.status, 500);
    assert_eq!(error_code(&response), ErrorCode::ServerError);
    assert!(
        !response.body.contains("database"),
        "the cause stays private: {}",
        response.body
    );

    let error = endpoint.try_handle(&request_for_leaf()).await.unwrap_err();
    assert!(matches!(error, FederationError::Store(_)), "{error:?}");
    assert!(error.to_string().contains("database unreachable"), "{error}");
}

#[tokio::test]
async fn signer_failure_is_a_server_error() {
    let endpoint = FetchEndpoint::new(anchor_id(), fetch_url(), store(), Arc::new(FailingSigner));

    let response = endpoint.handle(&request_for_leaf()).await;
    assert_eq!(response.status, 500);
    assert_eq!(error_code(&response), ErrorCode::ServerError);

    let error = endpoint.try_handle(&request_for_leaf()).await.unwrap_err();
    assert!(matches!(error, FederationError::Signing(_)), "{error:?}");
}

#[tokio::test]
async fn store_answering_with_another_subordinate_is_a_server_error() {
    let request = EndpointRequest::get("sub=https%3A%2F%2Frp.example.org");
    let endpoint = endpoint(Arc::new(WrongStore));

    assert_eq!(endpoint.handle(&request).await.status, 500);
    let error = endpoint.try_handle(&request).await.unwrap_err();
    assert!(
        error.to_string().contains("when asked for https://rp.example.org"),
        "{error}"
    );
}

#[tokio::test]
async fn lifetime_under_a_second_is_a_server_error() {
    let endpoint = endpoint(store()).with_lifetime(Duration::milliseconds(500));
    assert_eq!(endpoint.handle(&request_for_leaf()).await.status, 500);
}
