//! Checking a candidate Subordinate before registering it (OpenID Federation 1.0, Appendix A.1,
//! Sections 10.1 and 10.2): `FederationClient::check_candidate_subordinate` fetches the
//! candidate's Entity Configuration from a wiremock server and reports every check it fails, and
//! a passing report becomes the `Subordinate` a `SubordinateStore` serves.
//!
//! The keys in `tests/data/signer/` are test fixtures generated once for the signer suite. They
//! protect nothing.

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use openid_federation::{
    sign_federation_jwt, CandidateFailure, EntityConfiguration, EntityId, EntityMetadata, EntityType, FederationClient,
    FederationEntityMetadata, FederationError, FederationResult, HttpClient, HttpResponse, InMemorySigner,
    InMemorySubordinateStore, Jwk, JwkSet, JwtArtifactType, MetadataPolicy, NamingConstraints, PolicyOperators,
    ReqwestHttpClient, SubordinatePolicy, SubordinateStore,
};
use serde_json::json;
use std::collections::HashMap;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn entity(id: &str) -> EntityId {
    EntityId::parse(id).unwrap()
}

fn superior_id() -> EntityId {
    entity("https://ia.example.org")
}

fn candidate_jwks() -> JwkSet {
    let mut key: Jwk = serde_json::from_str(ED25519_JWK).unwrap();
    key.kid = Some("op-key".to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

fn candidate_signer() -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::EdDSA, "op-key", ED25519_DER).unwrap()
}

/// The Entity Configuration of `candidate`, naming `authority_hints`, with OpenID Provider and
/// federation metadata, and a fetch endpoint when `intermediate`.
fn configuration(candidate: &EntityId, authority_hints: Vec<EntityId>, intermediate: bool) -> EntityConfiguration {
    let mut metadata: EntityMetadata = serde_json::from_value(json!({
        "openid_provider": {
            "issuer": candidate.as_str(),
            "authorization_endpoint": format!("{candidate}/authorize"),
            "jwks_uri": format!("{candidate}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
        }
    }))
    .unwrap();
    if intermediate {
        metadata.federation_entity = Some(FederationEntityMetadata {
            federation_fetch_endpoint: Some(Url::parse(&format!("{candidate}/fetch")).unwrap()),
            federation_list_endpoint: Some(Url::parse(&format!("{candidate}/list")).unwrap()),
            ..Default::default()
        });
    }
    EntityConfiguration::new(candidate.clone(), candidate_jwks(), now() + 3600, now())
        .with_authority_hints(authority_hints)
        .with_metadata(metadata)
}

/// A metadata policy that the Superior applies to its OpenID Providers.
fn metadata_policy() -> MetadataPolicy {
    let operators: PolicyOperators = serde_json::from_value(json!({ "subset_of": ["EdDSA", "ES256"] })).unwrap();
    HashMap::from([(
        "openid_provider".to_string(),
        HashMap::from([("id_token_signing_alg_values_supported".to_string(), operators)]),
    )])
}

fn example_org_only() -> NamingConstraints {
    NamingConstraints {
        permitted: Some(vec![".example.org".to_string()]),
        excluded: None,
    }
}

/// Sends requests for the candidate's `https` Entity Identifier to the wiremock server that
/// stands in for its host.
struct Host {
    server: Url,
    inner: ReqwestHttpClient,
}

#[async_trait]
impl HttpClient for Host {
    async fn get(&self, mut url: Url) -> FederationResult<HttpResponse> {
        url.set_scheme("http").unwrap();
        url.set_host(self.server.host_str()).unwrap();
        url.set_port(self.server.port()).unwrap();
        self.inner.get(url).await
    }
}

/// A client whose requests reach a wiremock server that answers the Entity Configuration
/// request with `response`.
async fn client_serving(response: ResponseTemplate) -> (FederationClient, MockServer) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-federation"))
        .respond_with(response)
        .mount(&server)
        .await;
    let client = FederationClient::with_http_client(Host {
        server: Url::parse(&server.uri()).unwrap(),
        inner: ReqwestHttpClient::new(),
    });
    (client, server)
}

async fn client_serving_jwt(jwt: String) -> (FederationClient, MockServer) {
    client_serving(ResponseTemplate::new(200).set_body_raw(jwt, "application/entity-statement+jwt")).await
}

#[tokio::test]
async fn candidate_naming_the_superior_passes_and_becomes_a_subordinate() {
    let candidate = entity("https://op.example.org");
    let jwt = configuration(&candidate, vec![superior_id()], true)
        .sign(&candidate_signer())
        .await
        .unwrap();
    let (client, _server) = client_serving_jwt(jwt).await;
    let policy = SubordinatePolicy::new()
        .with_naming_constraints(example_org_only())
        .with_metadata_policy(metadata_policy());

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &policy)
        .await;

    assert!(report.passed(), "{:?}", report.failures);
    assert_eq!(
        report.entity_types,
        vec![EntityType::FederationEntity, EntityType::OpenIdProvider]
    );
    assert!(report.intermediate);
    assert!(report.configuration.is_some());

    let subordinate = report.into_subordinate().unwrap();
    assert_eq!(subordinate.entity_id, candidate);
    assert_eq!(subordinate.jwks, candidate_jwks());
    assert_eq!(
        subordinate.entity_types,
        vec![EntityType::FederationEntity, EntityType::OpenIdProvider]
    );
    assert!(subordinate.intermediate);
    assert_eq!(subordinate.metadata_policy, Some(metadata_policy()));

    let store = InMemorySubordinateStore::new();
    store.insert(subordinate.clone());
    assert_eq!(store.subordinate(&candidate).await.unwrap(), Some(subordinate));
}

#[tokio::test]
async fn leaf_candidate_is_not_an_intermediate() {
    let candidate = entity("https://op.example.org");
    let jwt = configuration(&candidate, vec![superior_id()], false)
        .sign(&candidate_signer())
        .await
        .unwrap();
    let (client, _server) = client_serving_jwt(jwt).await;

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &SubordinatePolicy::new())
        .await;

    assert!(report.passed(), "{:?}", report.failures);
    assert_eq!(report.entity_types, vec![EntityType::OpenIdProvider]);
    assert!(!report.intermediate);
    assert!(!report.into_subordinate().unwrap().intermediate);
}

#[tokio::test]
async fn candidate_without_the_superior_in_authority_hints_is_reported() {
    let candidate = entity("https://op.example.org");
    let jwt = configuration(&candidate, vec![entity("https://other-ia.example.org")], false)
        .sign(&candidate_signer())
        .await
        .unwrap();
    let (client, _server) = client_serving_jwt(jwt).await;

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &SubordinatePolicy::new())
        .await;

    assert!(
        matches!(
            report.failures.as_slice(),
            [CandidateFailure::SuperiorNotInAuthorityHints]
        ),
        "{:?}",
        report.failures
    );
    match report.into_subordinate() {
        Err(FederationError::Configuration(message)) => assert!(
            message.contains("https://op.example.org")
                && message.contains("authority_hints does not name the Superior"),
            "{message}"
        ),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn candidate_with_a_critical_claim_passes_only_when_the_client_understands_it() {
    let candidate = entity("https://op.example.org");
    let mut configuration = configuration(&candidate, vec![superior_id()], false);
    configuration.crit = Some(vec!["x".to_string()]);
    configuration.claims.additional.insert("x".to_string(), json!(1));
    let jwt = configuration.sign(&candidate_signer()).await.unwrap();
    let (client, _server) = client_serving_jwt(jwt).await;

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &SubordinatePolicy::new())
        .await;
    assert!(
        matches!(
            report.failures.as_slice(),
            [CandidateFailure::InvalidConfiguration(error)] if error.to_string().contains("not understood")
        ),
        "{:?}",
        report.failures
    );

    let report = client
        .with_understood_claims(["x"])
        .check_candidate_subordinate(&superior_id(), &candidate, &SubordinatePolicy::new())
        .await;
    assert!(report.passed(), "{:?}", report.failures);
}

#[tokio::test]
async fn candidate_with_a_bad_self_signature_is_reported() {
    let candidate = entity("https://op.example.org");
    // Signed under the published `kid`, but with another key than the one `jwks` publishes.
    let impostor = InMemorySigner::from_der(Algorithm::ES256, "op-key", EC_P256_DER).unwrap();
    let jwt = sign_federation_jwt(
        &configuration(&candidate, vec![superior_id()], false),
        JwtArtifactType::EntityStatement,
        &impostor,
    )
    .await
    .unwrap();
    let (client, _server) = client_serving_jwt(jwt).await;

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &SubordinatePolicy::new())
        .await;

    assert!(
        matches!(report.failures.as_slice(), [CandidateFailure::InvalidConfiguration(_)]),
        "{:?}",
        report.failures
    );
    assert!(report.configuration.is_none());
    assert!(report.entity_types.is_empty() && !report.intermediate);
    assert!(report.into_subordinate().is_err());
}

#[tokio::test]
async fn candidate_outside_the_naming_constraints_is_reported() {
    let candidate = entity("https://op.example.com");
    let jwt = configuration(&candidate, vec![superior_id()], false)
        .sign(&candidate_signer())
        .await
        .unwrap();
    let (client, _server) = client_serving_jwt(jwt).await;
    let policy = SubordinatePolicy::new().with_naming_constraints(example_org_only());

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &policy)
        .await;

    assert!(
        matches!(report.failures.as_slice(), [CandidateFailure::OutsideNamingConstraints]),
        "{:?}",
        report.failures
    );
    // The configuration itself verified.
    assert!(report.configuration.is_some());
    assert!(report.into_subordinate().is_err());
}

#[tokio::test]
async fn unreachable_candidate_is_reported_with_the_checks_that_need_no_configuration() {
    let candidate = entity("https://op.example.com");
    let (client, _server) = client_serving(ResponseTemplate::new(404)).await;
    let policy = SubordinatePolicy::new()
        .with_naming_constraints(example_org_only())
        .with_metadata_policy(HashMap::new());

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &policy)
        .await;

    assert!(
        matches!(
            report.failures.as_slice(),
            [
                CandidateFailure::ConfigurationUnreachable(FederationError::Endpoint(_)),
                CandidateFailure::OutsideNamingConstraints,
                CandidateFailure::InvalidMetadataPolicy(_),
            ]
        ),
        "{:?}",
        report.failures
    );
    assert!(report.configuration.is_none());
    let message = report.into_subordinate().unwrap_err().to_string();
    assert!(
        message.contains("could not be fetched")
            && message.contains("naming constraints")
            && message.contains("metadata policy"),
        "{message}"
    );
}

#[tokio::test]
async fn candidate_whose_jwks_cannot_be_published_is_reported() {
    let candidate = entity("https://op.example.org");
    let mut configuration = configuration(&candidate, vec![superior_id()], false);
    // The same key twice under one `kid`: the self-signature verifies, but a Subordinate
    // Statement cannot publish the set.
    let key = configuration.jwks.keys[0].clone();
    configuration.jwks.add_key(key);
    let jwt = sign_federation_jwt(&configuration, JwtArtifactType::EntityStatement, &candidate_signer())
        .await
        .unwrap();
    let (client, _server) = client_serving_jwt(jwt).await;

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &SubordinatePolicy::new())
        .await;

    assert!(
        matches!(report.failures.as_slice(), [CandidateFailure::InvalidJwks(_)]),
        "{:?}",
        report.failures
    );
}

#[tokio::test]
async fn invalid_metadata_policy_is_reported() {
    let candidate = entity("https://op.example.org");
    let jwt = configuration(&candidate, vec![superior_id()], false)
        .sign(&candidate_signer())
        .await
        .unwrap();
    let (client, _server) = client_serving_jwt(jwt).await;
    // `subset_of` and `superset_of` that cannot both hold (Section 6.1.3.1).
    let operators: PolicyOperators = serde_json::from_value(json!({
        "subset_of": ["EdDSA"],
        "superset_of": ["ES256"],
    }))
    .unwrap();
    let policy = SubordinatePolicy::new().with_metadata_policy(HashMap::from([(
        "openid_provider".to_string(),
        HashMap::from([("id_token_signing_alg_values_supported".to_string(), operators)]),
    )]));

    let report = client
        .check_candidate_subordinate(&superior_id(), &candidate, &policy)
        .await;

    assert!(
        matches!(
            report.failures.as_slice(),
            [CandidateFailure::InvalidMetadataPolicy(
                FederationError::InvalidMetadata(_)
            )]
        ),
        "{:?}",
        report.failures
    );
}

#[test]
fn entity_types_follow_the_metadata_members() {
    let metadata: EntityMetadata = serde_json::from_value(json!({
        "oauth_resource": {},
        "zz_custom": {},
        "oauth_client": {},
        "federation_entity": {},
        "aa_custom": {},
        // Not metadata of an Entity Type, which is a JSON object (Section 5).
        "null_custom": null,
        "string_custom": "x",
    }))
    .unwrap();

    assert_eq!(
        metadata.entity_types(),
        vec![
            EntityType::FederationEntity,
            EntityType::OauthClient,
            EntityType::OauthResource,
            EntityType::Other("aa_custom".to_string()),
            EntityType::Other("zz_custom".to_string()),
        ]
    );
    assert!(!metadata.has_entity_type(&EntityType::Other("null_custom".to_string())));
    assert!(metadata.has_entity_type(&EntityType::Other("aa_custom".to_string())));
    assert!(!metadata.has_entity_type(&EntityType::Other("string_custom".to_string())));
    assert!(EntityMetadata::new().entity_types().is_empty());
}
