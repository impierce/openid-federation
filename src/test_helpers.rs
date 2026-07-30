//! Shared test helpers for OpenID Federation tests.

#![cfg(test)]

use crate::{
    EntityConfiguration, EntityMetadata, FederationEntityMetadata, Jwk, JwkSet, JwtArtifactType, JwtProcessor,
    SubordinateStatement,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{Algorithm, EncodingKey};
use url::Url;
use wiremock::{
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

pub const TEST_SECRET: &str = "your-256-bit-secret-key-here-minimum-32-bytes!!!!";

pub fn test_encoding_key() -> EncodingKey {
    EncodingKey::from_secret(TEST_SECRET.as_bytes())
}

pub fn test_jwk_set() -> JwkSet {
    let mut jwks = JwkSet::new();
    jwks.add_key(Jwk {
        kty: "oct".to_string(),
        use_: Some("sig".to_string()),
        key_ops: None,
        alg: Some("HS256".to_string()),
        kid: Some("test-key".to_string()),
        x5u: None,
        x5c: None,
        x5t: None,
        x5t_s256: None,
        n: None,
        e: None,
        d: None,
        p: None,
        q: None,
        dp: None,
        dq: None,
        qi: None,
        crv: None,
        x: None,
        y: None,
        k: Some(URL_SAFE_NO_PAD.encode(TEST_SECRET.as_bytes())),
    });
    jwks
}

pub fn future_expiration() -> i64 {
    (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp()
}

pub fn build_federation_metadata(fetch_endpoint: Url) -> EntityMetadata {
    let mut metadata = EntityMetadata::new();
    metadata.federation_entity = Some(FederationEntityMetadata {
        organization_name: Some("Test Federation".to_string()),
        homepage_uri: None,
        policy_uri: None,
        logo_uri: None,
        contacts: None,
        federation_fetch_endpoint: Some(fetch_endpoint),
        federation_list_endpoint: None,
        federation_resolve_endpoint: None,
        federation_trust_mark_status_endpoint: None,
        federation_historical_keys_endpoint: None,
    });
    metadata
}

pub fn build_entity_configuration(
    entity_id: &Url,
    authority_hints: Option<Vec<Url>>,
    fetch_endpoint: Option<Url>,
) -> EntityConfiguration {
    let mut config = EntityConfiguration::new(
        entity_id.clone(),
        test_jwk_set(),
        future_expiration(),
        chrono::Utc::now().timestamp(),
    );

    if let Some(hints) = authority_hints {
        config.authority_hints = Some(hints);
    }

    if let Some(endpoint) = fetch_endpoint {
        config.metadata = Some(build_federation_metadata(endpoint));
    }

    config
}

pub fn build_subordinate_statement(issuer: &Url, subject: &Url) -> SubordinateStatement {
    SubordinateStatement::new(
        issuer.clone(),
        subject.clone(),
        future_expiration(),
        chrono::Utc::now().timestamp(),
        test_jwk_set(),
    )
}

pub fn build_fetch_endpoint(entity_id: &Url) -> Url {
    let mut endpoint = entity_id.clone();
    endpoint.set_path("/federation_fetch_endpoint");
    endpoint.set_query(None);
    endpoint
}

pub fn encode_entity_configuration(config: &EntityConfiguration) -> String {
    let processor = JwtProcessor::new();
    processor
        .sign_jwt(
            config,
            &test_encoding_key(),
            Algorithm::HS256,
            JwtArtifactType::EntityStatement,
            Some("test-key".to_string()),
        )
        .expect("entity configuration JWT should sign")
}

pub fn encode_entity_statement(statement: &SubordinateStatement) -> String {
    let processor = JwtProcessor::new();
    processor
        .sign_jwt(
            statement,
            &test_encoding_key(),
            Algorithm::HS256,
            JwtArtifactType::EntityStatement,
            Some("test-key".to_string()),
        )
        .expect("entity statement JWT should sign")
}

pub async fn mock_entity_configuration(server: &MockServer, jwt: String) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-federation"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(jwt)
                .insert_header("content-type", "application/entity-statement+jwt"),
        )
        .mount(server)
        .await;
}

pub async fn mock_subordinate_statement(server: &MockServer, subject: &Url, jwt: String) {
    Mock::given(method("GET"))
        .and(path("/federation_fetch_endpoint"))
        .and(query_param("sub", subject.as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(jwt)
                .insert_header("content-type", "application/entity-statement+jwt"),
        )
        .mount(server)
        .await;
}
