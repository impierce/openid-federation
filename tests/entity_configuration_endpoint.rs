//! Serving an Entity Configuration with `EntityConfigurationEndpoint` (OpenID Federation 1.0,
//! Sections 9, 9.1 and 9.2): a `200` with `application/entity-statement+jwt` and a configuration
//! the entity's own keys verify, re-signed before it expires, mounted at the well-known path, and
//! a `server_error` when it cannot be signed.

use async_trait::async_trait;
use chrono::Duration;
use jsonwebtoken::Algorithm;
use openid_federation::{
    EntityConfiguration, EntityConfigurationEndpoint, EntityId, ErrorCode, ErrorResponse, FederationError,
    InMemorySigner, Jwk, JwkSet, SignError, Signer,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");

fn jwks(kid: &str) -> JwkSet {
    let mut key: Jwk = serde_json::from_str(EC_P256_JWK).unwrap();
    key.kid = Some(kid.to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

fn entity_id() -> EntityId {
    EntityId::parse("https://ta.example.org").unwrap()
}

/// The configuration to serve. Its `iat` and `exp` are long past: the endpoint stamps its own.
fn configuration() -> EntityConfiguration {
    EntityConfiguration::new(entity_id(), jwks("ta-key"), 1, 0)
}

fn signer() -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap()
}

/// Wraps a signer and counts the calls that reach it.
struct Counting<S> {
    inner: S,
    calls: AtomicUsize,
}

impl<S> Counting<S> {
    fn new(inner: S) -> Arc<Self> {
        Arc::new(Self {
            inner,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl<S: Signer> Signer for Counting<S> {
    fn alg(&self) -> Algorithm {
        self.inner.alg()
    }

    fn kid(&self) -> &str {
        self.inner.kid()
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(signing_input).await
    }
}

/// A signer whose backend fails, like an unreachable HSM, under the kid the configuration
/// publishes.
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

#[tokio::test]
async fn serves_an_entity_configuration_its_own_keys_verify() {
    let endpoint =
        EntityConfigurationEndpoint::new(configuration(), Arc::new(signer())).with_lifetime(Duration::hours(6));

    let response = endpoint.handle().await;

    assert_eq!(response.status, 200);
    assert_eq!(response.content_type, "application/entity-statement+jwt");
    let served = EntityConfiguration::from_verified_jwt(&response.body, &entity_id(), &[]).unwrap();
    let now = chrono::Utc::now().timestamp();
    assert!((now - 5..=now).contains(&served.claims.iat), "iat is the signing time");
    assert_eq!(served.claims.exp - served.claims.iat, Duration::hours(6).num_seconds());
}

#[tokio::test]
async fn cached_configuration_is_served_until_it_nears_exp() {
    let signer = Counting::new(signer());
    let endpoint = EntityConfigurationEndpoint::new(configuration(), signer.clone())
        .with_lifetime(Duration::hours(1))
        .with_refresh_margin(Duration::minutes(5));

    let first = endpoint.handle().await;
    let second = endpoint.handle().await;

    assert_eq!(signer.calls(), 1, "the cached configuration is far from exp");
    assert_eq!(first, second);
}

/// Waits until the clock reads at least `timestamp`, in whole seconds as `iat` and `exp` count.
async fn wait_until(timestamp: i64) {
    while chrono::Utc::now().timestamp() < timestamp {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn cached_configuration_is_re_signed_once_it_expires_within_the_refresh_margin() {
    let signer = Counting::new(signer());
    let endpoint = EntityConfigurationEndpoint::new(configuration(), signer.clone())
        .with_lifetime(Duration::seconds(3))
        .with_refresh_margin(Duration::seconds(1));
    // Start at the beginning of a second, so the requests below fall in the seconds they name.
    wait_until(chrono::Utc::now().timestamp() + 1).await;

    let first = endpoint.handle().await;
    let exp = EntityConfiguration::from_verified_jwt(&first.body, &entity_id(), &[])
        .unwrap()
        .claims
        .exp;
    assert_eq!(signer.calls(), 1);

    // One second before the margin begins, the cached configuration is still served.
    wait_until(exp - 2).await;
    assert_eq!(endpoint.handle().await, first);
    assert_eq!(signer.calls(), 1, "re-signed before exp - refresh_margin");

    // From exp - refresh_margin on, a fresh one is signed.
    wait_until(exp - 1).await;
    let refreshed = endpoint.handle().await;
    assert_eq!(signer.calls(), 2, "not re-signed at exp - refresh_margin");
    let refreshed = EntityConfiguration::from_verified_jwt(&refreshed.body, &entity_id(), &[]).unwrap();
    assert!(refreshed.claims.exp > exp);
}

#[tokio::test]
async fn configuration_within_the_refresh_margin_of_exp_is_re_signed() {
    let signer = Counting::new(signer());
    // Every configuration expires within the margin as soon as it is signed.
    let endpoint = EntityConfigurationEndpoint::new(configuration(), signer.clone())
        .with_lifetime(Duration::minutes(1))
        .with_refresh_margin(Duration::minutes(2));

    for expected_calls in 1..=3 {
        let response = endpoint.handle().await;
        assert_eq!(response.status, 200);
        EntityConfiguration::from_verified_jwt(&response.body, &entity_id(), &[]).unwrap();
        assert_eq!(signer.calls(), expected_calls);
    }
}

#[test]
fn mount_path_is_the_well_known_path_of_the_entity_identifier() {
    for (id, path) in [
        (
            "https://example.org/federation/",
            "/federation/.well-known/openid-federation",
        ),
        (
            "https://example.org/federation",
            "/federation/.well-known/openid-federation",
        ),
        ("https://example.org", "/.well-known/openid-federation"),
    ] {
        let id = EntityId::parse(id).unwrap();
        let configuration = EntityConfiguration::new(id.clone(), jwks("ta-key"), 1, 0);
        let endpoint = EntityConfigurationEndpoint::new(configuration, Arc::new(signer()));
        assert_eq!(endpoint.path(), path, "{id}");
        assert_eq!(id.entity_configuration_url().path(), path, "{id}");
    }
}

#[tokio::test]
async fn signer_failure_is_a_server_error() {
    let endpoint = EntityConfigurationEndpoint::new(configuration(), Arc::new(FailingSigner));

    let response = endpoint.handle().await;

    assert_eq!(response.status, 500);
    assert_eq!(response.content_type, "application/json");
    let error: ErrorResponse = serde_json::from_str(&response.body).unwrap();
    assert_eq!(error.error, ErrorCode::ServerError);
    assert!(
        !error.error_description.contains("HSM"),
        "the cause stays private: {error}"
    );

    let error = endpoint.try_handle().await.unwrap_err();
    assert!(matches!(error, FederationError::Signing(_)), "{error:?}");
    assert!(error.to_string().contains("HSM unreachable"), "{error}");
}

#[tokio::test]
async fn lifetime_and_refresh_margin_are_checked() {
    for (lifetime, margin, message) in [
        (
            Duration::zero(),
            Duration::zero(),
            "lifetime must be at least one second",
        ),
        (
            Duration::milliseconds(500),
            Duration::zero(),
            "lifetime must be at least one second",
        ),
        (
            Duration::hours(1),
            Duration::seconds(-1),
            "refresh margin must not be negative",
        ),
    ] {
        let endpoint = EntityConfigurationEndpoint::new(configuration(), Arc::new(signer()))
            .with_lifetime(lifetime)
            .with_refresh_margin(margin);
        let error = endpoint.try_handle().await.unwrap_err();
        assert!(matches!(error, FederationError::Configuration(_)), "{error:?}");
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[tokio::test]
async fn configuration_the_signer_cannot_sign_for_is_a_server_error() {
    // The signer's kid is not in the configuration's jwks, so verifiers could not check it.
    let configuration = EntityConfiguration::new(entity_id(), jwks("other-key"), 1, 0);
    let endpoint = EntityConfigurationEndpoint::new(configuration, Arc::new(signer()));

    assert_eq!(endpoint.handle().await.status, 500);
    let error = endpoint.try_handle().await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not a key in the Entity Configuration's own jwks"),
        "{error}"
    );
}
