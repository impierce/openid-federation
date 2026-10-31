//! Signing federation artifacts through the async `Signer` trait (OpenID Federation 1.0,
//! Section 3 and Appendix A.1), with the in-memory signer over DER keys and with signers that
//! fail.
//!
//! The keys in `tests/data/signer/` are test fixtures generated once for this suite, with their
//! public halves as JWKs next to them. They protect nothing.

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, Header};
use openid_federation::{
    sign_compact_jws, sign_federation_jwt, EntityConfiguration, EntityId, FederationError, InMemorySigner, Jwk, JwkSet,
    JwtArtifactType, SignError, Signer, SubordinateStatement, TrustChain,
};
use std::sync::atomic::{AtomicUsize, Ordering};

const RSA_2048_DER: &[u8] = include_bytes!("data/signer/rsa-2048.pkcs1.der");
const RSA_2048_JWK: &str = include_str!("data/signer/rsa-2048.public.jwk.json");
const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");
const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");

/// One case per key type: the algorithm, the private key and the public JWK.
fn cases() -> [(Algorithm, &'static [u8], &'static str); 3] {
    [
        (Algorithm::ES256, EC_P256_DER, EC_P256_JWK),
        (Algorithm::PS256, RSA_2048_DER, RSA_2048_JWK),
        (Algorithm::EdDSA, ED25519_DER, ED25519_JWK),
    ]
}

fn public_jwks(jwk: &str, kid: &str) -> JwkSet {
    let mut key: Jwk = serde_json::from_str(jwk).expect("fixture JWK parses");
    key.kid = Some(kid.to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

fn entity_statement_header(signer: &dyn Signer) -> Header {
    let mut header = Header::new(signer.alg());
    header.typ = Some(JwtArtifactType::EntityStatement.header_value().to_string());
    header.kid = Some(signer.kid().to_string());
    header
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[tokio::test]
async fn entity_configuration_signed_through_signer_verifies() {
    let entity_id = EntityId::parse("https://ta.example.org").unwrap();
    for (alg, der, jwk) in cases() {
        let signer = InMemorySigner::from_der(alg, "ta-key", der).unwrap();
        let configuration =
            EntityConfiguration::new(entity_id.clone(), public_jwks(jwk, "ta-key"), now() + 3600, now());

        let jwt = sign_compact_jws(&entity_statement_header(&signer), &configuration, &signer)
            .await
            .unwrap();

        let verified =
            EntityConfiguration::from_verified_jwt(&jwt, &entity_id).unwrap_or_else(|e| panic!("{alg:?}: {e}"));
        assert_eq!(verified.claims.sub, entity_id);
        assert_eq!(jsonwebtoken::decode_header(&jwt).unwrap().alg, alg);
    }
}

#[tokio::test]
async fn trust_chain_signed_through_signers_validates() {
    let anchor_id = EntityId::parse("https://ta.example.org").unwrap();
    let leaf_id = EntityId::parse("https://op.example.org").unwrap();
    for (alg, der, jwk) in cases() {
        // One key material for both entities, under different `kid`s, keeps the fixtures small;
        // each statement is still verified against the keys endorsed for its issuer.
        let anchor_signer = InMemorySigner::from_der(alg, "ta-key", der).unwrap();
        let leaf_signer = InMemorySigner::from_der(alg, "op-key", der).unwrap();
        let anchor_keys = public_jwks(jwk, "ta-key");
        let leaf_keys = public_jwks(jwk, "op-key");

        let mut leaf = EntityConfiguration::new(leaf_id.clone(), leaf_keys.clone(), now() + 3600, now());
        leaf.authority_hints = Some(vec![anchor_id.clone()]);
        let about_leaf = SubordinateStatement::new(anchor_id.clone(), leaf_id.clone(), now() + 3600, now(), leaf_keys);
        let anchor = EntityConfiguration::new(anchor_id.clone(), anchor_keys, now() + 3600, now());

        let chain = vec![
            sign_compact_jws(&entity_statement_header(&leaf_signer), &leaf, &leaf_signer)
                .await
                .unwrap(),
            sign_compact_jws(&entity_statement_header(&anchor_signer), &about_leaf, &anchor_signer)
                .await
                .unwrap(),
            sign_compact_jws(&entity_statement_header(&anchor_signer), &anchor, &anchor_signer)
                .await
                .unwrap(),
        ];

        let chain = TrustChain::try_new(chain).unwrap_or_else(|e| panic!("{alg:?}: {e}"));
        assert_eq!(chain.trust_anchor_entity_id_and_configuration().unwrap().0, anchor_id);
        assert_eq!(chain.leaf_entity_id_and_configuration().unwrap().0, leaf_id);
    }
}

#[tokio::test]
async fn in_memory_signer_produces_jws_form_signatures() {
    // RFC 7518 Section 3.4: an ES256 signature is `r || s`, 64 bytes, not DER. Ed25519 is 64
    // bytes too, and an RSA signature is as long as the 2048-bit modulus.
    for (alg, der, len) in [
        (Algorithm::ES256, EC_P256_DER, 64),
        (Algorithm::EdDSA, ED25519_DER, 64),
        (Algorithm::PS256, RSA_2048_DER, 256),
        (Algorithm::RS256, RSA_2048_DER, 256),
    ] {
        let signer = InMemorySigner::from_der(alg, "key", der).unwrap();
        assert_eq!(signer.sign(b"input").await.unwrap().len(), len, "{alg:?}");
    }
}

#[test]
fn in_memory_signer_rejects_unusable_keys() {
    // A key of another type, a curve that does not fit the algorithm, and garbage.
    assert!(InMemorySigner::from_der(Algorithm::ES256, "key", RSA_2048_DER).is_err());
    assert!(InMemorySigner::from_der(Algorithm::PS256, "key", EC_P256_DER).is_err());
    assert!(InMemorySigner::from_der(Algorithm::EdDSA, "key", EC_P256_DER).is_err());
    assert!(InMemorySigner::from_der(Algorithm::ES384, "key", EC_P256_DER).is_err());
    assert!(matches!(
        InMemorySigner::from_der(Algorithm::ES256, "key", b"not a key"),
        Err(FederationError::Signing(_))
    ));
}

#[test]
fn in_memory_signer_rejects_symmetric_algorithms_and_empty_kid() {
    assert!(matches!(
        InMemorySigner::from_der(Algorithm::HS256, "key", b"secret"),
        Err(FederationError::Configuration(_))
    ));
    assert!(matches!(
        InMemorySigner::from_der(Algorithm::ES256, "", EC_P256_DER),
        Err(FederationError::Configuration(_))
    ));
}

#[test]
fn in_memory_signer_debug_hides_the_key() {
    let signer = InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap();
    let debug = format!("{signer:?}");
    assert!(debug.contains("ES256") && debug.contains("ta-key"), "{debug}");
    assert!(!debug.contains("key:"), "{debug}");
}

/// A signer that counts its calls and fails, like an unreachable HSM.
struct FailingSigner {
    calls: AtomicUsize,
}

#[async_trait]
impl Signer for FailingSigner {
    fn alg(&self) -> Algorithm {
        Algorithm::ES256
    }

    fn kid(&self) -> &str {
        "hsm-key"
    }

    async fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(SignError::msg("HSM unreachable"))
    }
}

#[tokio::test]
async fn failing_backend_is_an_error() {
    let signer = FailingSigner {
        calls: AtomicUsize::new(0),
    };
    let error = sign_compact_jws(&entity_statement_header(&signer), &serde_json::json!({}), &signer)
        .await
        .unwrap_err();
    assert!(matches!(error, FederationError::Signing(_)), "{error:?}");
    assert!(error.to_string().contains("HSM unreachable"), "{error}");
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn header_alg_other_than_signer_fails_before_signing() {
    let signer = FailingSigner {
        calls: AtomicUsize::new(0),
    };
    let mut header = entity_statement_header(&signer);
    header.alg = Algorithm::PS256;
    let error = sign_compact_jws(&header, &serde_json::json!({}), &signer)
        .await
        .unwrap_err();
    assert!(matches!(error, FederationError::Configuration(_)), "{error:?}");
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0, "the signer must not be called");
}

/// Wraps a signer and counts the calls that reach it.
struct Counting<S> {
    inner: S,
    calls: AtomicUsize,
}

impl<S> Counting<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
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

fn typ_and_kid(jwt: &str) -> (Option<String>, Option<String>) {
    let header = jsonwebtoken::decode_header(jwt).unwrap();
    (header.typ, header.kid)
}

#[tokio::test]
async fn entity_configuration_sign_sets_typ_and_kid() {
    let entity_id = EntityId::parse("https://ta.example.org").unwrap();
    for (alg, der, jwk) in cases() {
        let signer = InMemorySigner::from_der(alg, "ta-key", der).unwrap();
        let configuration =
            EntityConfiguration::new(entity_id.clone(), public_jwks(jwk, "ta-key"), now() + 3600, now());

        let jwt = configuration
            .sign(&signer)
            .await
            .unwrap_or_else(|e| panic!("{alg:?}: {e}"));

        assert_eq!(
            typ_and_kid(&jwt),
            (Some("entity-statement+jwt".to_string()), Some("ta-key".to_string()))
        );
        assert_eq!(
            EntityConfiguration::from_verified_jwt(&jwt, &entity_id).unwrap(),
            configuration
        );
    }
}

#[tokio::test]
async fn subordinate_statement_sign_sets_typ_and_kid() {
    let anchor_id = EntityId::parse("https://ta.example.org").unwrap();
    let leaf_id = EntityId::parse("https://op.example.org").unwrap();
    for (alg, der, jwk) in cases() {
        let signer = InMemorySigner::from_der(alg, "ta-key", der).unwrap();
        let statement = SubordinateStatement::new(
            anchor_id.clone(),
            leaf_id.clone(),
            now() + 3600,
            now(),
            public_jwks(jwk, "op-key"),
        );

        let jwt = statement.sign(&signer).await.unwrap_or_else(|e| panic!("{alg:?}: {e}"));

        assert_eq!(
            typ_and_kid(&jwt),
            (Some("entity-statement+jwt".to_string()), Some("ta-key".to_string()))
        );
        let verified =
            SubordinateStatement::from_verified_jwt(&jwt, &anchor_id, &leaf_id, &public_jwks(jwk, "ta-key")).unwrap();
        assert_eq!(verified, statement);
    }
}

#[tokio::test]
async fn entity_configuration_sign_rejects_kid_outside_own_jwks() {
    let entity_id = EntityId::parse("https://ta.example.org").unwrap();
    let signer = Counting::new(InMemorySigner::from_der(Algorithm::ES256, "other-key", EC_P256_DER).unwrap());
    let configuration = EntityConfiguration::new(entity_id, public_jwks(EC_P256_JWK, "ta-key"), now() + 3600, now());

    let error = configuration.sign(&signer).await.unwrap_err();

    assert!(matches!(error, FederationError::Configuration(_)), "{error:?}");
    assert_eq!(signer.calls(), 0, "the signer must not be called");
}

#[tokio::test]
async fn entity_configuration_sign_rejects_other_key_under_published_kid() {
    // The `kid` is in `jwks`, but it names the EC key, and the signer holds the Ed25519 key.
    let entity_id = EntityId::parse("https://ta.example.org").unwrap();
    let signer = InMemorySigner::from_der(Algorithm::EdDSA, "ta-key", ED25519_DER).unwrap();
    let configuration = EntityConfiguration::new(entity_id, public_jwks(EC_P256_JWK, "ta-key"), now() + 3600, now());

    let error = configuration.sign(&signer).await.unwrap_err();

    assert!(matches!(error, FederationError::Configuration(_)), "{error:?}");
    assert!(error.to_string().contains("does not verify"), "{error}");
}

#[tokio::test]
async fn invalid_statements_fail_before_the_signer_is_called() {
    let anchor_id = EntityId::parse("https://ta.example.org").unwrap();
    let leaf_id = EntityId::parse("https://op.example.org").unwrap();
    let signer = Counting::new(InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap());
    let keys = public_jwks(EC_P256_JWK, "ta-key");

    let expired = EntityConfiguration::new(anchor_id.clone(), keys.clone(), now() - 60, now() - 3600);
    assert!(expired.sign(&signer).await.is_err());

    let self_issued =
        SubordinateStatement::new(anchor_id.clone(), anchor_id.clone(), now() + 3600, now(), keys.clone());
    assert!(self_issued.sign(&signer).await.is_err());

    let mut private = keys.clone();
    private.keys[0].d = Some("ZA".to_string());
    let publishes_private_key =
        SubordinateStatement::new(anchor_id.clone(), leaf_id, now() + 3600, now(), private.clone());
    assert!(publishes_private_key.sign(&signer).await.is_err());
    let configuration_with_private_key = EntityConfiguration::new(anchor_id, private, now() + 3600, now());
    assert!(configuration_with_private_key.sign(&signer).await.is_err());

    assert_eq!(signer.calls(), 0, "the signer must not be called");
}

/// A signer that names no key.
struct NoKid;

#[async_trait]
impl Signer for NoKid {
    fn alg(&self) -> Algorithm {
        Algorithm::ES256
    }

    fn kid(&self) -> &str {
        ""
    }

    async fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignError> {
        unreachable!("a signer without kid must not be called")
    }
}

#[tokio::test]
async fn signer_without_kid_is_refused() {
    let error = sign_federation_jwt(&serde_json::json!({}), JwtArtifactType::EntityStatement, &NoKid)
        .await
        .unwrap_err();
    assert!(matches!(error, FederationError::Configuration(_)), "{error:?}");
}

/// A signer that claims an HMAC algorithm.
struct Symmetric;

#[async_trait]
impl Signer for Symmetric {
    fn alg(&self) -> Algorithm {
        Algorithm::HS256
    }

    fn kid(&self) -> &str {
        "hmac-key"
    }

    async fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignError> {
        unreachable!("a symmetric signer must not be called")
    }
}

#[tokio::test]
async fn symmetric_signer_is_refused() {
    let error = sign_federation_jwt(&serde_json::json!({}), JwtArtifactType::EntityStatement, &Symmetric)
        .await
        .unwrap_err();
    assert!(matches!(error, FederationError::Configuration(_)), "{error:?}");
}

#[tokio::test]
async fn additional_claim_repeating_a_typed_claim_is_refused() {
    let anchor_id = EntityId::parse("https://ta.example.org").unwrap();
    let leaf_id = EntityId::parse("https://op.example.org").unwrap();
    let signer = Counting::new(InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap());

    let mut statement = SubordinateStatement::new(
        anchor_id.clone(),
        leaf_id,
        now() + 3600,
        now(),
        public_jwks(EC_P256_JWK, "op-key"),
    );
    statement
        .claims
        .additional
        .insert("iss".to_string(), serde_json::json!("https://attacker.example"));
    let error = statement.sign(&signer).await.unwrap_err();
    assert!(error.to_string().contains("\"iss\" appears more than once"), "{error}");

    let mut configuration =
        EntityConfiguration::new(anchor_id, public_jwks(EC_P256_JWK, "ta-key"), now() + 3600, now());
    configuration
        .claims
        .additional
        .insert("jwks".to_string(), serde_json::json!({ "keys": [] }));
    assert!(configuration.sign(&signer).await.is_err());

    assert_eq!(signer.calls(), 0, "the signer must not be called");
}

const EC_P256_OTHER_DER: &[u8] = include_bytes!("data/signer/ec-p256-other.pkcs8.der");

#[tokio::test]
async fn entity_configuration_sign_rejects_other_key_of_same_algorithm() {
    // Same algorithm and published `kid`, but another P-256 key than the one in `jwks`.
    let entity_id = EntityId::parse("https://ta.example.org").unwrap();
    let signer = InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_OTHER_DER).unwrap();
    let configuration = EntityConfiguration::new(entity_id, public_jwks(EC_P256_JWK, "ta-key"), now() + 3600, now());

    let error = configuration.sign(&signer).await.unwrap_err();

    assert!(matches!(error, FederationError::Configuration(_)), "{error:?}");
    assert!(error.to_string().contains("does not verify"), "{error}");
}

fn http_anchor_hint() -> EntityId {
    EntityId::parse("http://ta.example.org").unwrap()
}

#[tokio::test]
async fn entity_identifiers_without_https_or_with_fragment_are_refused_when_signing() {
    let signer = Counting::new(InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap());
    let anchor_id = EntityId::parse("https://ta.example.org").unwrap();

    let http_anchor = EntityId::parse("http://ta.example.org").unwrap();
    let configuration = EntityConfiguration::new(
        http_anchor.clone(),
        public_jwks(EC_P256_JWK, "ta-key"),
        now() + 3600,
        now(),
    );
    let error = configuration.sign(&signer).await.unwrap_err();
    assert!(error.to_string().contains("HTTPS"), "{error}");

    let statement = SubordinateStatement::new(
        http_anchor,
        anchor_id.clone(),
        now() + 3600,
        now(),
        public_jwks(EC_P256_JWK, "op"),
    );
    assert!(statement.sign(&signer).await.is_err());

    let http_subject = EntityId::parse("http://op.example.org").unwrap();
    let statement = SubordinateStatement::new(
        anchor_id.clone(),
        http_subject.clone(),
        now() + 3600,
        now(),
        public_jwks(EC_P256_JWK, "op"),
    );
    let error = statement.sign(&signer).await.unwrap_err();
    assert!(error.to_string().contains("sub"), "{error}");

    let leaf_id = EntityId::parse("https://op.example.org").unwrap();
    for hints in ["authority_hints", "trust_anchor_hints"] {
        let mut configuration =
            EntityConfiguration::new(leaf_id.clone(), public_jwks(EC_P256_JWK, "ta-key"), now() + 3600, now());
        match hints {
            "authority_hints" => configuration.authority_hints = Some(vec![http_anchor_hint()]),
            _ => configuration.trust_anchor_hints = Some(vec![http_anchor_hint()]),
        }
        let error = configuration.sign(&signer).await.unwrap_err();
        assert!(error.to_string().contains(hints), "{error}");
    }

    let with_fragment = EntityId::parse("https://op.example.org/#frag").unwrap();
    let statement = SubordinateStatement::new(
        anchor_id,
        with_fragment,
        now() + 3600,
        now(),
        public_jwks(EC_P256_JWK, "op"),
    );
    let error = statement.sign(&signer).await.unwrap_err();
    assert!(error.to_string().contains("fragment"), "{error}");

    assert_eq!(signer.calls(), 0, "the signer must not be called");
}

fn federation_entity(fetch_endpoint: &str) -> openid_federation::EntityMetadata {
    let mut metadata = openid_federation::EntityMetadata::new();
    metadata.federation_entity = Some(openid_federation::FederationEntityMetadata {
        federation_fetch_endpoint: Some(url::Url::parse(fetch_endpoint).unwrap()),
        ..Default::default()
    });
    metadata
}

#[tokio::test]
async fn federation_entity_endpoints_are_checked_when_signing() {
    let anchor_id = EntityId::parse("https://ta.example.org").unwrap();
    let leaf_id = EntityId::parse("https://op.example.org").unwrap();
    let signer = Counting::new(InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap());

    for bad in ["https://ta.example.org/fetch#frag", "http://ta.example.org/fetch"] {
        let mut configuration = EntityConfiguration::new(
            anchor_id.clone(),
            public_jwks(EC_P256_JWK, "ta-key"),
            now() + 3600,
            now(),
        );
        configuration.metadata = Some(federation_entity(bad));
        let error = configuration.sign(&signer).await.unwrap_err();
        assert!(
            error.to_string().contains("federation_fetch_endpoint"),
            "{bad}: {error}"
        );

        let mut statement = SubordinateStatement::new(
            anchor_id.clone(),
            leaf_id.clone(),
            now() + 3600,
            now(),
            public_jwks(EC_P256_JWK, "op-key"),
        );
        statement.metadata = Some(federation_entity(bad));
        assert!(statement.sign(&signer).await.is_err(), "{bad}");
    }
    assert_eq!(signer.calls(), 0, "the signer must not be called");

    let mut configuration = EntityConfiguration::new(
        anchor_id.clone(),
        public_jwks(EC_P256_JWK, "ta-key"),
        now() + 3600,
        now(),
    );
    configuration.metadata = Some(federation_entity("https://ta.example.org:8443/fetch?tenant=1"));
    let jwt = configuration.sign(&signer).await.unwrap();
    assert_eq!(
        EntityConfiguration::from_verified_jwt(&jwt, &anchor_id).unwrap(),
        configuration
    );

    let mut statement = SubordinateStatement::new(
        anchor_id.clone(),
        leaf_id.clone(),
        now() + 3600,
        now(),
        public_jwks(EC_P256_JWK, "op-key"),
    );
    statement.metadata = Some(federation_entity("https://op.example.org/fetch"));
    let jwt = statement.sign(&signer).await.unwrap();
    let verified =
        SubordinateStatement::from_verified_jwt(&jwt, &anchor_id, &leaf_id, &public_jwks(EC_P256_JWK, "ta-key"))
            .unwrap();
    assert_eq!(verified, statement);
}
