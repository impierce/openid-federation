//! Verifying a Trust Mark that an Entity presents (OpenID Federation 1.0, Sections 7.2.2, 7.3
//! and 17.5): the examples of Sections 7.4 and 7.5, re-signed by the test, verify, and each step
//! of the validation rejects what it should. `FederationClient` establishes trust in the Trust
//! Mark Issuer through a Trust Chain first, and stores the Trust Marks of a Trust Chain's leaf
//! that verify.
//!
//! The keys in `tests/data/signer/` are test fixtures generated once for the signer suite. They
//! protect nothing.

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use openid_federation::{
    sign_federation_jwt, EntityConfiguration, EntityId, EntityMetadata, FederationClient, FederationEntityMetadata,
    FederationError, FederationResult, HttpClient, HttpResponse, InMemorySigner, Jwk, JwkSet, JwtArtifactType,
    SubordinateStatement, TrustMark, TrustMarkDelegation, TrustMarkEntry, TrustMarkIssuers, TrustMarkOwner,
    TrustMarkOwners, TrustMarkRejection,
};
use serde_json::json;
use std::collections::HashMap;
use url::Url;

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");
const ED25519_DER: &[u8] = include_bytes!("data/signer/ed25519.pkcs8.der");
const ED25519_JWK: &str = include_str!("data/signer/ed25519.public.jwk.json");
const RSA_2048_DER: &[u8] = include_bytes!("data/signer/rsa-2048.pkcs1.der");
const RSA_2048_JWK: &str = include_str!("data/signer/rsa-2048.public.jwk.json");

/// Section 7.5: the Trust Mark Issuer, the owner of the type, the subject and the type.
const TMI: &str = "https://tmi.example.org";
const OWNER: &str = "https://tm-owner.example.org";
const SUBJECT: &str = "https://entity.example.org";
const SIRTFI: &str = "https://refeds.org/sirtfi";
const ANCHOR: &str = "https://ta.example.org";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn entity(id: &str) -> EntityId {
    EntityId::parse(id).unwrap()
}

fn jwks(jwk: &str, kid: &str) -> JwkSet {
    let mut key: Jwk = serde_json::from_str(jwk).unwrap();
    key.kid = Some(kid.to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

/// The Trust Mark Issuer's key: EC P-256 under `tmi-key`.
fn issuer_signer() -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::ES256, "tmi-key", EC_P256_DER).unwrap()
}

fn issuer_keys() -> JwkSet {
    jwks(EC_P256_JWK, "tmi-key")
}

/// The owner's key: RSA under `owner-key`, as in Figure 26.
fn owner_signer() -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::RS256, "owner-key", RSA_2048_DER).unwrap()
}

/// The Trust Anchor's key: Ed25519 under `ta-key`.
fn anchor_signer() -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::EdDSA, "ta-key", ED25519_DER).unwrap()
}

/// The Trust Anchor's Entity Configuration, recognizing `issuers` per type and naming the owner
/// of SIRTFI when `owned` is set.
fn anchor(issuers: &[(&str, &[&str])], owned: bool) -> EntityConfiguration {
    let mut anchor = EntityConfiguration::new(entity(ANCHOR), jwks(ED25519_JWK, "ta-key"), now() + 3600, now());
    let mut metadata = EntityMetadata::new();
    metadata.federation_entity = Some(FederationEntityMetadata {
        federation_fetch_endpoint: Some(Url::parse(&format!("{ANCHOR}/fetch")).unwrap()),
        ..Default::default()
    });
    anchor.metadata = Some(metadata);
    anchor.trust_mark_issuers = Some(TrustMarkIssuers {
        by_type: issuers
            .iter()
            .map(|(trust_mark_type, issuers)| {
                (
                    trust_mark_type.to_string(),
                    issuers.iter().map(|id| entity(id)).collect(),
                )
            })
            .collect(),
    });
    if owned {
        anchor.trust_mark_owners = Some(TrustMarkOwners {
            by_type: HashMap::from([(
                SIRTFI.to_string(),
                TrustMarkOwner {
                    sub: entity(OWNER),
                    jwks: jwks(RSA_2048_JWK, "owner-key"),
                    additional: HashMap::new(),
                },
            )]),
        });
    }
    anchor
}

/// Figure 27, issued now: the owner lets the Trust Mark Issuer issue SIRTFI Trust Marks.
fn delegation() -> TrustMarkDelegation {
    TrustMarkDelegation::new(entity(OWNER), entity(TMI), SIRTFI, now() - 60)
}

/// Figure 25, issued now and valid for a month, carrying `delegation` when given.
fn sirtfi(delegation: Option<String>) -> TrustMark {
    TrustMark {
        exp: Some(now() + 30 * 24 * 3600),
        delegation,
        ..TrustMark::new(entity(TMI), entity(SUBJECT), SIRTFI, now() - 60)
    }
}

/// `claims` signed with `signer` as `artifact`, without the checks of `TrustMark::sign`.
async fn sign<T: serde::Serialize>(claims: &T, artifact: JwtArtifactType, signer: &InMemorySigner) -> String {
    sign_federation_jwt(claims, artifact, signer).await.unwrap()
}

async fn delegated_sirtfi() -> String {
    let delegation = sign(&delegation(), JwtArtifactType::TrustMarkDelegation, &owner_signer()).await;
    sign(&sirtfi(Some(delegation)), JwtArtifactType::TrustMark, &issuer_signer()).await
}

fn verify(jwt: &str, anchor: &EntityConfiguration) -> FederationResult<TrustMark> {
    TrustMark::from_verified_jwt(jwt, &entity(SUBJECT), &entity(TMI), &issuer_keys(), anchor)
}

fn rejection<T: std::fmt::Debug>(result: FederationResult<T>) -> TrustMarkRejection {
    match result {
        Err(FederationError::TrustMarkRejected(rejection)) => *rejection,
        other => panic!("expected a rejected Trust Mark, got {other:?}"),
    }
}

#[tokio::test]
async fn section_7_4_trust_mark_verifies() {
    // Figure 19, re-signed by its issuer.
    let issuer = "https://epigeo.tm-issuer.example.it";
    let subject = entity("https://porcino.example.com/rp");
    let trust_mark_type = "https://mushrooms.federation.example.com/openid_relying_party/public/";
    let mut claims = TrustMark::new(entity(issuer), subject.clone(), trust_mark_type, now() - 60);
    claims.additional = serde_json::from_value(json!({
        "organization_name": "Porcino Mushrooms & Co.",
        "policy_uri": "https://porcino.example.com/privacy_policy",
        "tos_uri": "https://porcino.example.com/info_policy",
        "service_documentation": "https://porcino.example.com/api/v1/get/services",
    }))
    .unwrap();
    claims.r#ref = Some(Url::parse("https://porcino.example.com/documentation/manuale_operativo.pdf").unwrap());
    let jwt = claims.sign(&issuer_signer()).await.unwrap();

    // Recognized by name, and by an empty list, which lets anyone issue the type.
    for recognized in [&[issuer][..], &[]] {
        let anchor = anchor(&[(trust_mark_type, recognized)], false);
        let verified = TrustMark::from_verified_jwt(&jwt, &subject, &entity(issuer), &issuer_keys(), &anchor).unwrap();
        assert_eq!(verified, claims);
    }
}

#[tokio::test]
async fn section_7_5_delegated_trust_mark_verifies() {
    let jwt = delegated_sirtfi().await;
    let verified = verify(&jwt, &anchor(&[(SIRTFI, &[TMI])], true)).unwrap();
    assert_eq!(verified.iss, entity(TMI));
    assert_eq!(verified.sub, entity(SUBJECT));
    assert!(verified.delegation.is_some());
}

#[tokio::test]
async fn trust_mark_itself_is_checked_before_the_trust_anchor_policy() {
    let anchor = anchor(&[(SIRTFI, &[TMI])], false);

    // Typed as an Entity Statement.
    let wrong_type = sign(&sirtfi(None), JwtArtifactType::EntityStatement, &issuer_signer()).await;
    assert!(matches!(
        rejection(verify(&wrong_type, &anchor)),
        TrustMarkRejection::NotATrustMark(_)
    ));
    assert!(matches!(
        rejection(verify("not-a-jwt", &anchor)),
        TrustMarkRejection::NotATrustMark(_)
    ));

    // About another entity, or presented as the Trust Mark of another issuer.
    let jwt = sign(&sirtfi(None), JwtArtifactType::TrustMark, &issuer_signer()).await;
    assert_eq!(
        rejection(TrustMark::from_verified_jwt(
            &jwt,
            &entity("https://other.example.org"),
            &entity(TMI),
            &issuer_keys(),
            &anchor
        )),
        TrustMarkRejection::SubjectMismatch {
            expected: entity("https://other.example.org"),
            sub: entity(SUBJECT),
        }
    );
    assert!(matches!(
        rejection(TrustMark::from_verified_jwt(
            &jwt,
            &entity(SUBJECT),
            &entity("https://other-tmi.example.org"),
            &issuer_keys(),
            &anchor
        )),
        TrustMarkRejection::IssuerMismatch { .. }
    ));

    // Issued an hour from now, or expired an hour ago.
    let future = TrustMark {
        iat: now() + 3600,
        ..sirtfi(None)
    };
    let future = sign(&future, JwtArtifactType::TrustMark, &issuer_signer()).await;
    assert_eq!(rejection(verify(&future, &anchor)), TrustMarkRejection::IssuedInFuture);
    let expired = TrustMark {
        iat: now() - 7200,
        exp: Some(now() - 3600),
        ..sirtfi(None)
    };
    let expired = sign(&expired, JwtArtifactType::TrustMark, &issuer_signer()).await;
    assert_eq!(rejection(verify(&expired, &anchor)), TrustMarkRejection::Expired);

    // Signed under the issuer's `kid` with another key.
    let impostor = InMemorySigner::from_der(Algorithm::EdDSA, "tmi-key", ED25519_DER).unwrap();
    let forged = sign(&sirtfi(None), JwtArtifactType::TrustMark, &impostor).await;
    assert!(matches!(
        rejection(verify(&forged, &anchor)),
        TrustMarkRejection::InvalidSignature(_)
    ));

    // An empty type, which `TrustMark::validate` refuses.
    let untyped = TrustMark {
        trust_mark_type: String::new(),
        ..sirtfi(None)
    };
    let untyped = sign(&untyped, JwtArtifactType::TrustMark, &issuer_signer()).await;
    assert!(matches!(
        rejection(verify(&untyped, &anchor)),
        TrustMarkRejection::Invalid(_)
    ));

    verify(&jwt, &anchor).unwrap();
}

#[tokio::test]
async fn trust_anchor_recognizes_the_type_and_the_issuer() {
    let jwt = sign(&sirtfi(None), JwtArtifactType::TrustMark, &issuer_signer()).await;

    assert_eq!(
        rejection(verify(
            &jwt,
            &anchor(&[(SIRTFI, &["https://other-tmi.example.org"])], false)
        )),
        TrustMarkRejection::IssuerNotRecognized
    );
    assert_eq!(
        rejection(verify(&jwt, &anchor(&[("https://refeds.org/other", &[])], false))),
        TrustMarkRejection::TypeNotRecognized
    );
    let mut silent = anchor(&[], false);
    silent.trust_mark_issuers = None;
    assert_eq!(rejection(verify(&jwt, &silent)), TrustMarkRejection::TypeNotRecognized);
}

#[tokio::test]
async fn owned_type_needs_a_delegation_from_its_owner() {
    let anchor = anchor(&[(SIRTFI, &[TMI])], true);

    let undelegated = sign(&sirtfi(None), JwtArtifactType::TrustMark, &issuer_signer()).await;
    assert_eq!(
        rejection(verify(&undelegated, &anchor)),
        TrustMarkRejection::DelegationMissing
    );

    // Each delegation is otherwise valid, and breaks one rule of Section 7.2.2.
    let anchor_key_as_owner = InMemorySigner::from_der(Algorithm::EdDSA, "owner-key", ED25519_DER).unwrap();
    let cases = [
        // Signed under the owner's `kid` with a key `trust_mark_owners` does not list.
        sign(
            &delegation(),
            JwtArtifactType::TrustMarkDelegation,
            &anchor_key_as_owner,
        )
        .await,
        // Issued by someone other than the owner.
        sign(
            &TrustMarkDelegation {
                iss: entity("https://not-the-owner.example.org"),
                ..delegation()
            },
            JwtArtifactType::TrustMarkDelegation,
            &owner_signer(),
        )
        .await,
        // Expired.
        sign(
            &TrustMarkDelegation {
                iat: now() - 7200,
                exp: Some(now() - 3600),
                ..delegation()
            },
            JwtArtifactType::TrustMarkDelegation,
            &owner_signer(),
        )
        .await,
        // Typed as a Trust Mark.
        sign(&delegation(), JwtArtifactType::TrustMark, &owner_signer()).await,
        // Expiring at its own iat, which `TrustMarkDelegation::validate` refuses.
        sign(
            &TrustMarkDelegation {
                iat: now() - 30,
                exp: Some(now() - 30),
                ..delegation()
            },
            JwtArtifactType::TrustMarkDelegation,
            &owner_signer(),
        )
        .await,
    ];
    for delegation in cases {
        let jwt = sign(&sirtfi(Some(delegation)), JwtArtifactType::TrustMark, &issuer_signer()).await;
        assert!(
            matches!(
                rejection(verify(&jwt, &anchor)),
                TrustMarkRejection::InvalidDelegation(_)
            ),
            "{:?}",
            verify(&jwt, &anchor)
        );
    }

    // A delegation of another type, or to another issuer.
    for delegation in [
        TrustMarkDelegation {
            trust_mark_type: "https://refeds.org/other".to_string(),
            ..delegation()
        },
        TrustMarkDelegation {
            sub: entity("https://other-tmi.example.org"),
            ..delegation()
        },
    ] {
        let delegation = sign(&delegation, JwtArtifactType::TrustMarkDelegation, &owner_signer()).await;
        let jwt = sign(&sirtfi(Some(delegation)), JwtArtifactType::TrustMark, &issuer_signer()).await;
        assert!(matches!(
            rejection(verify(&jwt, &anchor)),
            TrustMarkRejection::InvalidDelegation(_)
        ));
    }

    // A delegation for a type whose owner the Trust Anchor does not name cannot be verified.
    let unowned = self::anchor(&[(SIRTFI, &[TMI])], false);
    assert!(matches!(
        rejection(verify(&delegated_sirtfi().await, &unowned)),
        TrustMarkRejection::InvalidDelegation(_)
    ));
}

/// A federation served by URL: the Trust Anchor, the Trust Mark Issuer and the subject, with the
/// Trust Anchor's Subordinate Statements about the other two.
struct Federation {
    configurations: HashMap<String, String>,
    statements: HashMap<String, String>,
}

#[async_trait]
impl HttpClient for Federation {
    async fn get(&self, url: Url) -> FederationResult<HttpResponse> {
        let host = url.host_str().unwrap_or_default().to_string();
        let body = match url.path() {
            "/.well-known/openid-federation" => self.configurations.get(&host),
            "/fetch" if host == "ta.example.org" => url
                .query_pairs()
                .find(|(name, _)| name == "sub")
                .and_then(|(_, sub)| self.statements.get(sub.as_ref())),
            _ => None,
        };
        Ok(match body {
            Some(body) => HttpResponse::new(200, Some("application/entity-statement+jwt".to_string()), body.clone()),
            None => HttpResponse::new(404, None, ""),
        })
    }
}

/// The federation, where the Trust Mark Issuer publishes `issuer_jwks`, the Trust Anchor endorses
/// only `tmi-key` for it, and the subject's Entity Configuration carries `trust_marks`.
async fn federation(issuer_jwks: JwkSet, trust_marks: Vec<TrustMarkEntry>) -> Federation {
    let anchor_id = entity(ANCHOR);
    let mut tmi = EntityConfiguration::new(entity(TMI), issuer_jwks, now() + 3600, now());
    tmi.authority_hints = Some(vec![anchor_id.clone()]);
    let subject_signer = InMemorySigner::from_der(Algorithm::ES256, "entity-key", EC_P256_DER).unwrap();
    let mut subject = EntityConfiguration::new(entity(SUBJECT), jwks(EC_P256_JWK, "entity-key"), now() + 3600, now());
    subject.authority_hints = Some(vec![anchor_id.clone()]);
    subject.trust_marks = Some(trust_marks);

    let anchor_jwt = anchor(&[(SIRTFI, &[TMI])], true).sign(&anchor_signer()).await.unwrap();
    let about =
        |sub: &str, jwks: JwkSet| SubordinateStatement::new(anchor_id.clone(), entity(sub), now() + 3600, now(), jwks);
    Federation {
        configurations: HashMap::from([
            ("ta.example.org".to_string(), anchor_jwt),
            ("tmi.example.org".to_string(), tmi.sign(&issuer_signer()).await.unwrap()),
            (
                "entity.example.org".to_string(),
                subject.sign(&subject_signer).await.unwrap(),
            ),
        ]),
        statements: HashMap::from([
            (
                TMI.to_string(),
                about(TMI, issuer_keys()).sign(&anchor_signer()).await.unwrap(),
            ),
            (
                SUBJECT.to_string(),
                about(SUBJECT, jwks(EC_P256_JWK, "entity-key"))
                    .sign(&anchor_signer())
                    .await
                    .unwrap(),
            ),
        ]),
    }
}

#[tokio::test]
async fn client_trusts_the_issuer_through_its_trust_chain_first() {
    let client = FederationClient::with_http_client(federation(issuer_keys(), vec![]).await);
    let jwt = delegated_sirtfi().await;
    let verified = client
        .verify_trust_mark(&jwt, &entity(SUBJECT), &entity(ANCHOR))
        .await
        .unwrap();
    assert_eq!(verified.trust_mark_type, SIRTFI);

    // A Trust Anchor the issuer has no Trust Chain to cannot verify it.
    let error = client
        .verify_trust_mark(&jwt, &entity(SUBJECT), &entity("https://other-ta.example.org"))
        .await
        .unwrap_err();
    assert!(!matches!(error, FederationError::TrustMarkRejected(_)), "{error:?}");
}

#[tokio::test]
async fn client_verifies_with_the_keys_the_superior_endorses() {
    // The issuer also publishes `rogue-key` in its own configuration, which the Trust Anchor
    // does not endorse. A Trust Mark signed with it does not verify.
    let mut published = issuer_keys();
    let mut rogue: Jwk = serde_json::from_str(RSA_2048_JWK).unwrap();
    rogue.kid = Some("rogue-key".to_string());
    published.add_key(rogue);
    let client = FederationClient::with_http_client(federation(published, vec![]).await);

    let rogue_signer = InMemorySigner::from_der(Algorithm::RS256, "rogue-key", RSA_2048_DER).unwrap();
    let delegation = sign(&delegation(), JwtArtifactType::TrustMarkDelegation, &owner_signer()).await;
    let jwt = sign(&sirtfi(Some(delegation)), JwtArtifactType::TrustMark, &rogue_signer).await;
    let error = client.verify_trust_mark(&jwt, &entity(SUBJECT), &entity(ANCHOR)).await;
    assert!(matches!(rejection(error), TrustMarkRejection::InvalidSignature(_)));
}

#[tokio::test]
async fn client_verifies_a_trust_mark_the_trust_anchor_issues_with_its_own_keys() {
    let mut claims = TrustMark::new(
        entity(ANCHOR),
        entity(SUBJECT),
        "https://ta.example.org/member",
        now() - 60,
    );
    claims.exp = Some(now() + 3600);
    let jwt = claims.sign(&anchor_signer()).await.unwrap();

    let mut federation = federation(issuer_keys(), vec![]).await;
    let anchor = anchor(&[(SIRTFI, &[TMI]), ("https://ta.example.org/member", &[ANCHOR])], true);
    federation.configurations.insert(
        "ta.example.org".to_string(),
        anchor.sign(&anchor_signer()).await.unwrap(),
    );
    let client = FederationClient::with_http_client(federation);

    let verified = client
        .verify_trust_mark(&jwt, &entity(SUBJECT), &entity(ANCHOR))
        .await
        .unwrap();
    assert_eq!(verified, claims);
}

#[tokio::test]
async fn chain_keeps_the_trust_marks_of_its_leaf_that_verify() {
    let valid = TrustMarkEntry {
        trust_mark_type: SIRTFI.to_string(),
        trust_mark: delegated_sirtfi().await,
    };
    let undelegated = TrustMarkEntry {
        trust_mark_type: SIRTFI.to_string(),
        trust_mark: sign(&sirtfi(None), JwtArtifactType::TrustMark, &issuer_signer()).await,
    };
    let client =
        FederationClient::with_http_client(federation(issuer_keys(), vec![valid.clone(), undelegated.clone()]).await);

    let mut chain = client
        .discover_trust_chain(&entity(SUBJECT), Some(&[entity(ANCHOR)]))
        .await
        .unwrap();
    assert_eq!(
        chain.trust_marks, None,
        "discovery does not verify Trust Marks by itself"
    );

    let failures = client.verify_chain_trust_marks(&mut chain).await.unwrap();
    let verified = chain.trust_marks.unwrap();
    assert_eq!(verified.len(), 1);
    assert!(verified[0].delegation.is_some());
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].entry, undelegated);
    match &failures[0].error {
        FederationError::TrustMarkRejected(rejection) => {
            assert_eq!(**rejection, TrustMarkRejection::DelegationMissing);
        }
        other => panic!("{other:?}"),
    }
}
