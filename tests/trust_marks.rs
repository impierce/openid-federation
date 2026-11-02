//! Issuing Trust Marks and Trust Mark delegations (OpenID Federation 1.0, Section 7): the claims of
//! Sections 7.1 and 7.2.1, the examples of Sections 7.4 and 7.5, and signing them as
//! `trust-mark+jwt` and `trust-mark-delegation+jwt`.
//!
//! The keys in `tests/data/signer/` are test fixtures generated once for the signer suite. They
//! protect nothing.

use jsonwebtoken::Algorithm;
use openid_federation::{
    extract_claims_unverified, sign_federation_jwt, EntityConfiguration, EntityId, FederationError, InMemorySigner,
    Jwk, JwkSet, JwtArtifactType, JwtProcessor, TrustMark, TrustMarkDelegation,
};

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");

const SIRTFI: &str = "https://refeds.org/sirtfi";

fn entity(id: &str) -> EntityId {
    EntityId::parse(id).unwrap()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn signer(kid: &str) -> InMemorySigner {
    InMemorySigner::from_der(Algorithm::ES256, kid, EC_P256_DER).unwrap()
}

fn public_jwks(kid: &str) -> JwkSet {
    let mut key: Jwk = serde_json::from_str(EC_P256_JWK).unwrap();
    key.kid = Some(kid.to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    jwks
}

/// Verifies `jwt` against `jwks` as `artifact_type` with the crate's default processor, which
/// does not require `exp` of Trust Marks and delegations.
fn verify<T: for<'de> serde::Deserialize<'de>>(jwt: &str, jwks: &JwkSet, artifact_type: JwtArtifactType) -> T {
    JwtProcessor::new()
        .verify_jwt_with_jwks(jwt, jwks, artifact_type)
        .unwrap()
}

/// A Trust Mark issued by `https://tmi.example.org` to `https://entity.example.org`.
fn trust_mark() -> TrustMark {
    TrustMark::new(
        entity("https://tmi.example.org"),
        entity("https://entity.example.org"),
        SIRTFI,
        now(),
    )
}

/// A delegation by which `https://tm-owner.example.org` lets `https://tmi.example.org` issue
/// Sirtfi Trust Marks.
fn delegation() -> TrustMarkDelegation {
    TrustMarkDelegation::new(
        entity("https://tm-owner.example.org"),
        entity("https://tmi.example.org"),
        SIRTFI,
        now(),
    )
}

fn assert_invalid(result: Result<impl std::fmt::Debug, FederationError>, expected: &str) {
    match result {
        Err(FederationError::InvalidTrustMark(message)) => {
            assert!(message.contains(expected), "{message:?} does not mention {expected:?}")
        }
        other => panic!("expected InvalidTrustMark mentioning {expected:?}, got {other:?}"),
    }
}

/// Figures 19 to 24: Trust Mark payloads, with and without `logo_uri`, `ref`, `exp` and
/// additional claims.
#[test]
fn section_7_4_examples_deserialize() {
    let national_profile: TrustMark = serde_json::from_value(serde_json::json!({
        "trust_mark_type": "https://mushrooms.federation.example.com/openid_relying_party/public/",
        "iss": "https://epigeo.tm-issuer.example.it",
        "sub": "https://porcino.example.com/rp",
        "iat": 1579621160,
        "organization_name": "Porcino Mushrooms & Co.",
        "policy_uri": "https://porcino.example.com/privacy_policy",
        "tos_uri": "https://porcino.example.com/info_policy",
        "service_documentation": "https://porcino.example.com/api/v1/get/services",
        "ref": "https://porcino.example.com/documentation/manuale_operativo.pdf"
    }))
    .unwrap();
    assert_eq!(national_profile.exp, None);
    assert_eq!(national_profile.iat, 1579621160);
    assert_eq!(
        national_profile.r#ref.as_ref().map(|url| url.as_str()),
        Some("https://porcino.example.com/documentation/manuale_operativo.pdf")
    );
    assert_eq!(
        national_profile.additional["organization_name"],
        "Porcino Mushrooms & Co."
    );
    assert_eq!(national_profile.additional.len(), 4);

    let agreement: TrustMark = serde_json::from_value(serde_json::json!({
        "trust_mark_type": "https://mushrooms.federation.example.com/arrosto/agreements",
        "iss": "https://agaricaceae.example.it",
        "sub": "https://coppolino.example.com",
        "iat": 1579621160,
        "logo_uri": "https://coppolino.example.com/sgd-cmyk-150dpi-90mm.svg",
        "organization_type": "public",
        "id_code": "123456",
        "email": "info@coppolino.example.com",
        "organization_name#it": "Mazza di Tamburo",
        "policy_uri#it": "https://coppolino.example.com/privacy_policy",
        "tos_uri#it": "https://coppolino.example.com/info_policy",
        "service_documentation": "https://coppolino.example.com/api/v1/get/services",
        "ref": "https://agaricaceae.example.it/documentation/agaricaceae.pdf"
    }))
    .unwrap();
    assert!(agreement.logo_uri.is_some());
    assert_eq!(agreement.additional["organization_name#it"], "Mazza di Tamburo");

    let self_signed: TrustMark = serde_json::from_value(serde_json::json!({
        "trust_mark_type": "https://mushrooms.federation.example.com/trust-marks/self-signed",
        "iss": "https://amanita.muscaria.example.com",
        "sub": "https://amanita.muscaria.example.com",
        "iat": 1579621160,
        "logo_uri": "https://amanita.muscaria.example.com/img/amanita-mus.svg",
        "ref": "https://amanita.muscaria.example.com/uploads/cookbook.zip"
    }))
    .unwrap();
    assert_eq!(self_signed.iss, self_signed.sub);
    assert!(self_signed.additional.is_empty());

    let accreditation: TrustMark = serde_json::from_value(serde_json::json!({
        "iss": "https://swamid.se",
        "sub": "https://umu.se/op",
        "iat": 1577833200,
        "exp": 1609369200,
        "trust_mark_type": "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"
    }))
    .unwrap();
    assert_eq!(accreditation.exp, Some(1609369200));
    assert_eq!(accreditation.delegation, None);
}

/// Figure 18: the Trust Mark JWT in an Entity Configuration's `trust_marks` claim.
#[test]
fn section_7_4_trust_mark_jwt_deserializes() {
    let jwt: String = "eyJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoia29
        zR20yd3VaaDlER21OeEF0a3VPNDBwUGpwTDMtakNmMU4tcVBPLVllVSJ9.
        eyJpc3MiOiJodHRwczovL3d3dy5hZ2lkLmdvdi5pdCIsInN1YiI6Imh0dHBzOi8
        vcnAuZXhhbXBsZS5pdC9zcGlkIiwiaWF0IjoxNTc5NjIxMTYwLCJ0cnVzdF9tYX
        JrX3R5cGUiOiJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9jZXJ0aWZpY2F0aW9uL
        3JwIiwibG9nb191cmkiOiJodHRwczovL3d3dy5hZ2lkLmdvdi5pdC90aGVtZXMv
        Y3VzdG9tL2FnaWQvbG9nby5zdmciLCJyZWYiOiJodHRwczovL2RvY3MuaXRhbGl
        hLml0L2RvY3Mvc3BpZC1jaWUtb2lkYy1kb2NzL2l0L3ZlcnNpb25lLWNvcnJlbn
        RlLyJ9.
        L_pSh1InEiFAcs3E-1HBM7fNZYwF5ru3UGA_8yc80dGS3sszfA_sbj4AoW_zAJW
        QBdZpjxnHBBmybYXFrfZBcqxcedsrvUYrmbt1nPYxbUE54fRRoZK-sJmVqh1GzS
        an5nOmkxuAtMinU8k_-aWnPWj83sYe2AzT2mMgkXiz8zhda3jZm8hoxZ4jR6B0Y
        AvbMlq2pPWO5OWKdZhiFRMSprwh0GYluQkK0j1aLNMGXD3keMJd2zEoWX9D7w2f
        XShAA48W3cNhuXyBVnCoum1K4IWK3s_fx4nIkp6W-V4jCBOpxp7Yo8LZ30o_xpE
        OzGTIECGWVR86azOAlwVC8XSiAA"
        .split_whitespace()
        .collect();

    let header = jsonwebtoken::decode_header(&jwt).unwrap();
    assert_eq!(header.typ.as_deref(), Some("trust-mark+jwt"));
    let trust_mark: TrustMark = extract_claims_unverified(&jwt).unwrap();
    assert_eq!(trust_mark.trust_mark_type, "https://www.spid.gov.it/certification/rp");
    assert_eq!(trust_mark.iss, entity("https://www.agid.gov.it"));
    assert_eq!(trust_mark.sub, entity("https://rp.example.it/spid"));
    assert_eq!(trust_mark.exp, None);
    assert!(trust_mark.logo_uri.is_some() && trust_mark.r#ref.is_some());
}

/// Figures 25 to 27: a Trust Mark carrying a delegation, and the delegation's header and claims.
#[test]
fn section_7_5_example_deserializes() {
    let delegation_jwt: String = "eyJ0eXAiOiJ0cnVzdC1tYXJrLWRlbGVnYXRpb24rand0IiwiYWxnIjoiUl
        MyNTYiLCJraWQiOiJrb3NHbTJ3dVpoOURHbU54QXRrdU80MHBQanBMMy1qQ
        2YxTi1xUE8tWWVVIn0.
        eyJzdWIiOiJodHRwczovL3RtaS5leGFtcGxlLm9yZyIsInRydXN0X21hcmt
        fdHlwZSI6Imh0dHBzOi8vcmVmZWRzLm9yZy9zaXJ0ZmkiLCJpc3MiOiJodH
        RwczovL3RtX293bmVyLmV4YW1wbGUub3JnIiwiaWF0IjoxNzI1MTc2MzAyfQ.
        ao0rWGpVjEgpNyFxsKawps8q71eYnp78TzRdY4P52
        CT8QX6etXt-2L2Z1Vw5A6jx2mhjpPwWi_sOxfiOSA5TugJfN0Gbwj7teTzM
        0IMciuasCWgnLrKyLZjS147ZE50I9e9P8Ot8UQwhmXcLiuwsbDxSdqM4pVp
        75lfWnmzPH0L2pDZG5COFgIgSOAlK3TVMBOR8fziF-VmWNPzAfB0lSc-hjH
        -7q66GyT43o3Exnm6DsoLxyB8bxG99BQltLxURDT90CzM6szGcF3OG64Rbe
        0I4lT_LAOfvhlrRbT56eK4sJNCsbVbGnDBfFmyfB_HIeBMGP0L7T5JPMOUU
        9bjIlA"
        .split_whitespace()
        .collect();

    let mut trust_mark: TrustMark = serde_json::from_value(serde_json::json!({
        "delegation": delegation_jwt,
        "iat": 1725176302,
        "trust_mark_type": SIRTFI,
        "sub": "https://entity.example.org",
        "exp": 1727768302,
        "iss": "https://tmi.example.org"
    }))
    .unwrap();
    assert_eq!(trust_mark.exp, Some(1727768302));
    assert_eq!(trust_mark.delegation.as_deref(), Some(delegation_jwt.as_str()));

    let header = jsonwebtoken::decode_header(&delegation_jwt).unwrap();
    assert_eq!(header.typ.as_deref(), Some("trust-mark-delegation+jwt"));
    assert_eq!(
        header.kid.as_deref(),
        Some("kosGm2wuZh9DGmNxAtkuO40pPjpL3-jCf1N-qPO-YeU")
    );
    let delegation: TrustMarkDelegation = extract_claims_unverified(&delegation_jwt).unwrap();
    assert_eq!(delegation.iss, entity("https://tm_owner.example.org"));
    assert_eq!(delegation.sub, trust_mark.iss);
    assert_eq!(delegation.trust_mark_type, SIRTFI);
    assert_eq!(delegation.iat, 1725176302);
    assert_eq!(delegation.exp, None);

    // The example expired in 2024; without its `exp`, the Trust Mark and its delegation are well
    // formed.
    assert_invalid(trust_mark.validate(), "has expired");
    trust_mark.exp = None;
    trust_mark.validate().unwrap();
}

#[tokio::test]
async fn trust_mark_without_exp_round_trips() {
    let trust_mark = trust_mark();

    let json = serde_json::to_value(&trust_mark).unwrap();
    assert!(json.get("exp").is_none(), "{json}");
    assert_eq!(serde_json::from_value::<TrustMark>(json).unwrap(), trust_mark);

    let jwt = trust_mark.sign(&signer("tmi-key")).await.unwrap();
    let verified: TrustMark = verify(&jwt, &public_jwks("tmi-key"), JwtArtifactType::TrustMark);
    assert_eq!(verified, trust_mark);
}

#[tokio::test]
async fn signed_trust_mark_carries_typ_and_kid() {
    let mut trust_mark = trust_mark();
    trust_mark.exp = Some(now() + 3600);
    trust_mark.logo_uri = Some("https://tmi.example.org/logo.svg".parse().unwrap());
    trust_mark
        .additional
        .insert("organization_name".to_string(), "Entity & Co.".into());

    let jwt = trust_mark.sign(&signer("tmi-key")).await.unwrap();

    let header = jsonwebtoken::decode_header(&jwt).unwrap();
    assert_eq!(header.typ.as_deref(), Some("trust-mark+jwt"));
    assert_eq!(header.kid.as_deref(), Some("tmi-key"));
    let verified: TrustMark = JwtProcessor::new()
        .verify_jwt_with_jwks(&jwt, &public_jwks("tmi-key"), JwtArtifactType::TrustMark)
        .unwrap();
    assert_eq!(verified, trust_mark);
}

#[tokio::test]
async fn signed_trust_mark_entry_passes_validation() {
    let entry = trust_mark().sign_entry(&signer("tmi-key")).await.unwrap();

    assert_eq!(entry.trust_mark_type, SIRTFI);
    entry.validate().unwrap();
    let configuration = EntityConfiguration::new(
        entity("https://entity.example.org"),
        public_jwks("entity-key"),
        now() + 3600,
        now(),
    )
    .with_trust_marks(vec![entry]);
    configuration.validate().unwrap();
}

#[tokio::test]
async fn delegated_trust_mark_is_signed_and_validates() {
    let mut delegation = delegation();
    delegation.exp = Some(now() + 3600);
    let delegation_jwt = delegation.sign(&signer("owner-key")).await.unwrap();

    let header = jsonwebtoken::decode_header(&delegation_jwt).unwrap();
    assert_eq!(header.typ.as_deref(), Some("trust-mark-delegation+jwt"));
    assert_eq!(header.kid.as_deref(), Some("owner-key"));
    let verified: TrustMarkDelegation = verify(
        &delegation_jwt,
        &public_jwks("owner-key"),
        JwtArtifactType::TrustMarkDelegation,
    );
    assert_eq!(verified, delegation);

    let mut trust_mark = trust_mark();
    trust_mark.delegation = Some(delegation_jwt);
    trust_mark.validate().unwrap();
    let entry = trust_mark.sign_entry(&signer("tmi-key")).await.unwrap();
    let signed: TrustMark = verify(&entry.trust_mark, &public_jwks("tmi-key"), JwtArtifactType::TrustMark);
    assert_eq!(signed.delegation, trust_mark.delegation);
}

#[tokio::test]
async fn delegation_without_exp_round_trips() {
    let delegation = delegation();

    let json = serde_json::to_value(&delegation).unwrap();
    assert!(json.get("exp").is_none(), "{json}");
    assert_eq!(serde_json::from_value::<TrustMarkDelegation>(json).unwrap(), delegation);
}

#[tokio::test]
async fn delegation_for_another_type_or_issuer_is_refused() {
    let owner = signer("owner-key");

    let mut other_type = delegation();
    other_type.trust_mark_type = "https://refeds.org/other".to_string();
    let mut trust_mark = trust_mark();
    trust_mark.delegation = Some(other_type.sign(&owner).await.unwrap());
    assert_invalid(
        trust_mark.validate(),
        "delegates Trust Marks of type https://refeds.org/other",
    );
    assert_invalid(
        trust_mark.sign(&signer("tmi-key")).await,
        "delegates Trust Marks of type",
    );

    let mut other_issuer = delegation();
    other_issuer.sub = entity("https://other-tmi.example.org");
    trust_mark.delegation = Some(other_issuer.sign(&owner).await.unwrap());
    assert_invalid(trust_mark.validate(), "delegates to https://other-tmi.example.org");

    let mut expired = delegation();
    expired.exp = Some(now() - 3600);
    let expired_jwt = sign_federation_jwt(&expired, JwtArtifactType::TrustMarkDelegation, &owner)
        .await
        .unwrap();
    trust_mark.delegation = Some(expired_jwt);
    assert_invalid(
        trust_mark.validate(),
        "Trust Mark delegation of type https://refeds.org/sirtfi has expired",
    );
}

#[tokio::test]
async fn delegation_that_is_not_a_delegation_jwt_is_refused() {
    let owner = signer("owner-key");
    let mut trust_mark = trust_mark();

    // The delegation's claims, signed as a Trust Mark.
    let mistyped = sign_federation_jwt(&delegation(), JwtArtifactType::TrustMark, &owner)
        .await
        .unwrap();
    trust_mark.delegation = Some(mistyped);
    assert_invalid(trust_mark.validate(), "expected 'trust-mark-delegation+jwt'");

    trust_mark.delegation = Some("not a JWT".to_string());
    assert_invalid(trust_mark.validate(), "is not a JWT");

    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.typ = Some(JwtArtifactType::TrustMarkDelegation.header_value().to_string());
    let without_kid = openid_federation::sign_compact_jws(&header, &delegation(), &owner)
        .await
        .unwrap();
    trust_mark.delegation = Some(without_kid);
    assert_invalid(trust_mark.validate(), "names no signing key in kid");

    let without_type = sign_federation_jwt(
        &serde_json::json!({
            "iss": "https://tm-owner.example.org",
            "sub": "https://tmi.example.org",
            "iat": now(),
        }),
        JwtArtifactType::TrustMarkDelegation,
        &owner,
    )
    .await
    .unwrap();
    trust_mark.delegation = Some(without_type);
    assert_invalid(trust_mark.validate(), "has no delegation claims");
}

#[tokio::test]
async fn malformed_trust_mark_or_delegation_is_not_signed() {
    let signer = signer("key");

    let mut empty_type = trust_mark();
    empty_type.trust_mark_type = String::new();
    assert_invalid(
        empty_type.sign(&signer).await,
        "Trust Mark has an empty trust_mark_type",
    );
    let mut empty_type = delegation();
    empty_type.trust_mark_type = String::new();
    assert_invalid(
        empty_type.sign(&signer).await,
        "Trust Mark delegation has an empty trust_mark_type",
    );

    for name in ["exp", "iss", "delegation"] {
        let mut repeated = trust_mark();
        repeated.additional.insert(name.to_string(), 1.into());
        assert_invalid(
            repeated.sign(&signer).await,
            &format!("additional claim {name:?} is a claim the specification defines"),
        );
    }
    let mut repeated = delegation();
    repeated
        .additional
        .insert("ref".to_string(), "https://example.org".into());
    assert_invalid(repeated.sign(&signer).await, "additional claim \"ref\"");
    // `logo_uri` and `delegation` are Trust Mark claims, not delegation claims.
    let mut extension = delegation();
    extension
        .additional
        .insert("logo_uri".to_string(), "https://example.org/logo.svg".into());
    extension.sign(&signer).await.unwrap();

    let mut expired = trust_mark();
    expired.exp = Some(now() - 3600);
    assert_invalid(
        expired.sign(&signer).await,
        "Trust Mark of type https://refeds.org/sirtfi has expired",
    );
    let mut expired = delegation();
    expired.exp = Some(now() - 3600);
    assert_invalid(expired.sign(&signer).await, "has expired");

    for (claim, trust_mark) in [
        (
            "iss",
            TrustMark {
                iss: entity("http://tmi.example.org"),
                ..trust_mark()
            },
        ),
        (
            "sub",
            TrustMark {
                sub: entity("https://entity.example.org#rp"),
                ..trust_mark()
            },
        ),
    ] {
        match trust_mark.sign(&signer).await {
            Err(FederationError::Configuration(message)) => assert!(message.starts_with(claim), "{message}"),
            other => panic!("{claim}: {other:?}"),
        }
    }
    let http_owner = TrustMarkDelegation {
        iss: entity("http://tm-owner.example.org"),
        ..delegation()
    };
    assert!(matches!(
        http_owner.sign(&signer).await,
        Err(FederationError::Configuration(_))
    ));
}

#[tokio::test]
async fn time_claims_are_checked_with_clock_skew() {
    let signer = signer("key");

    // Within the clock skew, an `exp` just passed and an `iat` just ahead are accepted.
    let mut skewed = trust_mark();
    skewed.iat = now() + 30;
    skewed.exp = Some(now() + 3600);
    skewed.validate().unwrap();
    let mut skewed = delegation();
    skewed.iat = now() - 3600;
    skewed.exp = Some(now() - 30);
    skewed.validate().unwrap();

    let mut future = trust_mark();
    future.iat = now() + 3600;
    assert_invalid(
        future.sign(&signer).await,
        "Trust Mark of type https://refeds.org/sirtfi is issued in the future",
    );
    let mut future = delegation();
    future.iat = now() + 3600;
    assert_invalid(
        future.sign(&signer).await,
        "Trust Mark delegation of type https://refeds.org/sirtfi is issued in the future",
    );

    for exp in [now() + 10, now() + 30] {
        let mut inverted = trust_mark();
        inverted.iat = now() + 30;
        inverted.exp = Some(exp);
        assert_invalid(
            inverted.sign(&signer).await,
            "Trust Mark of type https://refeds.org/sirtfi expires at or before its iat",
        );
        let mut inverted = delegation();
        inverted.iat = now() + 30;
        inverted.exp = Some(exp);
        assert_invalid(inverted.sign(&signer).await, "expires at or before its iat");
    }
}

#[tokio::test]
async fn verifier_still_requires_exp_of_other_artifacts() {
    // The claims of a Trust Mark without `exp`, signed as an Entity Statement.
    let jwt = sign_federation_jwt(&trust_mark(), JwtArtifactType::EntityStatement, &signer("tmi-key"))
        .await
        .unwrap();
    let result = JwtProcessor::new().verify_jwt_with_jwks::<TrustMark>(
        &jwt,
        &public_jwks("tmi-key"),
        JwtArtifactType::EntityStatement,
    );
    assert!(
        matches!(&result, Err(FederationError::Jwt(err)) if matches!(err.kind(), jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claim) if claim == "exp")),
        "{result:?}"
    );
}
