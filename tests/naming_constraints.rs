//! Naming constraints as a type (OpenID Federation 1.0, Section 6.2.2): the examples of the
//! section, an excluded name winning over a permitted one, and names that are not fully qualified
//! domain names refused before a Subordinate Statement is built or signed.

use chrono::Duration;
use jsonwebtoken::Algorithm;
use openid_federation::{Constraints, EntityId, InMemorySigner, Jwk, JwkSet, NamingConstraints, SubordinateStatement};

const EC_P256_DER: &[u8] = include_bytes!("data/signer/ec-p256.pkcs8.der");
const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");

fn entity(id: &str) -> EntityId {
    EntityId::parse(id).unwrap()
}

fn names(names: &[&str]) -> Option<Vec<String>> {
    Some(names.iter().map(|name| name.to_string()).collect())
}

fn permitted(list: &[&str]) -> NamingConstraints {
    NamingConstraints {
        permitted: names(list),
        excluded: None,
    }
}

#[test]
fn leading_period_permits_hosts_below_the_domain_but_not_the_domain() {
    let constraints = permitted(&[".example.com"]);

    assert!(constraints.permits(&entity("https://host.example.com")));
    assert!(constraints.permits(&entity("https://my.host.example.com/federation")));
    assert!(!constraints.permits(&entity("https://example.com")));
    assert!(
        !constraints.permits(&entity("https://badexample.com")),
        "a label boundary is required"
    );
    assert!(!constraints.permits(&entity("https://example.org")));
}

#[test]
fn name_without_leading_period_names_one_host() {
    let constraints = permitted(&["host.example.com"]);

    assert!(constraints.permits(&entity("https://host.example.com")));
    assert!(
        constraints.permits(&entity("https://HOST.Example.COM:8443/path")),
        "the host decides"
    );
    assert!(!constraints.permits(&entity("https://my.host.example.com")));
    assert!(!constraints.permits(&entity("https://example.com")));
}

#[test]
fn excluded_name_wins_over_a_permitted_one() {
    let constraints = NamingConstraints {
        permitted: names(&[".example.com"]),
        excluded: names(&["blocked.example.com", ".internal.example.com"]),
    };

    assert!(constraints.permits(&entity("https://op.example.com")));
    assert!(!constraints.permits(&entity("https://blocked.example.com")));
    assert!(!constraints.permits(&entity("https://rp.internal.example.com")));

    let excluded_only = NamingConstraints {
        permitted: None,
        excluded: names(&[".example.com"]),
    };
    assert!(
        excluded_only.permits(&entity("https://example.org")),
        "no permitted list permits the rest"
    );
    assert!(!excluded_only.permits(&entity("https://op.example.com")));
}

#[test]
fn names_must_be_fully_qualified_domain_names() {
    for valid in [
        permitted(&["host.example.com", ".example.com", "xn--bcher-kva.example"]),
        NamingConstraints {
            permitted: None,
            excluded: names(&["localhost"]),
        },
    ] {
        valid.validate().unwrap();
    }

    for name in [
        "https://host.example.com",
        "host.example.com/path",
        "host.example.com:443",
        "host.example.com.",
        "..example.com",
        "-host.example.com",
        "host-.example.com",
        "bücher.example",
        "",
        ".",
    ] {
        let error = permitted(&[name]).validate().unwrap_err();
        assert!(
            error.to_string().contains("not a fully qualified domain name"),
            "{name:?}: {error}"
        );
    }

    let too_long_label = format!("{}.example.com", "a".repeat(64));
    assert!(permitted(&[&too_long_label]).validate().is_err());
}

#[test]
fn naming_constraints_need_a_non_empty_list() {
    let error = NamingConstraints::default().validate().unwrap_err();
    assert!(error.to_string().contains("permitted, excluded or both"), "{error}");

    let error = permitted(&[]).validate().unwrap_err();
    assert!(
        error.to_string().contains("permitted must not be the empty array"),
        "{error}"
    );

    let error = NamingConstraints {
        permitted: None,
        excluded: Some(Vec::new()),
    }
    .validate()
    .unwrap_err();
    assert!(
        error.to_string().contains("excluded must not be the empty array"),
        "{error}"
    );
}

#[test]
fn naming_constraints_round_trip_as_the_specification_spells_them() {
    let json = r#"{"naming_constraints":{"permitted":[".example.com"],"excluded":["east.example.com"]}}"#;
    let constraints: Constraints = serde_json::from_str(json).unwrap();

    assert_eq!(
        constraints.naming_constraints,
        Some(NamingConstraints {
            permitted: names(&[".example.com"]),
            excluded: names(&["east.example.com"]),
        })
    );
    assert_eq!(serde_json::to_string(&constraints).unwrap(), json);
}

#[test]
fn subordinate_statement_with_malformed_naming_constraints_is_not_built() {
    let mut key: Jwk = serde_json::from_str(EC_P256_JWK).unwrap();
    key.kid = Some("op-key".to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    let builder =
        SubordinateStatement::builder(entity("https://ta.example.org"), entity("https://op.example.org"), jwks)
            .lifetime(Duration::hours(1));

    let error = builder
        .clone()
        .constraints(Constraints {
            naming_constraints: Some(permitted(&["https://example.com"])),
            ..Default::default()
        })
        .build()
        .unwrap_err();
    assert!(
        error.to_string().contains("not a fully qualified domain name"),
        "{error}"
    );

    builder
        .constraints(Constraints {
            max_path_length: Some(0),
            naming_constraints: Some(permitted(&[".example.org"])),
            ..Default::default()
        })
        .build()
        .unwrap();
}

/// A statement assembled without the builder is checked when it is signed, before the signer is
/// called.
#[tokio::test]
async fn subordinate_statement_with_malformed_naming_constraints_is_not_signed() {
    let mut key: Jwk = serde_json::from_str(EC_P256_JWK).unwrap();
    key.kid = Some("op-key".to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    let now = chrono::Utc::now().timestamp();
    let statement = SubordinateStatement::new(
        entity("https://ta.example.org"),
        entity("https://op.example.org"),
        now + 3600,
        now,
        jwks,
    )
    .with_constraints(Constraints {
        naming_constraints: Some(permitted(&["https://example.com"])),
        ..Default::default()
    });
    let signer = InMemorySigner::from_der(Algorithm::ES256, "ta-key", EC_P256_DER).unwrap();

    let error = statement.sign(&signer).await.unwrap_err();

    assert!(
        error.to_string().contains("not a fully qualified domain name"),
        "{error}"
    );
}
