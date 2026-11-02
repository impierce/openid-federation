//! Validating metadata policies (OpenID Federation 1.0, Sections 6.1.2, 6.1.3 and 6.1.4.1): one
//! test per combination rule of the standard operators, the example of Section 6.1.5, additional
//! operators kept and round-tripped, and a critical operator that is not understood refused.

use chrono::Duration;
use openid_federation::{
    validate_metadata_policy, EntityId, FederationError, Jwk, JwkSet, MetadataPolicy, PolicyOperators,
    SubordinateStatement,
};
use serde_json::{json, Value};

const EC_P256_JWK: &str = include_str!("data/signer/ec-p256.public.jwk.json");

fn operators(json: Value) -> PolicyOperators {
    serde_json::from_value(json).unwrap()
}

fn policy_error(json: Value) -> String {
    let error = operators(json.clone()).validate().unwrap_err();
    assert!(
        matches!(error, FederationError::InvalidMetadata(_)),
        "{json}: {error:?}"
    );
    error.to_string()
}

fn assert_valid(json: Value) {
    operators(json.clone())
        .validate()
        .unwrap_or_else(|error| panic!("{json}: {error}"));
}

/// Section 6.1.3.1.4: `one_of` combines only with `value`, `default` and `essential`.
#[test]
fn one_of_combines_only_with_value_default_and_essential() {
    assert_valid(json!({ "one_of": ["ES256", "ES384"], "value": "ES256", "default": "ES256", "essential": true }));
    for other in [
        json!({ "add": ["ES256"] }),
        json!({ "subset_of": ["ES256"] }),
        json!({ "superset_of": ["ES256"] }),
    ] {
        let mut policy = json!({ "one_of": ["ES256"] });
        policy
            .as_object_mut()
            .unwrap()
            .extend(other.as_object().unwrap().clone());
        assert!(
            policy_error(policy.clone()).contains("one_of must not be combined with"),
            "{policy}"
        );
    }
}

/// Section 6.1.3.1.1 and 6.1.3.1.4: `value` must be among the `one_of` values.
#[test]
fn value_must_be_among_one_of() {
    assert_valid(json!({ "value": "ES256", "one_of": ["ES256", "ES384"] }));
    assert!(policy_error(json!({ "value": "RS256", "one_of": ["ES256"] })).contains("among the one_of values"));
}

/// Sections 6.1.3.1.1 and 6.1.3.1.5: the values of `value` must be a subset of `subset_of`.
#[test]
fn value_must_be_a_subset_of_subset_of() {
    assert_valid(json!({ "value": ["code"], "subset_of": ["code", "id_token"] }));
    assert_valid(json!({ "value": "code", "subset_of": ["code"] }));
    assert!(
        policy_error(json!({ "value": ["code", "token"], "subset_of": ["code"] }))
            .contains("subset of the values of subset_of")
    );
}

/// Sections 6.1.3.1.1 and 6.1.3.1.6: the values of `value` must be a superset of `superset_of`.
#[test]
fn value_must_be_a_superset_of_superset_of() {
    assert_valid(json!({ "value": ["code", "token"], "superset_of": ["code"] }));
    assert!(policy_error(json!({ "value": ["token"], "superset_of": ["code"] }))
        .contains("superset of the values of superset_of"));
}

/// Sections 6.1.3.1.1 and 6.1.3.1.2: the values of `add` must be a subset of `value`.
#[test]
fn add_must_be_a_subset_of_value() {
    assert_valid(json!({ "value": ["a@example.org", "b@example.org"], "add": ["a@example.org"] }));
    assert!(
        policy_error(json!({ "value": ["a@example.org"], "add": ["c@example.org"] }))
            .contains("add must be a subset of the values of value")
    );
}

/// Sections 6.1.3.1.2 and 6.1.3.1.5: the values of `add` must be a subset of `subset_of`.
#[test]
fn add_must_be_a_subset_of_subset_of() {
    assert_valid(json!({ "add": ["code"], "subset_of": ["code", "token"] }));
    assert!(policy_error(json!({ "add": ["id_token"], "subset_of": ["code"] }))
        .contains("add must be a subset of the values of subset_of"));
}

/// Sections 6.1.3.1.5 and 6.1.3.1.6: `subset_of` must be a superset of `superset_of`; equal
/// arrays express "set equals" (Section 6.1.3.1.8).
#[test]
fn subset_of_must_be_a_superset_of_superset_of() {
    assert_valid(json!({ "subset_of": ["code", "token"], "superset_of": ["code", "token"] }));
    assert!(
        policy_error(json!({ "subset_of": ["code"], "superset_of": ["code", "token"] }))
            .contains("subset_of must be a superset of the values of superset_of")
    );
}

/// Sections 6.1.3.1.1, 6.1.3.1.3 and 6.1.3.1.7: `value: null` combines neither with `default`
/// nor with `essential: true`.
#[test]
fn value_null_combines_neither_with_default_nor_with_essential_true() {
    let removed = operators(json!({ "value": null }));
    assert_eq!(removed.value, Some(Value::Null), "null is kept, not read as absent");
    removed.validate().unwrap();
    assert_valid(json!({ "value": null, "essential": false }));

    assert!(
        policy_error(json!({ "value": null, "default": "ES256" })).contains("null must not be combined with default")
    );
    assert!(policy_error(json!({ "value": null, "essential": true }))
        .contains("null must not be combined with essential true"));
    assert_valid(json!({ "value": "ES256", "default": "ES256", "essential": true }));
}

/// Section 6.1.3: an operator configured with a JSON type it does not support is a policy error.
#[test]
fn operator_values_have_a_supported_type() {
    assert!(policy_error(json!({ "value": { "alg": "ES256" } })).contains("value must be"));
    assert!(policy_error(json!({ "default": null })).contains("default must be"));
    assert!(policy_error(json!({ "default": { "alg": "ES256" } })).contains("default must be"));
    assert!(policy_error(json!({ "add": "code" })).contains("add must be an array"));
    assert!(policy_error(json!({ "subset_of": [true] })).contains("subset_of must be an array of strings"));
    assert!(policy_error(json!({ "one_of": [["ES256"]] })).contains("one_of must be an array of strings"));
    assert_valid(json!({ "one_of": [1, 2], "default": 3 }));
    assert_valid(json!({ "subset_of": [{ "kty": "EC" }], "superset_of": [{ "kty": "EC" }] }));

    for wrong in [
        json!({ "essential": "yes" }),
        json!({ "essential": null }),
        json!({ "one_of": "ES256" }),
        json!({ "subset_of": null }),
    ] {
        assert!(
            serde_json::from_value::<PolicyOperators>(wrong.clone()).is_err(),
            "{wrong}"
        );
    }
}

/// Section 6.1.3.2: an additional operator is kept under its name and round-trips.
#[test]
fn additional_operator_round_trips() {
    let json = json!({ "subset_of": ["ES256"], "regexp": "^ES" });
    let parsed = operators(json.clone());

    assert_eq!(parsed.additional.get("regexp"), Some(&json!("^ES")));
    assert_eq!(parsed.subset_of, Some(vec![json!("ES256")]));
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), json);

    let mut shadowing = PolicyOperators::default();
    shadowing.additional.insert("value".to_string(), json!("ES256"));
    assert!(shadowing
        .validate()
        .unwrap_err()
        .to_string()
        .contains("name of a standard operator"));
}

fn section_6_1_5_trust_anchor_policy() -> MetadataPolicy {
    serde_json::from_value(json!({
        "openid_relying_party": {
            "grant_types": {
                "default": ["authorization_code"],
                "subset_of": ["authorization_code", "refresh_token"],
                "superset_of": ["authorization_code"]
            },
            "token_endpoint_auth_method": {
                "one_of": ["private_key_jwt", "self_signed_tls_client_auth"],
                "essential": true
            },
            "token_endpoint_auth_signing_alg": { "one_of": ["PS256", "ES256"] },
            "subject_type": { "value": "pairwise" },
            "contacts": { "add": ["helpdesk@federation.example.org"] }
        }
    }))
    .unwrap()
}

/// Section 6.1.5: the metadata policies of the Trust Anchor and of the Intermediate Entity in the
/// example validate.
#[test]
fn section_6_1_5_example_validates() {
    validate_metadata_policy(&section_6_1_5_trust_anchor_policy(), &[]).unwrap();

    let intermediate: MetadataPolicy = serde_json::from_value(json!({
        "openid_relying_party": {
            "grant_types": { "subset_of": ["authorization_code"] },
            "token_endpoint_auth_method": { "one_of": ["self_signed_tls_client_auth"] },
            "contacts": { "add": ["helpdesk@org.example.org"] }
        }
    }))
    .unwrap();
    validate_metadata_policy(&intermediate, &[]).unwrap();
}

/// Sections 6.1.3.2 and 6.1.4.1: an additional operator is ignored unless it is critical; a
/// critical operator that is not understood is a policy error.
#[test]
fn critical_operator_that_is_not_understood_fails() {
    let policy: MetadataPolicy = serde_json::from_value(json!({
        "openid_relying_party": { "id_token_signed_response_alg": { "one_of": ["ES256"], "regexp": "^ES" } }
    }))
    .unwrap();

    validate_metadata_policy(&policy, &[]).unwrap();
    validate_metadata_policy(&policy, &["other_operator".to_string()]).unwrap();
    let error = validate_metadata_policy(&policy, &["regexp".to_string()]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("critical operator \"regexp\" is not understood"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("openid_relying_party.id_token_signed_response_alg"),
        "{error}"
    );
}

/// Section 6.1.2: each of the three levels has at least one member.
#[test]
fn every_level_has_a_member() {
    for (json, message) in [
        (json!({}), "at least one Entity Type"),
        (
            json!({ "openid_relying_party": {} }),
            "at least one metadata parameter policy",
        ),
        (
            json!({ "openid_relying_party": { "contacts": {} } }),
            "at least one operator",
        ),
    ] {
        let policy: MetadataPolicy = serde_json::from_value(json.clone()).unwrap();
        let error = validate_metadata_policy(&policy, &[]).unwrap_err();
        assert!(error.to_string().contains(message), "{json}: {error}");
    }
}

/// The Subordinate Statement builder refuses a policy with a combination that is not allowed.
#[test]
fn builder_refuses_a_malformed_metadata_policy() {
    let mut key: Jwk = serde_json::from_str(EC_P256_JWK).unwrap();
    key.kid = Some("op-key".to_string());
    let mut jwks = JwkSet::new();
    jwks.add_key(key);
    let builder = SubordinateStatement::builder(
        EntityId::parse("https://ta.example.org").unwrap(),
        EntityId::parse("https://op.example.org").unwrap(),
        jwks,
    )
    .lifetime(Duration::hours(1));

    builder
        .clone()
        .metadata_policy(section_6_1_5_trust_anchor_policy())
        .build()
        .unwrap();

    let malformed: MetadataPolicy = serde_json::from_value(
        json!({ "openid_relying_party": { "subject_type": { "value": null, "essential": true } } }),
    )
    .unwrap();
    let error = builder.metadata_policy(malformed).build().unwrap_err();
    assert!(
        matches!(error, FederationError::InvalidSubordinateStatement(_)),
        "a failed producer rule is reported like the others: {error:?}"
    );
    assert!(
        error.to_string().contains("openid_relying_party.subject_type"),
        "{error}"
    );
}
