//! Merging the metadata policies of a Trust Chain (OpenID Federation 1.0, Section 6.1.4.1): one
//! test per operator merge of Sections 6.1.3.1.1 to 6.1.3.1.7, the merges that are policy errors,
//! the copying of what only a lower policy has, critical operators, and the example of
//! Section 6.1.5.

use openid_federation::{
    resolve_metadata_policy, EntityId, FederationError, JwkSet, MetadataPolicy, SubordinateStatement,
};
use serde_json::{json, Value};

const TRUST_ANCHOR: &str = "https://ta.example.org";
const INTERMEDIATE: &str = "https://org.example.org";
const LEAF: &str = "https://rp.example.org";

fn policy(json: Value) -> MetadataPolicy {
    serde_json::from_value(json).unwrap()
}

/// A Subordinate Statement issued by `issuer` about `subject`, carrying `metadata_policy` if any.
fn statement(issuer: &str, subject: &str, metadata_policy: Option<Value>) -> SubordinateStatement {
    let statement = SubordinateStatement::new(
        EntityId::parse(issuer).unwrap(),
        EntityId::parse(subject).unwrap(),
        2_000_000_000,
        1_700_000_000,
        JwkSet::new(),
    );
    match metadata_policy {
        Some(json) => statement.with_metadata_policy(policy(json)),
        None => statement,
    }
}

/// The chain Trust Anchor → Intermediate → leaf, with the Trust Anchor's and the Intermediate's
/// policies, in Trust Anchor to subject order.
fn chain(superior: Value, intermediate: Value) -> Vec<SubordinateStatement> {
    vec![
        statement(TRUST_ANCHOR, INTERMEDIATE, Some(superior)),
        statement(INTERMEDIATE, LEAF, Some(intermediate)),
    ]
}

/// The policy for `openid_relying_party.<parameter>` with `superior` merged with `intermediate`.
fn merged(parameter: &str, superior: Value, intermediate: Value) -> Value {
    let resolved = resolve_metadata_policy(&chain(
        json!({ "openid_relying_party": { parameter: superior } }),
        json!({ "openid_relying_party": { parameter: intermediate } }),
    ))
    .unwrap()
    .expect("a policy");
    serde_json::to_value(&resolved["openid_relying_party"][parameter]).unwrap()
}

/// The policy error of merging `intermediate` into `superior` for
/// `openid_relying_party.<parameter>`.
fn merge_error(parameter: &str, superior: Value, intermediate: Value) -> String {
    let error = resolve_metadata_policy(&chain(
        json!({ "openid_relying_party": { parameter: superior } }),
        json!({ "openid_relying_party": { parameter: intermediate } }),
    ))
    .unwrap_err();
    assert!(matches!(error, FederationError::InvalidMetadata(_)), "{error:?}");
    let message = error.to_string();
    assert!(
        message.contains(&format!("the metadata_policy issued by {INTERMEDIATE}")),
        "names the issuer: {message}"
    );
    assert!(
        message.contains(&format!("openid_relying_party.{parameter}")),
        "names the Entity Type and parameter: {message}"
    );
    message
}

/// Section 6.1.3.1.1: two `value` operators merge only when equal.
#[test]
fn value_merges_only_when_equal() {
    assert_eq!(
        merged(
            "subject_type",
            json!({ "value": "pairwise" }),
            json!({ "value": "pairwise" })
        ),
        json!({ "value": "pairwise" })
    );
    assert_eq!(
        merged("contacts", json!({ "value": null }), json!({ "value": null })),
        json!({ "value": null })
    );
}

/// Section 6.1.3.1.1: an Intermediate's `value` that differs from the Trust Anchor's is a
/// policy error.
#[test]
fn intermediate_value_that_differs_from_the_trust_anchor_fails() {
    let message = merge_error(
        "subject_type",
        json!({ "value": "pairwise" }),
        json!({ "value": "public" }),
    );
    assert!(
        message.contains("value \"public\" differs from value \"pairwise\""),
        "{message}"
    );

    let message = merge_error(
        "grant_types",
        json!({ "value": ["authorization_code", "refresh_token"] }),
        json!({ "value": ["refresh_token", "authorization_code"] }),
    );
    assert!(
        message.contains("must be equal"),
        "arrays compare as JSON values: {message}"
    );
}

/// Section 6.1.3.1.2: two `add` operators merge to the union of their values.
#[test]
fn add_merges_by_union() {
    assert_eq!(
        merged(
            "contacts",
            json!({ "add": ["helpdesk@federation.example.org", "ops@example.org"] }),
            json!({ "add": ["ops@example.org", "helpdesk@org.example.org"] })
        ),
        json!({ "add": ["helpdesk@federation.example.org", "ops@example.org", "helpdesk@org.example.org"] })
    );
}

/// Section 6.1.3.1.3: two `default` operators merge only when equal.
#[test]
fn default_merges_only_when_equal() {
    assert_eq!(
        merged(
            "grant_types",
            json!({ "default": ["authorization_code"] }),
            json!({ "default": ["authorization_code"] })
        ),
        json!({ "default": ["authorization_code"] })
    );
    let message = merge_error(
        "grant_types",
        json!({ "default": ["authorization_code"] }),
        json!({ "default": ["refresh_token"] }),
    );
    assert!(
        message.contains("default [\"refresh_token\"] differs from default"),
        "{message}"
    );
}

/// Section 6.1.3.1.4: two `one_of` operators merge to the intersection of their values.
#[test]
fn one_of_merges_by_intersection() {
    assert_eq!(
        merged(
            "id_token_signed_response_alg",
            json!({ "one_of": ["ES256", "ES384", "PS256"] }),
            json!({ "one_of": ["PS256", "ES256", "RS256"] })
        ),
        json!({ "one_of": ["ES256", "PS256"] })
    );
}

/// Section 6.1.3.1.4: disjoint `one_of` values are a policy error.
#[test]
fn disjoint_one_of_fails() {
    let message = merge_error(
        "id_token_signed_response_alg",
        json!({ "one_of": ["ES256", "ES384"] }),
        json!({ "one_of": ["RS256"] }),
    );
    assert!(
        message.contains("one_of [\"RS256\"] has no value in common with one_of [\"ES256\",\"ES384\"]"),
        "{message}"
    );
}

/// Section 6.1.3.1.5: two `subset_of` operators merge to the intersection of their values,
/// which may be empty.
#[test]
fn subset_of_merges_by_intersection() {
    assert_eq!(
        merged(
            "response_types",
            json!({ "subset_of": ["code", "id_token", "code id_token"] }),
            json!({ "subset_of": ["code id_token", "code", "token"] })
        ),
        json!({ "subset_of": ["code", "code id_token"] })
    );
    assert_eq!(
        merged(
            "response_types",
            json!({ "subset_of": ["code"] }),
            json!({ "subset_of": ["token"] })
        ),
        json!({ "subset_of": [] })
    );
}

/// Section 6.1.3.1.6: two `superset_of` operators merge to the union of their values.
#[test]
fn superset_of_merges_by_union() {
    assert_eq!(
        merged(
            "grant_types",
            json!({ "superset_of": ["authorization_code"] }),
            json!({ "superset_of": ["refresh_token", "authorization_code"] })
        ),
        json!({ "superset_of": ["authorization_code", "refresh_token"] })
    );
}

/// Sections 6.1.3.1.2 and 6.1.3.1.4 to 6.1.3.1.6: a merged union or intersection holds each
/// value once, even when a policy repeats one.
#[test]
fn merged_values_are_distinct() {
    for (operator, superior, intermediate, result) in [
        (
            "add",
            json!(["a", "a", "b"]),
            json!(["b", "c", "c"]),
            json!(["a", "b", "c"]),
        ),
        ("superset_of", json!(["a", "a"]), json!(["b", "a"]), json!(["a", "b"])),
        ("subset_of", json!(["a", "b", "a"]), json!(["a", "c"]), json!(["a"])),
        ("one_of", json!(["a", "a", "b"]), json!(["a"]), json!(["a"])),
    ] {
        assert_eq!(
            merged(
                "response_types",
                json!({ operator: superior }),
                json!({ operator: intermediate })
            ),
            json!({ operator: result }),
            "{operator}"
        );
    }
}

/// Section 6.1.3.1.7: two `essential` operators merge to their logical OR, so an Intermediate
/// cannot make a parameter the Trust Anchor requires voluntary.
#[test]
fn essential_merges_by_logical_or() {
    for (superior, intermediate, result) in [
        (true, false, true),
        (false, true, true),
        (false, false, false),
        (true, true, true),
    ] {
        assert_eq!(
            merged(
                "token_endpoint_auth_method",
                json!({ "essential": superior }),
                json!({ "essential": intermediate })
            ),
            json!({ "essential": result }),
            "{superior} OR {intermediate}"
        );
    }
}

/// Sections 6.1.3.1.5, 6.1.3.1.6 and 6.1.4.1: a merged `subset_of` that no longer contains the
/// merged `superset_of` is a combination that is not allowed.
#[test]
fn merged_subset_of_that_no_longer_contains_superset_of_fails() {
    let message = merge_error(
        "grant_types",
        json!({ "subset_of": ["authorization_code", "refresh_token"], "superset_of": ["authorization_code"] }),
        json!({ "subset_of": ["refresh_token"] }),
    );
    assert!(
        message.contains("the merged metadata parameter policy is not allowed")
            && message.contains("subset_of must be a superset of the values of superset_of"),
        "{message}"
    );
}

/// Sections 6.1.1 and 6.1.4.1: an operator an Intermediate copies in must combine with what the
/// Trust Anchor set, so it cannot loosen it.
#[test]
fn copied_operator_that_conflicts_with_a_superior_fails() {
    let message = merge_error(
        "token_endpoint_auth_method",
        json!({ "value": "private_key_jwt" }),
        json!({ "one_of": ["self_signed_tls_client_auth"] }),
    );
    assert!(message.contains("must be among the one_of values"), "{message}");

    let message = merge_error(
        "grant_types",
        json!({ "subset_of": ["authorization_code"] }),
        json!({ "one_of": ["authorization_code"] }),
    );
    assert!(
        message.contains("one_of must not be combined with subset_of"),
        "{message}"
    );
}

/// Section 6.1.4.1: Entity Types, metadata parameters and operators present only lower in the
/// chain are copied into the resolved policy.
#[test]
fn what_only_a_lower_policy_has_is_copied() {
    let resolved = resolve_metadata_policy(&chain(
        json!({ "openid_relying_party": { "contacts": { "add": ["helpdesk@federation.example.org"] } } }),
        json!({
            "openid_relying_party": {
                "contacts": { "essential": true },
                "subject_type": { "value": "pairwise" }
            },
            "federation_entity": { "organization_name": { "essential": true } }
        }),
    ))
    .unwrap()
    .unwrap();

    assert_eq!(
        serde_json::to_value(&resolved).unwrap(),
        json!({
            "openid_relying_party": {
                "contacts": { "add": ["helpdesk@federation.example.org"], "essential": true },
                "subject_type": { "value": "pairwise" }
            },
            "federation_entity": { "organization_name": { "essential": true } }
        })
    );
}

/// Section 6.1.4.1: each operator only the lower metadata parameter policy has is copied into it.
#[test]
fn operators_only_a_lower_policy_has_are_copied() {
    let lower = json!({
        "value": ["code"],
        "add": ["code"],
        "default": ["code"],
        "subset_of": ["code", "id_token"],
        "superset_of": ["code"]
    });
    let mut expected = lower.clone();
    expected["essential"] = json!(true);
    assert_eq!(merged("response_types", json!({ "essential": true }), lower), expected);

    assert_eq!(
        merged(
            "token_endpoint_auth_method",
            json!({ "essential": true }),
            json!({ "one_of": ["private_key_jwt"] })
        ),
        json!({ "one_of": ["private_key_jwt"], "essential": true })
    );
}

/// Section 6.1.4.1: statements without a `metadata_policy` are skipped; the first policy found
/// becomes the current one; with none the chain has no resolved policy.
#[test]
fn statements_without_a_policy_are_skipped() {
    let only = json!({ "openid_relying_party": { "subject_type": { "value": "pairwise" } } });
    let statements = vec![
        statement(TRUST_ANCHOR, "https://inter-a.example.org", None),
        statement("https://inter-a.example.org", INTERMEDIATE, Some(only.clone())),
        statement(INTERMEDIATE, LEAF, None),
    ];
    assert_eq!(resolve_metadata_policy(&statements).unwrap(), Some(policy(only)));

    let without = vec![
        statement(TRUST_ANCHOR, INTERMEDIATE, None),
        statement(INTERMEDIATE, LEAF, None),
    ];
    assert_eq!(resolve_metadata_policy(&without).unwrap(), None);
    assert_eq!(resolve_metadata_policy(&[]).unwrap(), None);
}

/// Section 6.1.4.1: each policy is validated before it is merged, and the error names the entity
/// that issued it.
#[test]
fn every_policy_is_validated() {
    let error = resolve_metadata_policy(&chain(
        json!({ "openid_relying_party": { "subject_type": { "value": "pairwise" } } }),
        json!({ "openid_relying_party": { "grant_types": { "one_of": ["code"], "add": ["code"] } } }),
    ))
    .unwrap_err()
    .to_string();
    assert!(
        error.contains(&format!("the metadata_policy issued by {INTERMEDIATE}"))
            && error.contains("openid_relying_party.grant_types")
            && error.contains("one_of must not be combined with add"),
        "{error}"
    );

    let error = resolve_metadata_policy(&chain(json!({}), json!({ "openid_relying_party": {} })))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(&format!("the metadata_policy issued by {TRUST_ANCHOR}")),
        "the first policy is validated too: {error}"
    );
}

/// Sections 6.1.3.2 and 6.1.4.1: `metadata_policy_crit` is collected from every statement in the
/// chain, so a critical operator declared lower in the chain makes a policy higher up that uses
/// it a policy error. This crate understands no additional operator.
#[test]
fn critical_operators_are_collected_across_the_chain() {
    let mut statements = chain(
        json!({ "openid_relying_party": { "id_token_signed_response_alg": { "one_of": ["ES256"], "regexp": "^ES" } } }),
        json!({ "openid_relying_party": { "subject_type": { "value": "pairwise" } } }),
    );
    resolve_metadata_policy(&statements).unwrap();

    statements[1].metadata_policy_crit = Some(vec!["regexp".to_string()]);
    let error = resolve_metadata_policy(&statements).unwrap_err().to_string();
    assert!(
        error.contains(&format!("the metadata_policy issued by {TRUST_ANCHOR}"))
            && error.contains("openid_relying_party.id_token_signed_response_alg")
            && error.contains("critical operator \"regexp\" is not understood"),
        "{error}"
    );
}

/// Section 6.1.3.2: an additional operator that is not critical is carried through untouched:
/// copied when only the lower policy has it, the Superior's value kept when both do.
#[test]
fn additional_operators_are_carried_through() {
    assert_eq!(
        merged(
            "id_token_signed_response_alg",
            json!({ "one_of": ["ES256", "PS256"], "regexp": "^ES" }),
            json!({ "one_of": ["ES256"], "regexp": "^PS", "max_length": 5 })
        ),
        json!({ "one_of": ["ES256"], "regexp": "^ES", "max_length": 5 })
    );
}

/// Section 6.1.5: merging the Intermediate's example policy (Figure 11) into the Trust Anchor's
/// (Figure 10) gives the merged policy of Figure 12.
#[test]
fn section_6_1_5_example_merges_to_figure_12() {
    let resolved = resolve_metadata_policy(&chain(
        json!({
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
        }),
        json!({
            "openid_relying_party": {
                "grant_types": { "subset_of": ["authorization_code"] },
                "token_endpoint_auth_method": { "one_of": ["self_signed_tls_client_auth"] },
                "contacts": { "add": ["helpdesk@org.example.org"] }
            }
        }),
    ))
    .unwrap()
    .unwrap();

    let figure_12 = json!({
        "grant_types": {
            "default": ["authorization_code"],
            "superset_of": ["authorization_code"],
            "subset_of": ["authorization_code"]
        },
        "token_endpoint_auth_method": {
            "one_of": ["self_signed_tls_client_auth"],
            "essential": true
        },
        "token_endpoint_auth_signing_alg": { "one_of": ["PS256", "ES256"] },
        "subject_type": { "value": "pairwise" },
        "contacts": { "add": ["helpdesk@federation.example.org", "helpdesk@org.example.org"] }
    });
    assert_eq!(resolved.len(), 1);
    assert_eq!(
        serde_json::to_value(&resolved["openid_relying_party"]).unwrap(),
        figure_12
    );
}

/// Section 6.1.4.1: a policy merges down a longer chain, each step into the result of the ones
/// above it.
#[test]
fn policies_merge_down_a_longer_chain() {
    let statements = vec![
        statement(
            TRUST_ANCHOR,
            "https://inter-a.example.org",
            Some(
                json!({ "openid_relying_party": { "response_types": { "subset_of": ["code", "id_token", "token"] } } }),
            ),
        ),
        statement(
            "https://inter-a.example.org",
            INTERMEDIATE,
            Some(json!({ "openid_relying_party": { "response_types": { "subset_of": ["code", "id_token"] } } })),
        ),
        statement(
            INTERMEDIATE,
            LEAF,
            Some(json!({ "openid_relying_party": { "response_types": { "superset_of": ["token"] } } })),
        ),
    ];
    let error = resolve_metadata_policy(&statements).unwrap_err().to_string();
    assert!(
        error.contains(&format!("the metadata_policy issued by {INTERMEDIATE}"))
            && error.contains("subset_of must be a superset of the values of superset_of"),
        "the lowest policy conflicts with the merge of the two above: {error}"
    );

    let resolved = resolve_metadata_policy(&statements[..2]).unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&resolved).unwrap(),
        json!({ "openid_relying_party": { "response_types": { "subset_of": ["code", "id_token"] } } })
    );
}
