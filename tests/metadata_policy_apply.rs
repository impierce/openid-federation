//! Applying a resolved metadata policy to metadata (OpenID Federation 1.0, Sections 6.1.3.1 and
//! 6.1.4.2): one test per standard operator, every row of Table 1, `scope` processed as an
//! array, the order of application, the errors, and the example of Section 6.1.5.

use openid_federation::{apply_metadata_policy, EntityMetadata, FederationError, MetadataPolicy};
use serde_json::{json, Value};

fn metadata(json: Value) -> EntityMetadata {
    serde_json::from_value(json).unwrap()
}

fn policy(json: Value) -> MetadataPolicy {
    serde_json::from_value(json).unwrap()
}

/// The `oauth_client` metadata that results from applying `operators` to `parameter` of
/// `client`, an `oauth_client` metadata object. `oauth_client` keeps every parameter as JSON.
fn applied(client: Value, parameter: &str, operators: Value) -> Value {
    let resolved = apply_metadata_policy(
        &metadata(json!({ "oauth_client": client })),
        &policy(json!({ "oauth_client": { parameter: operators } })),
    )
    .unwrap_or_else(|error| panic!("{parameter} {operators}: {error}"));
    serde_json::to_value(&resolved).unwrap()["oauth_client"].clone()
}

/// The policy error of applying `operators` to `parameter` of `client`. It names the Entity
/// Type and the parameter.
fn policy_error(client: Value, parameter: &str, operators: Value) -> String {
    let error = apply_metadata_policy(
        &metadata(json!({ "oauth_client": client })),
        &policy(json!({ "oauth_client": { parameter: operators } })),
    )
    .unwrap_err();
    assert!(matches!(error, FederationError::InvalidMetadata(_)), "{error:?}");
    let message = error.to_string();
    assert!(message.contains(&format!("oauth_client.{parameter}")), "{message}");
    message
}

/// Section 6.1.3.1.1: `value` assigns its value, present or absent, and `null` removes the
/// parameter.
#[test]
fn value_assigns_or_removes() {
    assert_eq!(
        applied(
            json!({ "token_endpoint_auth_method": "client_secret_basic" }),
            "token_endpoint_auth_method",
            json!({ "value": "private_key_jwt" })
        ),
        json!({ "token_endpoint_auth_method": "private_key_jwt" })
    );
    assert_eq!(
        applied(json!({}), "grant_types", json!({ "value": ["authorization_code"] })),
        json!({ "grant_types": ["authorization_code"] })
    );
    assert_eq!(
        applied(
            json!({ "contacts": ["a@example.org"], "client_name": "RP" }),
            "contacts",
            json!({ "value": null })
        ),
        json!({ "client_name": "RP" })
    );
}

/// Section 6.1.3.1.2: `add` appends the values the parameter lacks, once, and initializes an
/// absent parameter.
#[test]
fn add_appends_missing_values() {
    assert_eq!(
        applied(
            json!({ "contacts": ["rp@example.org", "ops@example.org"] }),
            "contacts",
            json!({ "add": ["ops@example.org", "helpdesk@example.org"] })
        ),
        json!({ "contacts": ["rp@example.org", "ops@example.org", "helpdesk@example.org"] })
    );
    assert_eq!(
        applied(json!({}), "contacts", json!({ "add": ["helpdesk@example.org"] })),
        json!({ "contacts": ["helpdesk@example.org"] })
    );
    assert!(policy_error(
        json!({ "contacts": "rp@example.org" }),
        "contacts",
        json!({ "add": ["helpdesk@example.org"] })
    )
    .contains("add: the parameter \"rp@example.org\" is not an array"));
}

/// Section 6.1.3.1.3: `default` sets an absent parameter and leaves a present one.
#[test]
fn default_sets_only_an_absent_parameter() {
    assert_eq!(
        applied(json!({}), "grant_types", json!({ "default": ["authorization_code"] })),
        json!({ "grant_types": ["authorization_code"] })
    );
    assert_eq!(
        applied(
            json!({ "grant_types": ["refresh_token"] }),
            "grant_types",
            json!({ "default": ["authorization_code"] })
        ),
        json!({ "grant_types": ["refresh_token"] })
    );
}

/// Section 6.1.3.1.4: a present parameter must be one of the `one_of` values; an absent one
/// passes.
#[test]
fn one_of_checks_a_present_parameter() {
    let operators = json!({ "one_of": ["private_key_jwt", "self_signed_tls_client_auth"] });
    assert_eq!(
        applied(
            json!({ "token_endpoint_auth_method": "private_key_jwt" }),
            "token_endpoint_auth_method",
            operators.clone()
        ),
        json!({ "token_endpoint_auth_method": "private_key_jwt" })
    );
    assert_eq!(
        applied(json!({}), "token_endpoint_auth_method", operators.clone()),
        json!({})
    );
    assert!(policy_error(
        json!({ "token_endpoint_auth_method": "client_secret_basic" }),
        "token_endpoint_auth_method",
        operators
    )
    .contains("one_of: \"client_secret_basic\" is not one of"));
}

/// Section 6.1.3.1.5: `subset_of` narrows a present parameter to the values it shares with the
/// operator, possibly to `[]`.
#[test]
fn subset_of_narrows_a_present_parameter() {
    assert_eq!(
        applied(
            json!({ "response_types": ["code", "code id_token", "token"] }),
            "response_types",
            json!({ "subset_of": ["code", "code id_token"] })
        ),
        json!({ "response_types": ["code", "code id_token"] })
    );
    assert_eq!(
        applied(
            json!({ "response_types": ["token"] }),
            "response_types",
            json!({ "subset_of": ["code"] })
        ),
        json!({ "response_types": [] })
    );
    assert!(policy_error(
        json!({ "response_types": "code" }),
        "response_types",
        json!({ "subset_of": ["code"] })
    )
    .contains("subset_of: the parameter \"code\" is not an array"));
}

/// Section 6.1.3.1.6: a present parameter must contain every `superset_of` value; equality is
/// included.
#[test]
fn superset_of_checks_a_present_parameter() {
    let operators = json!({ "superset_of": ["authorization_code"] });
    assert_eq!(
        applied(
            json!({ "grant_types": ["authorization_code", "refresh_token"] }),
            "grant_types",
            operators.clone()
        ),
        json!({ "grant_types": ["authorization_code", "refresh_token"] })
    );
    assert_eq!(
        applied(
            json!({ "grant_types": ["authorization_code"] }),
            "grant_types",
            operators.clone()
        ),
        json!({ "grant_types": ["authorization_code"] })
    );
    assert!(
        policy_error(json!({ "grant_types": ["refresh_token"] }), "grant_types", operators)
            .contains("superset_of: the parameter lacks [\"authorization_code\"]")
    );
}

/// Section 6.1.3.1.7: an `essential` parameter left absent fails; `false` lets it be absent;
/// objects are supported.
#[test]
fn essential_parameter_must_be_present() {
    let jwks = json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": "x", "y": "y" }] });
    assert_eq!(
        applied(json!({ "jwks": jwks.clone() }), "jwks", json!({ "essential": true })),
        json!({ "jwks": jwks })
    );
    assert_eq!(applied(json!({}), "jwks", json!({ "essential": false })), json!({}));
    assert!(
        policy_error(json!({}), "jwks", json!({ "essential": true })).contains("essential: the parameter is absent")
    );
}

/// Section 6.1.3.1.8, Table 1: every combination of `essential` and `subset_of` [a,b,c] with
/// the metadata parameter it shows.
#[test]
fn table_1_essential_and_subset_of() {
    for (essential, input, output) in [
        (true, Some(json!(["a", "e"])), Some(json!(["a"]))),
        (false, Some(json!(["a", "e"])), Some(json!(["a"]))),
        (true, Some(json!(["d", "e"])), Some(json!([]))),
        (false, Some(json!(["d", "e"])), Some(json!([]))),
        (true, None, None),
        (false, None, None),
    ] {
        let client = match &input {
            Some(input) => json!({ "response_types": input }),
            None => json!({}),
        };
        let operators = json!({ "essential": essential, "subset_of": ["a", "b", "c"] });
        match (essential, input.is_some(), output) {
            (true, false, _) => {
                policy_error(client, "response_types", operators);
            }
            (_, _, Some(output)) => assert_eq!(
                applied(client, "response_types", operators),
                json!({ "response_types": output }),
                "essential {essential}, input {input:?}"
            ),
            (_, _, None) => assert_eq!(applied(client, "response_types", operators), json!({})),
        }
    }
}

/// Section 6.1.3.1.8: `scope` is processed as an array of its space-separated values and
/// written back as such a string.
#[test]
fn scope_is_processed_as_an_array() {
    assert_eq!(
        applied(
            json!({ "scope": "openid email phone" }),
            "scope",
            json!({ "subset_of": ["openid", "email", "address"] })
        ),
        json!({ "scope": "openid email" })
    );
    assert_eq!(
        applied(
            json!({ "scope": "openid" }),
            "scope",
            json!({ "add": ["email"], "superset_of": ["openid"] })
        ),
        json!({ "scope": "openid email" })
    );
    assert_eq!(
        applied(json!({}), "scope", json!({ "default": ["openid", "profile"] })),
        json!({ "scope": "openid profile" })
    );
    assert!(policy_error(
        json!({ "scope": "openid email" }),
        "scope",
        json!({ "superset_of": ["profile"] })
    )
    .contains("superset_of: the parameter lacks [\"profile\"]"));
}

/// Section 6.1.3.1: the operators run in their order of application: `value`, `add`, `default`,
/// `one_of`, `subset_of`, `superset_of`, `essential`.
#[test]
fn operators_run_in_their_order_of_application() {
    // `add` before `subset_of`: the added value survives only when `subset_of` allows it.
    assert_eq!(
        applied(
            json!({ "response_types": ["code", "token"] }),
            "response_types",
            json!({ "add": ["id_token"], "subset_of": ["code", "id_token"] })
        ),
        json!({ "response_types": ["code", "id_token"] })
    );
    // `value` before `add`: `add` appends to the assigned value.
    assert_eq!(
        applied(
            json!({ "contacts": ["rp@example.org"] }),
            "contacts",
            json!({ "value": ["a@example.org", "b@example.org"], "add": ["b@example.org"] })
        ),
        json!({ "contacts": ["a@example.org", "b@example.org"] })
    );
    // `default` before `one_of` and `essential`: the default is checked and makes the
    // parameter present.
    assert_eq!(
        applied(
            json!({}),
            "token_endpoint_auth_method",
            json!({ "default": "private_key_jwt", "one_of": ["private_key_jwt"], "essential": true })
        ),
        json!({ "token_endpoint_auth_method": "private_key_jwt" })
    );
    // `subset_of` before `superset_of`: a value `subset_of` removes is missing for
    // `superset_of`.
    assert!(policy_error(
        json!({ "grant_types": ["authorization_code", "implicit"] }),
        "grant_types",
        json!({ "subset_of": ["authorization_code"], "superset_of": ["implicit"] })
    )
    .contains("superset_of"));
}

/// Section 6.1.4.2: a policy applies only to the Entity Types the metadata has; an additional
/// operator that is not critical is ignored.
#[test]
fn policy_applies_to_the_entity_types_present() {
    let resolved = apply_metadata_policy(
        &metadata(json!({ "oauth_client": { "client_name": "RP" } })),
        &policy(json!({
            "openid_provider": { "issuer": { "essential": true } },
            "oauth_client": { "client_name": { "regexp": "^X" } }
        })),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&resolved).unwrap(),
        json!({ "oauth_client": { "client_name": "RP" } })
    );
}

/// Section 6.1.4.2: an Entity Type that is not standard is processed as its JSON object.
#[test]
fn policy_applies_to_an_entity_type_that_is_not_standard() {
    let resolved = apply_metadata_policy(
        &metadata(json!({ "openid_credential_issuer": { "credential_issuer": "https://ci.example.org" } })),
        &policy(json!({ "openid_credential_issuer": { "display": { "default": [{ "name": "CI" }] } } })),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&resolved).unwrap(),
        json!({ "openid_credential_issuer": { "credential_issuer": "https://ci.example.org", "display": [{ "name": "CI" }] } })
    );
}

/// Section 6.1.4.2: Resolved Metadata that no longer fits its Entity Type, here a Relying
/// Party without its required `redirect_uris`, is a policy error.
#[test]
fn illegal_resolved_metadata_fails() {
    let error = apply_metadata_policy(
        &metadata(json!({ "openid_relying_party": { "redirect_uris": ["https://rp.example.org/callback"] } })),
        &policy(json!({ "openid_relying_party": { "redirect_uris": { "value": null } } })),
    )
    .unwrap_err();
    assert!(matches!(error, FederationError::InvalidMetadata(_)), "{error:?}");
    assert!(error.to_string().contains("not valid metadata"), "{error}");
}

/// Section 6.1.5: the merged policy of Figure 12, applied to the Leaf Entity's metadata of
/// Figure 13 after the Intermediate's metadata values of Figure 11, gives the Resolved Metadata
/// of Figure 14.
#[test]
fn section_6_1_5_example_resolves_to_figure_14() {
    // Figure 13, with the `metadata` of Figure 11 applied.
    let leaf = metadata(json!({
        "openid_relying_party": {
            "redirect_uris": ["https://rp.example.org/callback"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "self_signed_tls_client_auth",
            "contacts": ["rp_admins@rp.example.org"],
            "sector_identifier_uri": "https://org.example.org/sector-ids.json",
            "policy_uri": "https://org.example.org/policy.html"
        }
    }));
    // Figure 12.
    let merged = policy(json!({
        "openid_relying_party": {
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
        }
    }));

    let resolved = apply_metadata_policy(&leaf, &merged).unwrap();
    assert_eq!(
        serde_json::to_value(&resolved).unwrap(),
        json!({
            "openid_relying_party": {
                "redirect_uris": ["https://rp.example.org/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "self_signed_tls_client_auth",
                "subject_type": "pairwise",
                "sector_identifier_uri": "https://org.example.org/sector-ids.json",
                "policy_uri": "https://org.example.org/policy.html",
                "contacts": [
                    "rp_admins@rp.example.org",
                    "helpdesk@federation.example.org",
                    "helpdesk@org.example.org"
                ]
            }
        })
    );
}
