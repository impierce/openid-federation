//! Resolving the metadata policy of a Trust Chain: the `metadata_policy` claims of its
//! Subordinate Statements merged into one (OpenID Federation 1.0, Section 6.1.4.1).

use crate::types::policy_error;
use crate::{validate_metadata_policy, FederationError, FederationResult, MetadataPolicy, PolicyOperators};
use crate::{EntityId, SubordinateStatement};
use serde_json::Value;

/// Resolves the metadata policy of a Trust Chain from its Subordinate Statements.
///
/// `statements` are the chain's Subordinate Statements in Trust Anchor to subject order: first
/// the one issued by the most Superior Entity, last the one issued by the subject's Immediate
/// Superior. Statements without a `metadata_policy` are skipped.
///
/// The resolution follows Section 6.1.4.1:
///
/// 1. The operator names in every `metadata_policy_crit` of the chain are collected.
/// 2. Each `metadata_policy` is validated with
///    [`validate_metadata_policy`] against the collected
///    critical operators. This crate implements no additional operator, so a policy that uses
///    one of them is a policy error.
/// 3. The first policy becomes the current one, and each later one is merged into it at three
///    levels. An Entity Type or metadata parameter that only the later policy has is copied.
///    An operator that only the later policy has is copied. An operator that both have merges
///    as Sections 6.1.3.1.1 to 6.1.3.1.7 define:
///    - `value` and `default` only when equal, compared as JSON values;
///    - `add` and `superset_of` by union;
///    - `one_of` by intersection, which must not be empty;
///    - `subset_of` by intersection, which may be empty;
///    - `essential` by logical OR.
/// 4. Each merged metadata parameter policy must still pass [`PolicyOperators::validate`], so a
///    Subordinate cannot repeal or loosen what a Superior set (Section 6.1.1).
///
/// An additional operator that is not critical is carried through untouched: copied when the
/// current policy lacks it, otherwise the Superior's value is kept. A verifier ignores it on
/// application (Section 6.1.3.2).
///
/// Returns `None` when no statement has a `metadata_policy`; the subject's metadata then resolves
/// without a policy (Section 6.1.4.2).
///
/// # Errors
///
/// [`FederationError::InvalidMetadata`] naming the entity that issued the policy that fails,
/// the Entity Type, the metadata parameter and the operator or rule. A Trust Chain whose policy
/// does not resolve is invalid (Section 6.1.4).
///
/// Reference: OpenID Federation 1.0 - Section 6.1.4.1 Resolution
/// <https://openid.net/specs/openid-federation-1_0.html#section-6.1.4.1>
pub fn resolve_metadata_policy(statements: &[SubordinateStatement]) -> FederationResult<Option<MetadataPolicy>> {
    let mut critical_operators: Vec<String> = Vec::new();
    for operator in statements
        .iter()
        .filter_map(|statement| statement.metadata_policy_crit.as_ref())
        .flatten()
    {
        if !critical_operators.contains(operator) {
            critical_operators.push(operator.clone());
        }
    }

    let mut resolved: Option<MetadataPolicy> = None;
    for statement in statements {
        let Some(policy) = &statement.metadata_policy else {
            continue;
        };
        let issuer = &statement.claims.iss;
        validate_metadata_policy(policy, &critical_operators).map_err(|error| issued_by(issuer, error))?;
        resolved = Some(match resolved.take() {
            None => policy.clone(),
            Some(mut current) => {
                merge_policy(&mut current, policy).map_err(|error| issued_by(issuer, error))?;
                current
            }
        });
    }
    Ok(resolved)
}

/// Merges `next`, a validated policy, into `current` at the levels of Entity Types, metadata
/// parameters and operators. Entity Types and parameters are visited in sorted order, so the
/// error reported for a policy with several conflicts does not depend on hash order.
fn merge_policy(current: &mut MetadataPolicy, next: &MetadataPolicy) -> FederationResult<()> {
    let mut entity_types: Vec<&String> = next.keys().collect();
    entity_types.sort();
    for entity_type in entity_types {
        let next_parameters = &next[entity_type];
        let Some(current_parameters) = current.get_mut(entity_type) else {
            current.insert(entity_type.clone(), next_parameters.clone());
            continue;
        };
        let mut parameters: Vec<&String> = next_parameters.keys().collect();
        parameters.sort();
        for parameter in parameters {
            let next_operators = &next_parameters[parameter];
            let Some(current_operators) = current_parameters.get_mut(parameter) else {
                current_parameters.insert(parameter.clone(), next_operators.clone());
                continue;
            };
            let in_context = |error: FederationError| match error {
                FederationError::InvalidMetadata(message) => {
                    FederationError::InvalidMetadata(format!("{entity_type}.{parameter}: {message}"))
                }
                other => other,
            };
            merge_operators(current_operators, next_operators).map_err(in_context)?;
            current_operators.validate().map_err(|error| match error {
                FederationError::InvalidMetadata(message) => in_context(policy_error(format!(
                    "the merged metadata parameter policy is not allowed: {}",
                    message.strip_prefix("metadata policy error: ").unwrap_or(&message)
                ))),
                other => other,
            })?;
        }
    }
    Ok(())
}

/// Merges the operators of `next` into `current`, operator by operator (Sections 6.1.3.1.1 to
/// 6.1.3.1.7 and 6.1.4.1). Both are validated, so `add` holds an array.
fn merge_operators(current: &mut PolicyOperators, next: &PolicyOperators) -> FederationResult<()> {
    merge_equal("value", &mut current.value, next.value.as_ref())?;
    merge_equal("default", &mut current.default, next.default.as_ref())?;

    if let Some(next_add) = &next.add {
        let mut add = current.add.take().map(into_array).unwrap_or_default();
        union(&mut add, &into_array(next_add.clone()));
        current.add = Some(Value::Array(add));
    }

    match (&mut current.one_of, &next.one_of) {
        (Some(one_of), Some(next_one_of)) => {
            let superior = one_of.clone();
            one_of.retain(|value| next_one_of.contains(value));
            if one_of.is_empty() {
                return Err(policy_error(format!(
                    "one_of {} has no value in common with one_of {} of a Superior",
                    Value::Array(next_one_of.clone()),
                    Value::Array(superior)
                )));
            }
        }
        (None, Some(next_one_of)) => current.one_of = Some(next_one_of.clone()),
        (_, None) => {}
    }

    match (&mut current.subset_of, &next.subset_of) {
        (Some(subset_of), Some(next_subset_of)) => subset_of.retain(|value| next_subset_of.contains(value)),
        (None, Some(next_subset_of)) => current.subset_of = Some(next_subset_of.clone()),
        (_, None) => {}
    }

    if let Some(next_superset_of) = &next.superset_of {
        union(current.superset_of.get_or_insert_with(Vec::new), next_superset_of);
    }

    if let Some(next_essential) = next.essential {
        current.essential = Some(current.essential.unwrap_or(false) || next_essential);
    }

    for (name, value) in &next.additional {
        current.additional.entry(name.clone()).or_insert_with(|| value.clone());
    }
    Ok(())
}

/// Merges an operator whose values must be equal: `value` and `default`.
fn merge_equal(name: &str, current: &mut Option<Value>, next: Option<&Value>) -> FederationResult<()> {
    match (current.as_ref(), next) {
        (Some(superior), Some(next)) if superior != next => Err(policy_error(format!(
            "{name} {next} differs from {name} {superior} of a Superior; the values must be equal"
        ))),
        (None, Some(next)) => {
            *current = Some(next.clone());
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The elements of a validated `add` value, which is an array.
fn into_array(value: Value) -> Vec<Value> {
    match value {
        Value::Array(values) => values,
        other => vec![other],
    }
}

/// Appends the elements of `next` that `values` lacks, keeping the order of both.
fn union(values: &mut Vec<Value>, next: &[Value]) {
    for value in next {
        if !values.contains(value) {
            values.push(value.clone());
        }
    }
}

/// Names the entity that issued the policy in a policy error.
fn issued_by(issuer: &EntityId, error: FederationError) -> FederationError {
    match error {
        FederationError::InvalidMetadata(message) => {
            FederationError::InvalidMetadata(format!("the metadata_policy issued by {issuer}: {message}"))
        }
        other => other,
    }
}
