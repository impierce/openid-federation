//! Metadata policies along a Trust Chain: the `metadata_policy` claims of its Subordinate
//! Statements merged into one (OpenID Federation 1.0, Section 6.1.4.1), and the resolved policy
//! applied to metadata (Section 6.1.4.2).

use crate::types::policy_error;
use crate::{validate_metadata_policy, FederationError, FederationResult, MetadataPolicy, PolicyOperators};
use crate::{EntityId, EntityMetadata, SubordinateStatement};
use serde_json::{Map, Value};

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
            intersection(one_of, next_one_of);
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
        (Some(subset_of), Some(next_subset_of)) => intersection(subset_of, next_subset_of),
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

/// Sets `values` to the union of `values` and `next`: each value once, in the order it first
/// appears in `values`, then in `next`.
fn union(values: &mut Vec<Value>, next: &[Value]) {
    *values = distinct(values.iter().chain(next));
}

/// Sets `values` to the intersection of `values` and `next`: each value once, in its order in
/// `values`.
fn intersection(values: &mut Vec<Value>, next: &[Value]) {
    *values = distinct(values.iter().filter(|value| next.contains(value)));
}

/// The values in order, each kept the first time it appears.
fn distinct<'a>(values: impl Iterator<Item = &'a Value>) -> Vec<Value> {
    let mut distinct: Vec<Value> = Vec::new();
    for value in values {
        if !distinct.contains(value) {
            distinct.push(value.clone());
        }
    }
    distinct
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

/// Applies a resolved metadata policy to `metadata` and returns the Resolved Metadata.
///
/// For every Entity Type that both `policy` and `metadata` have, and every metadata parameter
/// with a parameter policy, the operators run in their order of application (Section 6.1.3.1):
///
/// 1. `value`: the parameter takes the operator's value; `null` removes it.
/// 2. `add`: the values the parameter lacks are appended; an absent parameter is initialized
///    with them.
/// 3. `default`: an absent parameter takes the operator's value.
/// 4. `one_of`: a present parameter must be one of the values.
/// 5. `subset_of`: a present parameter keeps only the values it shares with the operator, which
///    may leave `[]`.
/// 6. `superset_of`: a present parameter must contain every value.
/// 7. `essential`: when `true`, the parameter must be present.
///
/// `subset_of` and `superset_of` are therefore skipped for an absent parameter, and an absent
/// `essential` one fails (Section 6.1.3.1.8, Table 1). The `scope` parameter, a string of
/// space-separated values, is processed as an array of those values and written back as such a
/// string (Section 6.1.3.1.8). Values compare as JSON values, objects included.
///
/// Metadata is processed in its JSON form, so typed and other Entity Types behave the same. A
/// policy for an Entity Type that `metadata` does not have is not applied. Additional operators
/// are not applied: this crate implements none, and [`resolve_metadata_policy`] rejects a
/// policy that uses a critical one, while one that is not critical is ignored (Section 6.1.3.2).
///
/// The typed members of [`EntityMetadata`] keep only the parameters their types define, so a
/// parameter policy for any other parameter of those Entity Types has nothing to apply to.
///
/// # Errors
///
/// [`FederationError::InvalidMetadata`] naming the Entity Type, the metadata parameter and the
/// operator that fails, a parameter policy that does not pass [`PolicyOperators::validate`], a
/// `scope` that is no longer a list of strings, or an Entity Type whose Resolved Metadata no
/// longer fits it: a required parameter removed, a value of the wrong type, or `federation_entity`
/// metadata that fails [`FederationEntityMetadata::validate`](crate::FederationEntityMetadata::validate),
/// such as an endpoint that is not `https`. Such metadata MUST NOT be used (Section 6.1.4.2).
///
/// Reference: OpenID Federation 1.0 - Section 6.1.4.2 Application
/// <https://openid.net/specs/openid-federation-1_0.html#section-6.1.4.2>
pub fn apply_metadata_policy(metadata: &EntityMetadata, policy: &MetadataPolicy) -> FederationResult<EntityMetadata> {
    let mut json = match serde_json::to_value(metadata) {
        Ok(Value::Object(json)) => json,
        Ok(other) => return Err(policy_error(format!("metadata is not a JSON object: {other}"))),
        Err(error) => return Err(policy_error(format!("metadata does not serialize: {error}"))),
    };

    let mut entity_types: Vec<&String> = policy.keys().collect();
    entity_types.sort();
    for entity_type in entity_types {
        let Some(Value::Object(parameters)) = json.get_mut(entity_type) else {
            continue;
        };
        let parameter_policies = &policy[entity_type];
        let mut names: Vec<&String> = parameter_policies.keys().collect();
        names.sort();
        for name in names {
            apply_operators(parameters, name, &parameter_policies[name]).map_err(|error| match error {
                FederationError::InvalidMetadata(message) => {
                    FederationError::InvalidMetadata(format!("{entity_type}.{name}: {message}"))
                }
                other => other,
            })?;
        }
    }

    let resolved: EntityMetadata = serde_json::from_value(Value::Object(json.clone())).map_err(|error| {
        // Name the Entity Type whose metadata no longer fits: deserialize each member alone.
        let entity_type = json.iter().find_map(|(entity_type, metadata)| {
            let mut member = Map::new();
            member.insert(entity_type.clone(), metadata.clone());
            serde_json::from_value::<EntityMetadata>(Value::Object(member))
                .is_err()
                .then_some(entity_type)
        });
        match entity_type {
            Some(entity_type) => policy_error(format!(
                "{entity_type}: the Resolved Metadata is not valid {entity_type} metadata: {error}"
            )),
            None => policy_error(format!("the Resolved Metadata is not valid metadata: {error}")),
        }
    })?;
    if let Some(federation_entity) = &resolved.federation_entity {
        federation_entity.validate().map_err(|error| {
            policy_error(format!(
                "federation_entity: the Resolved Metadata is not valid federation_entity metadata: {error}"
            ))
        })?;
    }
    Ok(resolved)
}

/// Applies the operators of one metadata parameter policy to the parameter `name` of
/// `parameters`, in their order of application.
fn apply_operators(
    parameters: &mut Map<String, Value>,
    name: &str,
    operators: &PolicyOperators,
) -> FederationResult<()> {
    // A resolved policy is valid already; a policy from elsewhere gets the same checks.
    operators.validate()?;
    let scope = name == "scope";
    let as_processed = |value: Value| if scope { scope_values(value) } else { value };
    let mut parameter = parameters.remove(name).map(as_processed);

    if let Some(value) = &operators.value {
        parameter = (!value.is_null()).then(|| as_processed(value.clone()));
    }
    if let Some(add) = &operators.add {
        let mut values = match parameter.take() {
            None => Vec::new(),
            Some(Value::Array(values)) => values,
            Some(other) => return Err(policy_error(format!("add: the parameter {other} is not an array"))),
        };
        for value in add.as_array().into_iter().flatten() {
            if !values.contains(value) {
                values.push(value.clone());
            }
        }
        parameter = Some(Value::Array(values));
    }
    if parameter.is_none() {
        parameter = operators.default.clone().map(as_processed);
    }
    if let (Some(present), Some(one_of)) = (&parameter, &operators.one_of) {
        let candidate = if scope {
            scope_string(present.clone())
        } else {
            present.clone()
        };
        if !one_of.contains(&candidate) {
            return Err(policy_error(format!(
                "one_of: {candidate} is not one of {}",
                Value::Array(one_of.clone())
            )));
        }
    }
    if let Some(subset_of) = &operators.subset_of {
        match &mut parameter {
            None => {}
            Some(Value::Array(values)) => values.retain(|value| subset_of.contains(value)),
            Some(other) => {
                return Err(policy_error(format!(
                    "subset_of: the parameter {other} is not an array"
                )))
            }
        }
    }
    if let Some(superset_of) = &operators.superset_of {
        match &parameter {
            None => {}
            Some(Value::Array(values)) => {
                let missing: Vec<Value> = superset_of
                    .iter()
                    .filter(|value| !values.contains(value))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    return Err(policy_error(format!(
                        "superset_of: the parameter lacks {}",
                        Value::Array(missing)
                    )));
                }
            }
            Some(other) => {
                return Err(policy_error(format!(
                    "superset_of: the parameter {other} is not an array"
                )))
            }
        }
    }
    if operators.essential == Some(true) && parameter.is_none() {
        return Err(policy_error("essential: the parameter is absent".to_string()));
    }

    if let Some(parameter) = parameter {
        let parameter = if scope { scope_string(parameter) } else { parameter };
        if scope && !parameter.is_string() {
            return Err(policy_error(format!(
                "scope: {parameter} is not a list of strings to write back as a space-separated string"
            )));
        }
        parameters.insert(name.to_string(), parameter);
    }
    Ok(())
}

/// The values of a `scope` string, as the array that policy operators process; any other JSON
/// value unchanged.
fn scope_values(value: Value) -> Value {
    match value {
        Value::String(scope) => Value::Array(
            scope
                .split_whitespace()
                .map(|value| Value::String(value.to_string()))
                .collect(),
        ),
        other => other,
    }
}

/// An array of `scope` values as the space-separated string the metadata carries; any other
/// JSON value, or an array with a value that is not a string, unchanged.
fn scope_string(value: Value) -> Value {
    match value {
        Value::Array(values) if values.iter().all(Value::is_string) => {
            Value::String(values.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "))
        }
        other => other,
    }
}
