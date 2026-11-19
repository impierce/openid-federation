# ADR 0006: Statements carry partial metadata; only Resolved Metadata is typed

- Status: accepted
- Date: 2026-11-04

## Context

`EntityConfiguration::metadata` and `SubordinateStatement::metadata` were `EntityMetadata`, whose
`openid_provider`, `openid_relying_party` and `oauth_authorization_server` members are structs
with required fields, such as `issuer` and `redirect_uris`.

The specification lets a statement state only part of an Entity Type's metadata (Section 3.1.1):

- An Entity Configuration publishes `{}` for an Entity Type when "Immediate Superiors supply any
  needed metadata".
- An Immediate Superior "MAY provide selected or all metadata parameters" for a Subordinate, and
  those override the Subordinate's parameters of the same name.

Such statements failed to parse, so their Trust Chains failed before metadata resolution (#55)
could combine the parts. Only the Resolved Metadata of a Trust Chain must be complete
(Section 6.1.4.2).

## Decision

1. Statements hold their `metadata` claim as `StatementMetadata`: `federation_entity` as
   `FederationEntityMetadata`, whose parameters are all optional and whose endpoints discovery
   reads, and every other member as the JSON object it is. Each member must be a JSON object.
2. `TrustChain::try_new` resolves the subject's metadata on that JSON and reads the result as
   `EntityMetadata`. Resolved Metadata that does not fit its Entity Types makes the chain invalid.
   `TrustChain::metadata` is that result, and a `TrustChain` comes only from `try_new`.
3. Code that builds a statement from typed metadata converts it with
   `StatementMetadata::try_from(EntityMetadata)`, which refuses an `additional` member that repeats
   a typed parameter. `StatementMetadata::to_entity_metadata` reads a complete claim as types.

## Consequences

- Chains whose statements carry partial metadata, as the specification allows, resolve.
- The parameters of a statement's non-`federation_entity` members are no longer checked against
  their types when the statement is parsed, but when the Trust Chain resolves.
- Builders take `StatementMetadata`; callers holding `EntityMetadata` call `try_into()`. This is
  a breaking change.
- A typed parameter repeated in `additional` can no longer reach signing: the conversion refuses
  it, and a JSON object cannot hold a member twice.
