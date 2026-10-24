# ADR 0001: Untrusted JWTs become statements only through authenticated entry points

- Status: accepted
- Date: 2026-10-14

## Context

Early versions turned a fetched JWT into an `EntityConfiguration` or `SubordinateStatement` by
decoding its claims, and validated signatures as a separate, optional step. `TrustChain::try_new`
checked the chain's structure but did not verify that each statement was signed with a key the
statement above it endorses, nor that a configuration served by one entity was actually about that
entity. A leaf could present a configuration with keys its superior never vouched for, and a server
could serve another entity's configuration under its own identifier.

## Decision

1. `EntityConfiguration::from_verified_jwt(jwt, entity_id)` and
   `SubordinateStatement::from_verified_jwt(jwt, issuer, subject, issuer_keys)` are the only way to
   obtain a statement that code may rely on. Each runs the structural `validate`, checks that `iss`
   and `sub` are exactly the expected entities, and verifies the `entity-statement+jwt` type and the
   signature: a configuration with a key from its own `jwks`, a Subordinate Statement with one of
   `issuer_keys`, which must already be authenticated for the issuer.
2. `TrustChain::try_new` authenticates top-down. The Trust Anchor's Entity Configuration is the root
   of trust; each Subordinate Statement must be issued by the entity whose keys were just
   authenticated and signed with one of them, and its `jwks` becomes the authenticated keys of its
   subject; the leaf's configuration must be signed with a key the lowest statement endorses.
3. Discovery binds every fetched document to the entity identifier it was fetched for, so a
   terminal configuration that claims another identity is rejected instead of becoming an anchor.
4. Whether a Trust Anchor is trusted is the caller's decision, made by comparing the anchor's entity
   identifier against a trust list. The crate authenticates chains; it does not pick anchors.
5. `extract_claims_unverified` remains public for inspection (reading `sub` before verification,
   the minimum `exp` of a chain) and must never be the source of a typed statement.

## Consequences

- Key substitution by a leaf and identity confusion by a server fail at construction time, with an
  error naming the entities involved.
- Tests that build chains must sign every statement with the key the statement above endorses;
  the regression tests in `src/trust_chain.rs` give each entity its own key for that reason.
- Any new way of obtaining a statement, such as a resolve endpoint client, must go through these
  constructors or add an equivalent one.
