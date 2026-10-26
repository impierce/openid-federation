# ADR 0003: NumericDates are read and checked by the crate, not by `jsonwebtoken`

- Status: accepted
- Date: 2026-10-23

## Context

RFC 7519 defines `exp`, `iat` and `nbf` as NumericDates: any JSON number of seconds, non-integer
values included. Some federation implementations send `1.7E9`. `JwtClaims` only accepted integers,
so their statements failed to deserialize.

`jsonwebtoken`'s own time validation has a second problem: once `serde_json`'s
`arbitrary_precision` feature is enabled anywhere in a build, for example by a transitive
dependency of the application, it misreads a non-integer `exp` as missing and rejects the token.
A library cannot control the feature set of the final binary.

## Decision

1. `exp`, `iat` and `nbf` deserialize through `serde_json::Number`, accept any JSON number and round
   it to whole seconds, as `jsonwebtoken` does when it validates. This works with and without
   `arbitrary_precision`, including inside `#[serde(flatten)]`.
2. `JwtProcessor::verify_jwt` lets `jsonwebtoken` verify the signature only. It then applies the
   `exp` and `nbf` checks itself, with the same leeway, required claims and error kinds, so callers
   see no difference.
3. `extract_claims_unverified` requires no claims, since it validates nothing; the target type
   requires what it needs.

## Consequences

- Statements from implementations that emit non-integer NumericDates resolve.
- Behaviour no longer depends on which `serde_json` features the consuming application enables.
- Time validation has its own tests (expiry, leeway, `nbf`, missing `exp`), which `jsonwebtoken`'s
  path never had in this crate; changes to `jsonwebtoken`'s validation do not change this crate's.
