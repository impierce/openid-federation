# ADR 0002: Syntactic validation is separate from trust evaluation

- Status: accepted
- Date: 2026-10-23

## Context

An Entity Configuration carries Trust Marks as `{ trust_mark_type, trust_mark: "<JWT>" }`. The
specification's Entity Statement Validation requires that the `trust_mark_type` of each entry equals
the `trust_mark_type` claim inside the Trust Mark JWT, and says explicitly that evaluating whether a
Trust Mark is issued by a trusted party is a separate step that may be performed later.

A first implementation decoded the Trust Mark through `jsonwebtoken` to read the claim. That fails
on any header `jsonwebtoken` cannot parse, such as `alg: ES512`, and would have made an Entity
Configuration invalid because of a Trust Mark this crate cannot verify, although the configuration
itself is well formed.

## Decision

1. `validate` on a statement performs syntactic validation only: shape, internal consistency and the
   checks the specification lists under Entity Statement Validation. For Trust Marks that is
   `TrustMarkEntry::validate`, which splits the compact JWT, base64url-decodes the payload and
   compares the `trust_mark_type` claim. It does not verify the signature.
2. Trust evaluation, meaning the trust chain, the caller's anchors, and (when implemented) Trust
   Mark issuers, owners and delegations, is a separate step with its own API.
3. A Trust Mark signed with an algorithm this crate cannot verify is a well-formed entry. It is
   rejected, if at all, when its trust is evaluated.

## Consequences

- `from_verified_jwt` and trust chain validation refuse configurations whose Trust Mark entries
  are malformed or mismatched, as the specification requires, without taking a position on whether
  the Trust Marks are trusted.
- Trust Mark verification can be added without changing what `validate` means.
- The same split applies to future checks: `crit`, constraints and metadata policy are validated
  for shape in `validate` and enforced during chain validation and metadata resolution.
