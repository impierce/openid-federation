# ADR 0004: Entity Identifiers keep their spelling and compare as URLs

- Status: accepted
- Date: 2026-10-27

## Context

`EntityId` was an alias for `url::Url`. Parsing normalizes a URL, for example
`https://ta.example.org` becomes `https://ta.example.org/`, and the crate sent the normalized
spelling to other entities. A fetch endpoint that compares the `sub` parameter as a string does not
recognize it: a Superior deployed in a live federation answers `sub=https://ta.example.org` with
the Subordinate Statement and the normalized `sub=https://ta.example.org/` with 404 (#22).

The specification defines an Entity Identifier as a URL and requires an `iss` to match the
`authority_hints` value and the `sub` of the next statement, but does not say how to compare URLs.
Live federations spell the same identifier both ways. A Trust Anchor publishes
`https://ta.example.org`, while a member's `authority_hints` lists `https://ta.example.org/`. That
Trust Anchor's Subordinate Statement about the member, which publishes `https://leaf.example.org/`,
has `sub: https://leaf.example.org`. Comparing as plain strings would break these chains, although
both spellings name the same resource.

## Decision

1. `EntityId` is a newtype that keeps the string it was parsed from next to the parsed URL.
   `as_str`, `Display` and serialization return that spelling; `as_url` returns the parsed URL for
   building requests.
2. Two `EntityId`s are equal, and hash equal, when their URLs are equal after parsing, so an empty
   path and `/` are the same identifier (RFC 3986, Section 6.2.3 Scheme-Based Normalization). Paths
   differing in a trailing `/` beyond the host, such as `/federation` and `/federation/`, stay
   different, as RFC 3986 treats them.
3. Discovery asks a superior about an entity under the `sub` the entity publishes in its verified
   Entity Configuration, not under the spelling of the authority hint or start identifier that led
   to it.

## Consequences

- Requests carry identifiers as the entities themselves spell them, so string-comparing endpoints
  answer.
- Chains between entities that spell the same identifier with and without a trailing `/` keep
  authenticating.
- `EntityId` is no longer a `Url`: callers construct it with `EntityId::parse`, `str::parse` or
  `From<Url>`, and use `as_url` where they need URL operations. This is a breaking change.
