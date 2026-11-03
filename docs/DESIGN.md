# OpenID Federation: Design

`openid-federation` is a Rust library for [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html): the data model of Entity Statements, Trust Chains and Trust Marks, their validation, and a client that discovers and authenticates trust chains over the federation endpoints. The [issuing side](#issuing-side), for Trust Anchors and Intermediate Entities that sign statements and serve those endpoints, is being added to the same crate (ADR 0005).
It is published as **one crate** without Cargo features. Consumers are `impierce/openid4vc` and `impierce/ssi-agent` (UniCore), which use it to establish trust between wallets, issuers and verifiers that belong to a federation.

This document describes the architecture as it is and the direction it is going. [`FEATURES.md`](FEATURES.md) tracks which parts of the specification are implemented and which are planned.

## Principles

1. **The specification is the oracle.** Every public type and function cites the section it implements, and the tests assert what the section requires. When another implementation in a live federation disagrees with the specification, the specification wins; interoperability fixes are accepted when the specification allows the behaviour (a path in an Entity Identifier, a non-integer NumericDate) and rejected when it does not.
2. **Untrusted input is authenticated before it is typed.** `EntityConfiguration::from_verified_jwt`, `SubordinateStatement::from_verified_jwt` and `TrustChain::try_new` are the only ways to turn a JWT string into a statement that code may rely on. Each binds the statement to the entity it was fetched for (`iss`, `sub`) and verifies the signature with keys that are already authenticated: the Trust Anchor's Entity Configuration with its own `jwks`, each Subordinate Statement with the keys authenticated for its issuer, and the leaf's Entity Configuration with the keys its superior endorses; the [Trust model](#trust-model) section spells out each step (ADR 0001). `extract_claims_unverified` exists for inspection, such as reading `sub` before verification, and never creates trust.
3. **Syntactic validation and trust evaluation are separate steps**, as the specification separates them. `validate` checks that a statement is well formed and internally consistent: `iss`/`sub` rules, `exp`/`nbf`, a non-empty `jwks`, Trust Mark entries whose type matches their JWT. Whether a Trust Anchor is trusted, or a Trust Mark issuer is, is decided by the caller's trust list and the trust chain (ADR 0002).
4. **Time claims are the crate's responsibility.** `exp`, `iat` and `nbf` are NumericDates, any JSON number of seconds, and are read and checked by this crate with the same leeway and error kinds `jsonwebtoken` would use. Verifying a JWT checks `exp` not past and `nbf` and `iat` not in the future, each with 60 seconds of leeway; the `validate` of an Entity Configuration or a Subordinate Statement, which `from_verified_jwt` runs first, checks `exp` and `nbf` against the current time without leeway. `jsonwebtoken` verifies signatures only, with the key of the issuer's `jwks` whose `kid` the header names exactly (ADR 0003).
5. **Discovery is best-effort and explicit about failures.** Anchored discovery stops at the first failing branch with an error that names it. All-chains discovery keeps exploring siblings and returns every skipped branch next to the chains it found, so a caller can tell an entity without a trust chain from one whose superiors could not be reached. No error is dropped silently.
6. **Few, maintained dependencies, publishable from day one.** `jsonwebtoken` for JWS, `reqwest` with `rustls` for HTTP, `serde`, `serde_json`, `url`, `chrono`, `base64`, `thiserror`, `tokio`. No git or path dependencies; `cargo publish --dry-run` runs on every pull request.
7. **Developer experience.** `unsafe_code = "forbid"`, clippy and rustdoc clean under `-D warnings`, a rolling six-month MSRV, one `CHANGELOG.md`, `release-plz`.

## Layout

```
openid-federation/
├── Cargo.toml
├── src/
│   ├── lib.rs           # re-exports every module at the crate root; integration tests
│   ├── entity.rs        # EntityConfiguration, SubordinateStatement: constructors, validate, from_verified_jwt
│   ├── trust_chain.rs   # TrustChain: try_new (authentication), expiration, leaf and anchor accessors
│   ├── jwt.rs           # JwtArtifactType (`typ` headers), JwtClaims, NumericDate, JwtProcessor, extract_claims_unverified
│   ├── jwk.rs           # Jwk, JwkSet and their conversion to jsonwebtoken keys; HistoricalKeys (Section 8.7.2)
│   ├── metadata.rs      # EntityMetadata and the metadata type of each entity type
│   ├── types.rs         # EntityId, EntityType, TrustMarkEntry, TrustMark, TrustMarkIssuers, TrustMarkOwners, MetadataPolicy, PolicyOperators (validate_metadata_policy), Constraints, NamingConstraints
│   ├── trust_marks.rs   # TrustMark::from_verified_jwt, TrustMarkRejection, FederationClient::verify_trust_mark and verify_chain_trust_marks (Sections 7.2.2, 7.3)
│   ├── utils.rs         # HttpClient, HttpResponse, FederationClient (fetch, resolve, discover, list), TrustChainDiscovery, UrlValidator
│   ├── endpoint.rs      # EndpointRequest, EndpointResponse, ErrorCode, ErrorResponse (Section 8.9)
│   ├── endpoint/
│   │   ├── entity_configuration.rs  # EntityConfigurationEndpoint (Section 9)
│   │   ├── fetch.rs     # FetchEndpoint (Section 8.1)
│   │   ├── historical_keys.rs  # HistoricalKeysEndpoint (Section 8.7)
│   │   ├── list.rs      # ListEndpoint (Section 8.2), filtered by a TrustMarkStore when it has one
│   │   ├── trust_mark_status.rs  # TrustMarkStatusEndpoint (Section 8.4)
│   │   ├── trust_marked_entities.rs  # TrustMarkedEntitiesEndpoint (Section 8.5)
│   │   └── trust_mark.rs  # TrustMarkEndpoint (Section 8.6)
│   ├── store.rs         # Subordinate, SubordinateStore, InMemorySubordinateStore; IssuedTrustMark, TrustMarkStore, InMemoryTrustMarkStore
│   ├── onboarding.rs    # FederationClient::check_candidate_subordinate, SubordinatePolicy, CandidateReport (Appendix A.1)
│   ├── policy.rs        # resolve_metadata_policy: the metadata policies of a Trust Chain merged into one (Section 6.1.4.1)
│   ├── keys.rs          # FederationKeys across rollover (Section 11.2), KeyStore, InMemoryKeyStore
│   └── error.rs         # FederationError, EndpointError, FederationResult
├── fuzz/                # cargo-fuzz targets; a workspace of its own
└── docs/                # this document, FEATURES.md, RELEASE.md, adr/, agents/
```

The module split follows the specification: `entity` and `trust_chain` are its Entity Statement and Trust Chain sections, `metadata` and `types` carry the data model of the Metadata, Federation Policy, Constraints and Trust Marks sections, `utils` holds the Federation Endpoints and the resolution of trust chains, and `jwt` is the JOSE layer shared by all of them.

## Trust model

A trust chain is a list of JWTs: the leaf's Entity Configuration first, then one Subordinate Statement per superior, then the Trust Anchor's Entity Configuration last. `TrustChain::try_new` authenticates it top-down:

1. The Trust Anchor's Entity Configuration must be self-signed with a key from its own `jwks`. Those keys are the root of trust for the chain. **Whether this anchor is one the caller trusts is the caller's decision**: discovery binds the configuration to the entity identifier it was fetched from, and the caller compares that identifier against its trust list.
2. Each Subordinate Statement, walking downwards, must be issued by the entity whose keys were just authenticated and be signed with one of those keys. Its `jwks` then becomes the set of authenticated keys for its subject.
3. The leaf's Entity Configuration must be about the entity the lowest Subordinate Statement endorses, be signed with a key that statement endorses, and be self-signed with a key from its own `jwks`. A leaf therefore cannot substitute its own keys for the ones its superior vouches for.

Every statement is signed with the key its header's `kid` names exactly, and lists in `crit` only extension claims the caller understands: `TrustChain::try_new` and the `from_verified_jwt` constructors take them as `understood_claims`, and `FederationClient::with_understood_claims` sets them for discovery. A statement whose `crit` names any other claim is invalid (Section 13.4).

`FederationClient` fetches the pieces: `resolve_entity_configuration` from `<entity id>/.well-known/openid-federation`, `fetch_subordinate_statement` from the superior's `federation_fetch_endpoint`. `discover_trust_chain` walks `authority_hints` towards a given set of Trust Anchors and returns the first chain that authenticates. `discover_all_trust_chains_with_failures` walks every branch and returns every chain plus every skipped branch as a `TrustChainDiscoveryFailure`. It ends a chain at every superior it reaches, not only at entities without `authority_hints`, since a Trust Anchor may have Superiors of its own when it also acts as an Intermediate Entity in another federation (Section 4.1); the caller picks the anchors it trusts. Superiors are asked about an entity under the `sub` it publishes: an `EntityId` keeps the spelling it was parsed from and compares as a URL, so `https://ta.example.org` and `https://ta.example.org/` are the same entity, but requests carry the spelling the entity uses (ADR 0004).

Trust Marks are carried in an Entity Configuration as `TrustMarkEntry { trust_mark_type, trust_mark }`, the type next to the signed Trust Mark JWT. `validate` checks that the type matches the `trust_mark_type` claim inside the JWT. A Trust Mark Issuer builds a `TrustMark` and signs it with `sign`, or with `sign_entry` to get the entry for the subject's Entity Configuration; when the issuer is not the owner of the Trust Mark type, the owner signs a `TrustMarkDelegation` that goes into the Trust Mark's `delegation` claim, and `TrustMark::validate` checks that it delegates that type to that issuer. Verifying a Trust Mark that an Entity presents is the trust evaluation step (Section 7.3). Trust in the issuer comes first: `FederationClient::verify_trust_mark` discovers the issuer's Trust Chain to the Trust Anchor, or uses the Trust Anchor's own keys when it is the issuer, and `TrustMark::from_verified_jwt` then checks the Trust Mark against the keys the issuer's Superior endorses and the Trust Anchor's Entity Configuration. The Trust Anchor must list the type in `trust_mark_issuers`, with the issuer or with no issuer at all (Section 17.5); when it names an owner for the type in `trust_mark_owners`, the Trust Mark must carry a delegation signed with the owner's key (Section 7.2.2). The checks that need no key run before discovery, so a Trust Mark that fails them causes no request to the issuer it names. A failed Trust Mark check is a `TrustMarkRejection` naming the step, wrapped in `FederationError::TrustMarkRejected`; an unreachable Trust Anchor, or an issuer without a Trust Chain to it, returns the `FederationError` of that fetch or discovery. Discovery leaves `TrustChain::trust_marks` empty, since every issuer needs a Trust Chain of its own; `FederationClient::verify_chain_trust_marks` fills it with the leaf's Trust Marks that verify and returns the others.

## Issuing side

A Trust Anchor or Intermediate Entity publishes its Entity Configuration, issues Subordinate Statements about its Immediate Subordinates, and serves the federation endpoints (Appendix A.1, Sections 8 and 9). The issuing side is planned in [`FEATURES.md`](FEATURES.md) and built on three pieces, decided in ADR 0005:

- **Endpoint handlers.** One function per federation endpoint. It takes the parsed request (HTTP method and query or form parameters, repeated parameters kept) and returns a response value: HTTP status, content type and body. The crate depends on no web framework; the application mounts each handler in its own router and keeps rate limiting and access policy there, and HTTP caching too. A handler that signs keeps what it signed only as long as the specification lets it: `EntityConfigurationEndpoint` caches the signed Entity Configuration and signs a fresh one within its refresh margin of `exp`. Handlers ignore parameters they do not know (Section 8) and answer errors with the error response of Section 8.9. Each handler is a value that holds what its endpoint needs, such as the signer and the store, with an async `handle` that returns the response and a `try_handle` that returns the cause of a `server_error` instead, for the application to log; the `server_error` response itself does not say why.
- **The `Signer` trait.** `alg()`, `kid()` and `async fn sign(signing_input)`, the same shape as `identity_kit::jose::Signer`, so the private key can live in memory, an HSM or a KMS. The crate's in-memory signer takes a DER-encoded private key and signs through `jsonwebtoken`, so the crypto backend stays the application's choice. Every signed artifact gets its `typ` from the artifact and its `kid` from the signer.
- **Storage traits.** Registered subordinates, issued Trust Marks and the entity's keys are read and written through async traits that the application implements on its own database. In-memory implementations ship for tests, examples and small deployments.

Before registering a subordinate, the Superior checks the candidate with `FederationClient::check_candidate_subordinate`. The specification does not standardise enrollment, but a statement about an entity whose `authority_hints` do not name the Superior, or whose keys differ from the registered ones, completes no Trust Chain (Sections 10.1 and 10.2). The check fetches and verifies the candidate's self-signed Entity Configuration and reports every check it fails as a `CandidateReport` rather than one error, so an operator sees all of them at once; a report without failures converts into the `Subordinate` the store keeps, with its `jwks`, Entity Types and Intermediate status taken from the verified configuration.

The relying side is unchanged by any of this, and a relying-only application pulls in no extra dependency. `endpoint.rs` holds the request and response values every handler takes and returns and the error responses; as the issuing-side issues land, the layout grows by:

```
src/
└── endpoint/     # + the remaining endpoint handlers
```

The `Signer` trait and the function that builds a compact JWS with it join the JOSE layer in `jwt.rs`.

## Errors

`FederationError` is one `#[non_exhaustive]` enum: wrapped `jsonwebtoken`, `serde_json`, `url` and `reqwest` errors, plus `InvalidSubordinateStatement`, `InvalidTrustMark`, `TrustChainValidation`, `EntityResolution`, `InvalidMetadata`, `MissingField`, `Configuration`, `InvalidJwtHeaderTyp`, `Signing`, `Store` and `Endpoint`, each with a message that names the entity or claim involved. Discovery errors list the branch that failed, so a caller can act on them without parsing the message.

Federation endpoints answer errors with the error response of Section 8.9: `{ "error", "error_description" }` as `application/json`, with a recommended HTTP status per code. Both sides share one model in `endpoint.rs`:

- **Serving.** `ErrorCode` has a variant per code the specification uses and `Other(String)` for any other, with `as_str` and the recommended `status`. An `ErrorResponse` converts into the `EndpointResponse` every handler returns: that status, `application/json` and the JSON body.
- **Fetching.** `HttpClient::get` returns every response as an `HttpResponse` (status, content type, body) and errs only when no response arrived. `FederationClient` turns a status other than 2xx into `FederationError::Endpoint(EndpointError { url, status, response })`; `response` is the parsed `ErrorResponse`, or `None` when the body is not one, so the status is never lost. The body is read whatever its content type, since Section 8.9 only says it SHOULD be `application/json`.

`InvalidSubordinateStatement` is also used for invalid Entity Configurations today. Splitting it is a breaking change and tracked in [`FEATURES.md`](FEATURES.md).

## Testing

- Unit tests live next to the code and in `src/lib.rs`. They build statements with the crate's own constructors and sign them with `jsonwebtoken`, so a test states the rule it checks rather than a captured fixture.
- HTTP is tested against [`wiremock`](https://docs.rs/wiremock) servers on `localhost`, one per entity, which makes negative cases (an unreachable superior, a statement about the wrong subject, a key the leaf does not sign with) explicit.
- The parsers are fuzzed with `cargo-fuzz` from `fuzz/`: arbitrary bytes must never panic, and whatever parses must round-trip.
- Interoperability against live federations is checked by hand before a release and fed back as unit tests citing the specification.

## Conformance

CI proves what this document promises: formatting, clippy and rustdoc under `-D warnings`, tests on three operating systems, a build on the MSRV, `cargo publish --dry-run`, `cargo deny` for advisories and licenses, and the fuzz targets on every change to `src/`.
