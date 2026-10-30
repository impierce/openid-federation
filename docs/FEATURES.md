# Features

Everything `openid-federation` implements or plans to implement, in the order of the
[OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) specification. The
architecture behind the list is in [`DESIGN.md`](DESIGN.md). Tick a row off in the pull request that
implements it; a planned row links to the GitHub issue that tracks it once one exists.

| Status | Meaning                                       |
| ------ | --------------------------------------------- |
| ✅     | Implemented on `main`, covered by tests        |
| 🚧     | In progress                                   |
| 📋     | Planned                                       |

## Entity Statements

| Feature                                                                                              | Status | Specification                                                                                                            | Issue |
| ---------------------------------------------------------------------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------------------------ | ----- |
| `SubordinateStatement` and `EntityConfiguration`: data model, builders, serde                        |   ✅   | [Entity Statement](https://openid.net/specs/openid-federation-1_0.html#entity-statement)                           |       |
| Structural validation: `iss`/`sub` rules, `exp`, `nbf`, non-empty `jwks`                              |   ✅   | [Entity Statement Validation](https://openid.net/specs/openid-federation-1_0.html#ESValidation)     |       |
| Trust Mark entries: `trust_mark_type` matches the claim inside the Trust Mark JWT                     |   ✅   | [Entity Statement Validation](https://openid.net/specs/openid-federation-1_0.html#ESValidation)     |       |
| `from_verified_jwt`: identity binding and signature verification with endorsed keys                  |   ✅   | [Validating a Trust Chain](https://openid.net/specs/openid-federation-1_0.html#trust_chain_validation)           |       |
| Required `typ` header per artifact (`entity-statement+jwt`, `trust-mark+jwt`, …)                      |   ✅   | [Entity Statement](https://openid.net/specs/openid-federation-1_0.html#entity-statement)             |       |
| NumericDates as any JSON number, time checks with leeway done by the crate                           |   ✅   | [RFC 7519 §2](https://www.rfc-editor.org/rfc/rfc7519#section-2)                                                          |       |
| `crit` and `metadata_policy_crit`: reject statements with unsupported critical claims                |   📋   | [Entity Statement Validation](https://openid.net/specs/openid-federation-1_0.html#ESValidation)     |       |
| Require `kid` in the JWT header (`typ` is already required, see above)                               |   📋   | [Entity Statement](https://openid.net/specs/openid-federation-1_0.html#entity-statement)             |       |
| Separate error variant for invalid Entity Configurations (`InvalidSubordinateStatement` today)       |   📋   |                                                                                                                          |       |

## Metadata

| Feature                                                                                              | Status | Specification                                                                                                            | Issue |
| ---------------------------------------------------------------------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------------------------ | ----- |
| `EntityType`: the six Entity Type Identifiers, spelled as the specification spells them               |   ✅   | [Entity Type Identifiers](https://openid.net/specs/openid-federation-1_0.html#entity_types)                         | #18   |
| `federation_entity` metadata, including the informational parameters and every endpoint             |   ✅   | [Federation Entity](https://openid.net/specs/openid-federation-1_0.html#federation_entity)                         |       |
| `openid_provider`, `openid_relying_party`, `oauth_authorization_server` as typed structs             |   ✅   | [Metadata](https://openid.net/specs/openid-federation-1_0.html#metadata)                                           |       |
| `oauth_resource` and `oauth_client` as typed structs (untyped JSON objects today)                     |   📋   | [Metadata](https://openid.net/specs/openid-federation-1_0.html#metadata)                                           |       |
| Metadata policy operators as a data type                                                             |   ✅   | [Metadata Policy](https://openid.net/specs/openid-federation-1_0.html#metadata_policy)                             |       |
| Applying a metadata policy to metadata, and merging policies along a chain                           |   📋   | [Enforcement](https://openid.net/specs/openid-federation-1_0.html#metadata_policy_enforcement)                             |       |
| Resolving the leaf's metadata through the trust chain (`TrustChain::metadata`)                       |   📋   | [Resolving the Trust Chain and Metadata](https://openid.net/specs/openid-federation-1_0.html#resolving_trust)     |       |

## Constraints

| Feature                                                                                              | Status | Specification                                                                                                            | Issue |
| ---------------------------------------------------------------------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------------------------ | ----- |
| `Constraints` as a data type (`max_path_length`, `naming_constraints`, `allowed_entity_types`)        |   ✅   | [Constraints](https://openid.net/specs/openid-federation-1_0.html#chain_constraints)                                     |       |
| Enforcing constraints during trust chain validation                                                  |   📋   | [Constraints](https://openid.net/specs/openid-federation-1_0.html#chain_constraints)                                     |       |

## Trust Marks

| Feature                                                                                              | Status | Specification                                                                                                            | Issue |
| ---------------------------------------------------------------------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------------------------ | ----- |
| `TrustMark` claims, `TrustMarkIssuers`, `TrustMarkOwners`                                            |   ✅   | [Trust Marks](https://openid.net/specs/openid-federation-1_0.html#trust_marks)                                     |       |
| Optional `exp` on a Trust Mark (required today)                                                      |   📋   | [Trust Marks](https://openid.net/specs/openid-federation-1_0.html#trust_marks)                                     |       |
| Verifying a Trust Mark: issuer trusted by the anchor, signature, delegation, owner                    |   📋   | [Validating a Trust Mark](https://openid.net/specs/openid-federation-1_0.html#trust-mark-validation)                                     |       |
| Trust Mark status endpoint client                                                                    |   📋   | [Trust Mark Status](https://openid.net/specs/openid-federation-1_0.html#status_endpoint)                         |       |

## Federation endpoints and trust chain resolution

| Feature                                                                                              | Status | Specification                                                                                                            | Issue |
| ---------------------------------------------------------------------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------------------------ | ----- |
| Entity Configuration from `<entity id>/.well-known/openid-federation`, paths preserved               |   ✅   | [Obtaining Federation Entity Configuration Information](https://openid.net/specs/openid-federation-1_0.html#federation_configuration) |       |
| Fetch endpoint client (`fetch_subordinate_statement`)                                                |   ✅   | [Fetching a Subordinate Statement](https://openid.net/specs/openid-federation-1_0.html#fetch_endpoint)                  |       |
| List endpoint client (`list_entities`)                                                               |   ✅   | [Subordinate Listing](https://openid.net/specs/openid-federation-1_0.html#entity_listing)                             |       |
| Resolve endpoint client and `resolve-response+jwt`                                                    |   📋   | [Resolve Entity](https://openid.net/specs/openid-federation-1_0.html#resolve)                   |       |
| Historical keys endpoint client and `jwk-set+jwt`                                                     |   📋   | [Federation Historical Keys Endpoint](https://openid.net/specs/openid-federation-1_0.html#historical_keys)                  |       |
| Anchored trust chain discovery towards given Trust Anchors (`discover_trust_chain`)                  |   ✅   | [Fetching Entity Statements to Establish a Trust Chain](https://openid.net/specs/openid-federation-1_0.html#fetching-es)           |       |
| All-chains discovery with every skipped branch reported (`discover_all_trust_chains_with_failures`)   |   ✅   | [Fetching Entity Statements to Establish a Trust Chain](https://openid.net/specs/openid-federation-1_0.html#fetching-es)           |       |
| Trust chain authentication top-down (`TrustChain::try_new`)                                          |   ✅   | [Validating a Trust Chain](https://openid.net/specs/openid-federation-1_0.html#trust_chain_validation)           |       |
| Trust chain expiration (minimum `exp`)                                                               |   ✅   | [Calculating the Expiration Time of a Trust Chain](https://openid.net/specs/openid-federation-1_0.html#trust_lifetime) |       |
| Injectable `HttpClient`; `reqwest` with `rustls` as the default                                       |   ✅   |                                                                                                                          |       |

## JOSE

| Feature                                                                                              | Status | Specification                                                                                                            | Issue |
| ---------------------------------------------------------------------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------------------------ | ----- |
| `Jwk`, `JwkSet`, conversion to `jsonwebtoken` keys; `kid` lookup                                     |   ✅   | [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)                                                                       |       |
| Members `Jwk` does not name are kept (`Jwk::additional`); `use` (de)serializes as `use`              |   ✅   | [RFC 7517 §4](https://www.rfc-editor.org/rfc/rfc7517#section-4)                                                          |       |
| Publishable `jwks`: unique, non-empty `kid`, no private or symmetric keys (`JwkSet::validate`)       |   ✅   | [Entity Statement Claims](https://openid.net/specs/openid-federation-1_0.html#section-3.1.1)                             |       |
| Public half of a key (`Jwk::to_public`)                                                              |   ✅   | [RFC 7518 §6](https://www.rfc-editor.org/rfc/rfc7518#section-6)                                                          |       |
| SHA-256 JWK Thumbprints for RSA, EC and OKP keys (`Jwk::thumbprint`)                                 |   ✅   | [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)                                                                       |       |
| Signing and verifying with HS*, RS*, PS*, ES256, ES384, EdDSA via `jsonwebtoken`                     |   ✅   | [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)                                                                       |       |
| ES512 verification (`jsonwebtoken` does not support it; entities signing with it cannot be resolved) |   📋   | [RFC 7518 §3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)                                                      |       |
