# ADR 0005: The issuing side lives in this crate, behind framework-agnostic handlers, an async signer and storage traits

- Status: accepted
- Date: 2026-10-30

## Context

The crate is a client today: it discovers, authenticates and evaluates Trust Chains. To operate a
federation, a Trust Anchor or Intermediate Entity also publishes its Entity Configuration, issues
Subordinate Statements and serves the federation endpoints (OpenID Federation 1.0,
[Appendix A.1](https://openid.net/specs/openid-federation-1_0.html#appendix-A.1),
[Section 8](https://openid.net/specs/openid-federation-1_0.html#section-8),
[Section 9](https://openid.net/specs/openid-federation-1_0.html#section-9)).

The crate is a general-purpose library. Known consumers are an agent that runs a Trust Anchor and a
wallet that only relies on federations. It has to work well with `identity-kit` without depending on
it. Applications serve HTTP with different web frameworks, keep keys in memory, an HSM or a KMS, and
store subordinates in their own databases.

## Decision

1. **Same crate, no Cargo feature.** The issuing side lives next to the relying side. It adds code,
   not dependencies, so relying-only users lose nothing, and the crate stays one crate without Cargo
   features.
2. **Framework-agnostic endpoint handlers.** Each federation endpoint is a function that takes the
   parsed request (HTTP method and query or form parameters, repeated parameters kept) and returns a
   response value: HTTP status, content type and body. The crate depends on no web framework; the
   application mounts the handlers in its router. Handlers ignore parameters they do not know, as
   Section 8 requires, and answer errors with the error response of
   [Section 8.9](https://openid.net/specs/openid-federation-1_0.html#section-8.9).
3. **An async signer trait owned by this crate.** `fn alg(&self)`, `fn kid(&self)` and
   `async fn sign(&self, signing_input: &[u8])`, which returns the signature in its JWS form. This
   is the same shape as `identity_kit::jose::Signer`, so an adapter takes a few lines, without a
   dependency on `identity-kit`. The in-memory implementation takes a DER-encoded private key and
   signs through `jsonwebtoken`, so the crypto backend stays the application's choice.
4. **Storage behind async traits, with in-memory implementations.** Subordinates, Trust Marks and
   keys are read and written through traits the application implements on its own database.
   In-memory implementations ship for tests, examples and small deployments.
5. **Verification stays on `jsonwebtoken`.** The issuing side builds on the existing JOSE layer;
   replacing it is out of scope.

### Considered options

- **A separate crate, or a Cargo feature, for the issuing side.** Rejected: the issuing side needs
  no extra dependency, and a feature would split the documentation and the test matrix for no
  saving.
- **Handlers for one web framework (such as `axum`).** Rejected: it forces that framework, and its
  release cadence, on every consumer, including the relying-only ones.
- **Taking `jsonwebtoken::EncodingKey` for signing.** Rejected: the private key must then be in
  process memory, which rules out an HSM or KMS for the keys that sign a whole federation.
- **Depending on `identity-kit` for the signer.** Rejected: it would pull the DID and credential
  stack into a crate that only needs one trait.

## Consequences

- Wiring a handler is a few lines in the application. With `axum`, for example (the names are
  illustrative; the handler and response types land with the endpoint issues):

  ```rust,ignore
  async fn fetch(
      State(federation): State<Arc<Federation>>,
      RawQuery(query): RawQuery,
  ) -> impl IntoResponse {
      let request = EndpointRequest::get(query.as_deref().unwrap_or_default());
      let response = endpoint::fetch(&federation.subordinates, &federation.signer, request).await;
      (
          StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
          [(header::CONTENT_TYPE, response.content_type)],
          response.body,
      )
  }
  ```

- Caching, rate limiting and client authentication policy around the handlers are the application's
  concern, unless an issue adds them to the crate.
- The storage traits are the contract between the crate and an application's database; changing
  them is a breaking change, so they stay small.
- A signer whose backend fails returns an error; handlers turn it into `server_error`, never a
  panic.
