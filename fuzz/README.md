# Fuzzing

The parsers of `openid-federation` are fuzzed with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz), the Cargo front end for LLVM's [libFuzzer](https://llvm.org/docs/LibFuzzer.html).
Each target in this directory feeds arbitrary bytes to one surface of the crate and asserts a property that must hold for every input: nothing panics, and whatever parses survives a round trip through its serialization.
libFuzzer mutates the inputs, keeps every input that reaches code the previous ones did not, and stops at the first panic, crash or timeout.
It runs on nightly, with AddressSanitizer, which is why this directory is a Cargo workspace of its own.

## Targets

One file per target in [`fuzz_targets/`](fuzz_targets/); the doc comment at the top of each states the property it asserts.

| Target             | Surface                                                                                                                              | Input                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------- |
| `entity_statement` | `EntityConfiguration`, `SubordinateStatement`, `EntityMetadata` as JSON: parse, `validate`, `to_subordinate_statement`, round trip   | a JSON document                                    |
| `jwt`              | `decode_header` and `typ` validation, `extract_claims_unverified`, `from_verified_jwt`, `TrustChain::try_new` over the input's lines | a compact JWT, or one JWT per line                 |
| `trust_mark`       | `TrustMarkEntry::validate`; `TrustMark`, `TrustMarkIssuers`, `TrustMarkOwners` round trips                                           | a Trust Mark type on the first line, then the JWT; or JSON |
| `jwk`              | `Jwk` and `JwkSet` JSON, conversion to `jsonwebtoken` keys, `kid` lookup, signature-key selection, round trip                        | a JWK or JWK Set as JSON                           |
| `entity_id`        | `UrlValidator::validate_entity_id` and `validate_endpoint_url`; a valid Entity Identifier prints and re-parses to itself; an `EntityId` keeps its spelling and equals the `EntityId` of its normalized URL | a URL |

Nothing in the targets verifies a signature, since no key is known for arbitrary input: `from_verified_jwt` and `try_new` are exercised for the absence of panics, and a result is accepted either way.

## Layout

```
fuzz/
├── Cargo.toml          # one [[bin]] per target; the Fuzz workflow discovers the targets here
├── fuzz_targets/       # the targets
├── seeds/<target>/     # committed starting inputs, one file per example
├── corpus/<target>/    # what the fuzzer discovers; generated, not committed
├── artifacts/<target>/ # the input of a failing run; generated, not committed
└── run.sh              # runs one target over its corpus and seeds
```

### Seeds

libFuzzer starts from whatever inputs it is given and mutates from there, so a seed that already parses puts it deep into the code from the first run instead of leaving it to guess the shape of an Entity Statement byte by byte.
The seeds in `seeds/<target>/` are specification examples (the JWKs of RFC 7517 and RFC 8037) and statements modelled on the specification's own federation example (`op.umu.se`, `umu.se`, `swamid.se`), signed with the test suite's HS256 key where a signature is needed, plus a few hand-made edge cases such as non-integer NumericDates and an `ES512` header.
Every file is named after what it holds, so it can be read and reviewed.
The names are for people; libFuzzer reads only the bytes.

### Corpus and artifacts

`corpus/<target>/` is where libFuzzer writes every input that reached new coverage.
Files there are named by the SHA-1 of their content, the libFuzzer convention, and they are mutated bytes nobody needs to read; the directory is in `.gitignore`.
In CI the corpus is cached per target between runs ([`actions/cache`](../.github/workflows/fuzz.yml)), so each run continues from the coverage of the previous one; locally it accumulates in your checkout.
Deleting it costs nothing but the time to rediscover it.

`artifacts/<target>/` holds the input of a failing run as `crash-<sha1>`, `timeout-<sha1>` or `oom-<sha1>`; the file is also what the workflow uploads when a job fails.

## Running locally

```sh
cargo install --locked cargo-fuzz
rustup toolchain install nightly

cargo +nightly fuzz list                           # the targets
fuzz/run.sh entity_statement 600                   # one target, ten minutes, over its corpus and seeds
cargo +nightly fuzz run jwt fuzz/artifacts/jwt/crash-…     # replay a failing input
cargo +nightly fuzz tmin jwt fuzz/artifacts/jwt/crash-…    # shrink it to the smallest failing input
cargo +nightly fuzz coverage jwt fuzz/corpus/jwt fuzz/seeds/jwt   # coverage of the corpus
```

`run.sh` passes the corpus directory first and the seeds second, which is how libFuzzer tells where to write (the first) from what to read (the rest); run `cargo fuzz run` by hand the same way, or the seeds are left out.

## In CI

The [Fuzz workflow](../.github/workflows/fuzz.yml) reads the targets from `Cargo.toml` and runs each one in its own job, for a minute on pull requests that touch `src/` or `fuzz/` and for ten minutes nightly, restoring and saving the corpus cache around the run.
A failing job uploads `artifacts/<target>/` for replay.

## When a target finds something

A crash is a bug in the library, or a property the target states too strongly; the input decides which.

- A bug: fix it in `src/`, add the input's behaviour as a regular test from the specification section it violates, keep the target's assertion.
- A wrong assumption in the target (a value that legitimately does not round-trip byte for byte): narrow the assertion and say why in a comment.
  Two such cases are already handled: `entity_id` asserts the round trip only for valid Entity Identifiers, because `url` does not round-trip every URL it parses, and the fuzz crate enables `serde_json`'s `float_roundtrip` feature, because without it a long numeric literal in an unknown claim changes on the second parse.

## Adding a target or a seed

A target is a file in `fuzz_targets/` and a `[[bin]]` entry in `Cargo.toml` with `test`, `doc` and `bench` off; the workflow picks it up from the manifest.
State the property in the doc comment, and seed it from the specification's examples under `seeds/<target>/`, one example per file, named after its source.
