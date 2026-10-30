# AGENTS.md

## Project

`openid-federation` is a single-crate Rust library for OpenID Federation 1.0: Entity Statements, Trust Chains, Trust Marks, entity metadata, and a client that discovers and authenticates trust chains over the federation endpoints.

- `docs/DESIGN.md` is the architecture and the trust model. Follow it unless there is a concrete reason not to, and record any deviation as an ADR in `docs/adr/`.
- The work breakdown is tracked as GitHub Issues labelled `ready-for-agent`, linked by native issue dependencies. Pick the lowest-numbered open issue with no open blockers, one pull request per issue, each with its tests.
- `CONTRIBUTING.md` lists the checks CI runs and the pull request conventions. Read it before writing a pull request title.
- `docs/FEATURES.md` is the feature checklist against the specification. When a pull request implements a row, flip its status to ✅ in that pull request.
- `GLOSSARY.md` is the domain language, in the specification's terms. Use its terms in code, tests, issues and pull requests.
- The agent skills from [mattpocock/skills](https://github.com/mattpocock/skills) live in `.agents/skills/`, with a link per skill in `.claude/skills/`, installed by the [`skills`](https://github.com/vercel-labs/skills) CLI and pinned in `skills-lock.json`. They are upstream files: don't edit them. A scheduled workflow opens a pull request for each new release (`CONTRIBUTING.md`).

## Ground rules

- The specification is the oracle. [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) decides behaviour. Every public item cites the section it implements, and a test asserts what the section requires, never what another implementation happens to emit. When implementations in the wild disagree with the specification, the specification wins, and the deviation gets a test and a comment that cites the section.
- Untrusted input is authenticated before it is typed. A JWT becomes an `EntityConfiguration`, a `SubordinateStatement` or a `TrustChain` only through `from_verified_jwt` and `TrustChain::try_new`, which bind the statement to the entity it was fetched for and verify its signature with keys that are already authenticated: a Trust Anchor's Entity Configuration with its own `jwks`, a Subordinate Statement with the keys authenticated for its issuer, and a leaf's Entity Configuration with the keys its superior endorses (ADR 0001). `extract_claims_unverified` is for inspection and is never a source of trust.
- Syntactic validation and trust evaluation are separate steps, as the specification separates them (ADR 0002). `validate` checks shape and internal consistency; whether an issuer is trusted is decided by the trust chain and the caller's Trust Anchors.
- Time claims are NumericDates, read and checked by this crate, not by `jsonwebtoken` (ADR 0003).
- Discovery is best-effort and explicit about failures. Anchored discovery fails fast with a branch-specific error; all-chains discovery records every skipped branch in `TrustChainDiscovery`. Never drop an error silently.
- No git or path dependencies; `cargo publish --dry-run` must pass on every pull request.
- `unsafe_code = "forbid"`, clippy clean under `-D warnings`, `cargo doc` clean under `-D warnings`, and the MSRV in `rust-version` of `Cargo.toml` compiles.

## Agent skills

### Issue tracker

Issues live in GitHub Issues on `impierce/openid-federation` (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary, except that the `wontfix` role uses the existing `Wontfix` label: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `Wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
