# Contributing

Thanks for your interest in contributing to `openid-federation`!

The default branch is `main`. Pull requests target it.

## Prerequisites

- A stable Rust toolchain, installed via [rustup](https://rustup.rs/).
- The minimum supported Rust version (MSRV) is set by `rust-version` in [`Cargo.toml`](Cargo.toml) and checked in CI.
  Don't use language or standard library features newer than the MSRV without raising it.
  The policy is a rolling six months: the MSRV may be raised to any stable release that is at least six months old.
  Raise it in its own pull request, together with the dependency updates it unlocks, and mark the pull request as a breaking change (`build!:`), since a crate built on an older toolchain stops compiling.
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) to run the dependency checks locally: `cargo install --locked cargo-deny`.
- [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) to check the public API for breaking changes: `cargo install --locked cargo-semver-checks`.

## Checks

CI runs the following checks on every pull request. Run them locally before opening one:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
cargo publish --dry-run --locked
cargo deny check
cargo semver-checks --package openid-federation --all-features --baseline-rev main
```

The tests run on Linux, macOS and Windows. HTTP is exercised against [`wiremock`](https://docs.rs/wiremock) servers on `localhost`; nothing in the test suite reaches the network.

CI also measures test coverage and reports it on the pull request via [Codecov](https://codecov.io/gh/impierce/openid-federation).
To see it locally, install [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) and run `cargo llvm-cov --all-features --open`.

### Specification references

Every public type and function documents the section of [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) it implements, as a `Reference:` line with a link to the section anchor.
Keep that line when you change an item, and add one to anything new.
Tests assert what the specification requires; when a live federation shows another implementation behaving differently, the fix cites the section that decides it.

### Fuzzing

The parsers are fuzzed with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) from the [`fuzz/`](fuzz/) crate, a workspace of its own that builds on nightly.
Each target feeds arbitrary input to one surface and asserts that nothing panics and that whatever parses round-trips; CI runs every target for a minute on pull requests that touch `src/` or `fuzz/` and for ten minutes nightly.
[`fuzz/README.md`](fuzz/README.md) describes the targets, the committed seeds, the generated corpus and how to run, replay and extend them.

```sh
cargo install --locked cargo-fuzz
fuzz/run.sh entity_statement 600      # one target, ten minutes
```

## Pull requests

Pull requests are squash-merged, so the **pull request title** becomes the commit message on `main`.
It must follow [Conventional Commits](https://www.conventionalcommits.org/), which CI checks:

- `` feat: resolve metadata through trust chain ``
- `` fix(jwt): accept non-integer NumericDates ``
- `` feat!: rename `TrustMark` to `TrustMarkClaims` `` (breaking change)

The title also determines the next version number and the changelog entry, so describe the change from a user's point of view.
Write it in terse commit style: drop articles (_the_, _a_, _an_) and wrap code literals in backticks, as in `` fix(entity): reject Trust Mark entries whose type differs from JWT claim ``.
Write `feat: add description to file`, not `feat: add a description to the file`.

A change that breaks the public API needs `!` in the title (`feat!:`, `fix!:`): before 1.0 it bumps the minor version, and the changelog lists it as breaking.
CI's `SemVer` job runs [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) on the public API, with all features, against the pull request's base, unless the title already has the `!`, and fails when it finds a breaking change.
After adding the `!`, re-run that job: it reads the current title, but editing the title doesn't start it.

## Releases

Releases are automated with [release-plz](https://release-plz.dev/): it keeps a release pull request open with the next version and changelog, and publishes to crates.io once that pull request is merged.
Don't bump the version or edit `CHANGELOG.md` outside that release pull request.
[`docs/RELEASE.md`](docs/RELEASE.md) describes the full process.

## Feature checklist

[`docs/FEATURES.md`](docs/FEATURES.md) lists every implemented and planned feature against the specification, with its tracking issue.
When a pull request implements a feature, change its status to ✅ in the same pull request.

## Agent skills

Coding agents in this repository use the skills of [mattpocock/skills](https://github.com/mattpocock/skills): the set its Claude Code plugin ships, from one release.
They are committed rather than installed as a plugin, because cloud sessions of Claude Code don't install the plugins a repository enables.

- `.agents/skills/` holds the skills; `.claude/skills/` holds one symlink per skill, which is where Claude Code reads them. On Windows, links need Developer Mode (or the *Create symbolic links* user right) and `core.symlinks` set before checkout: clone with `git clone -c core.symlinks=true <url>`, or set `git config --global core.symlinks true` first. In an existing clone, set `git config core.symlinks true`, then run `git checkout -- .claude/skills` to turn the plain files back into links.
- `skills-lock.json` pins the release (`ref`) and a hash of every skill. The [`skills`](https://github.com/vercel-labs/skills) CLI writes it.
- The `Agent skills` workflow checks for a new release every Monday and opens a pull request that installs it. Read the upstream changelog it links before merging; when an entry asks to re-run `/setup-matt-pocock-skills`, run it on that branch so `docs/agents/` follows the new templates.
- To install a release by hand, run `scripts/update-agent-skills.sh <tag>`, for example `scripts/update-agent-skills.sh v1.3.2`. It needs Node.js, `curl` and `jq`.

Don't edit the skills in place: the next update overwrites them. Repository-specific guidance belongs in `AGENTS.md` and `docs/agents/`, which the skills read.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md), and not in public issues or pull requests.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), as described in section 5 of the license.
