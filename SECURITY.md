# Security Policy

## Supported versions

Until 1.0, only the latest released version of `openid-federation` receives security fixes.

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public issues, discussions or pull requests.

Instead, report them privately through [GitHub's private vulnerability reporting](https://github.com/impierce/openid-federation/security/advisories/new).

Please include as much of the following as you can:

- The affected version(s) and, if relevant, the enabled crate features
- A description of the vulnerability and its impact
- Steps to reproduce, ideally a minimal proof of concept

## What happens next

We will acknowledge your report, investigate it and keep you updated on our progress in the advisory.
Once a fix is released, we publish a GitHub Security Advisory and request a [RustSec](https://rustsec.org/) advisory, so that users of `cargo audit` and `cargo deny` are notified.
Unless you prefer otherwise, we credit you in the advisory.
