# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/impierce/openid-federation/compare/v0.1.0...v0.2.0) - 2026-10-26

### Added

- report trust chain discovery failures ([#8](https://github.com/impierce/openid-federation/pull/8))
- bootstrap OpenID Federation 1.0 standard in Rust ([#2](https://github.com/impierce/openid-federation/pull/2))

### Documentation

- add agent instructions, design, feature checklist, ADRs and policies ([#11](https://github.com/impierce/openid-federation/pull/11))

### Fixed

- [**breaking**] spell Entity Type Identifiers according to the specification ([#19](https://github.com/impierce/openid-federation/pull/19))
- resolve entities with path identifiers, Trust Marks, or float dates ([#7](https://github.com/impierce/openid-federation/pull/7))
- authenticate signatures and identities during trust chain validation ([#6](https://github.com/impierce/openid-federation/pull/6))
- add missing informational metadata parameters ([#5](https://github.com/impierce/openid-federation/pull/5))

### Other

- *(deps)* [**breaking**] update all dependencies to latest versions ([#17](https://github.com/impierce/openid-federation/pull/17))
- improve and rename `EntityStatement` enum ([#4](https://github.com/impierce/openid-federation/pull/4))

## [0.1.0](https://github.com/impierce/openid-federation/releases/tag/v0.1.0) - 2025-10-02

### Added

- Initial release: Entity Configurations and Subordinate Statements, Trust Chain validation, entity metadata types, Trust Mark types, and a federation client for discovery
