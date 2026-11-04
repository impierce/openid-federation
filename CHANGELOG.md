# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/impierce/openid-federation/compare/v0.3.0...v0.4.0) - 2026-11-04

### Added

- *(metadata)* [**breaking**] preserve unknown parameters and issuer spelling ([#88](https://github.com/impierce/openid-federation/pull/88))
- *(policy)* apply resolved metadata policy ([#86](https://github.com/impierce/openid-federation/pull/86))
- *(policy)* merge metadata policies of a Trust Chain ([#85](https://github.com/impierce/openid-federation/pull/85))
- *(trust_marks)* verify Trust Marks and Trust Mark delegations ([#84](https://github.com/impierce/openid-federation/pull/84))
- *(onboarding)* check a candidate subordinate before registering it ([#79](https://github.com/impierce/openid-federation/pull/79))
- *(endpoint)* list Trust Marked Entities, serve Trust Marks ([#82](https://github.com/impierce/openid-federation/pull/82))
- *(endpoint)* report Trust Mark status with `TrustMarkStatusEndpoint` ([#80](https://github.com/impierce/openid-federation/pull/80))
- *(types)* [**breaking**] issue Trust Marks and Trust Mark delegations ([#78](https://github.com/impierce/openid-federation/pull/78))
- *(endpoint)* publish historical keys with `HistoricalKeysEndpoint` ([#77](https://github.com/impierce/openid-federation/pull/77))
- *(keys)* roll over Federation Entity Keys with `FederationKeys` ([#76](https://github.com/impierce/openid-federation/pull/76))
- *(types)* [**breaking**] type naming constraints with `NamingConstraints` ([#74](https://github.com/impierce/openid-federation/pull/74))
- *(types)* [**breaking**] validate metadata policies and keep additional operators ([#75](https://github.com/impierce/openid-federation/pull/75))
- *(endpoint)* list Immediate Subordinates with `ListEndpoint` ([#73](https://github.com/impierce/openid-federation/pull/73))
- *(endpoint)* serve Subordinate Statements with `FetchEndpoint` over a `SubordinateStore` ([#72](https://github.com/impierce/openid-federation/pull/72))
- *(endpoint)* serve the Entity Configuration with `EntityConfigurationEndpoint` ([#71](https://github.com/impierce/openid-federation/pull/71))
- *(endpoint)* [**breaking**] serve and parse federation error responses ([#69](https://github.com/impierce/openid-federation/pull/69))
- *(entity)* issue Subordinate Statements with builder, deprecate `to_subordinate_statement` ([#70](https://github.com/impierce/openid-federation/pull/70))
- *(entity)* [**breaking**] check Trust Anchor and Intermediate Entity Configuration rules ([#68](https://github.com/impierce/openid-federation/pull/68))
- *(metadata)* [**breaking**] complete `federation_entity` metadata, check endpoints when signing ([#67](https://github.com/impierce/openid-federation/pull/67))
- *(entity)* sign Entity Statements with `typ` and `kid` ([#66](https://github.com/impierce/openid-federation/pull/66))
- *(jwt)* [**breaking**] sign through async `Signer` trait, add `InMemorySigner` ([#64](https://github.com/impierce/openid-federation/pull/64))
- *(jwk)* [**breaking**] validate publishable JWK Sets, add RFC 7638 thumbprints ([#63](https://github.com/impierce/openid-federation/pull/63))

### Fixed

- *(entity)* [**breaking**] check `iat`, `kid` and `crit` when verifying Entity Statements ([#83](https://github.com/impierce/openid-federation/pull/83))
- [**breaking**] leave crypto backend of `jsonwebtoken` to application ([#26](https://github.com/impierce/openid-federation/pull/26))

## [0.3.0](https://github.com/impierce/openid-federation/compare/v0.2.0...v0.3.0) - 2026-10-27

### Fixed

- [**breaking**] end discovered trust chains at Trust Anchors with Superiors ([#23](https://github.com/impierce/openid-federation/pull/23))
- [**breaking**] preserve spelling of Entity Identifiers, compare them as URLs ([#24](https://github.com/impierce/openid-federation/pull/24))

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
