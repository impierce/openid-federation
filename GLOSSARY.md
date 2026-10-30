# OpenID Federation

The language of this crate: the terms of [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html), spelled and capitalised as the specification spells them, plus the few terms this crate adds. Code, issues, tests and docs use these names.

## Language

### Entities

**Federation**:
A set of Entities that trust each other through Trust Chains ending at a common Trust Anchor.
_Avoid_: Ecosystem (a broader product term that also covers non-federation data), network, trust domain

**Federation Operator**:
The organisation that runs a federation's Trust Anchor and decides who belongs to it.
_Avoid_: Federation owner, admin

**Entity**:
A participant in a federation, identified by its Entity Identifier and represented by its Entity Configuration.
_Avoid_: Party, node, member

**Entity Identifier**:
The `https` URL that identifies an Entity; it may carry a path, and its spelling is kept as published (ADR 0004).
_Avoid_: Entity ID in prose (fine as `EntityId` in code), issuer URL, DID

**Entity Type**:
A role an Entity plays, named by an Entity Type Identifier such as `openid_provider` and declared as a member of its `metadata`.
_Avoid_: Role, kind

**Federation Entity**:
An Entity with the `federation_entity` Entity Type, which carries its federation endpoints and informational metadata.

**Superior**:
An Entity that issues a Subordinate Statement about another Entity; the **Immediate Superior** is the one directly above.
_Avoid_: Parent, authority (except in the `authority_hints` claim)

**Subordinate**:
An Entity that a Superior issues a Subordinate Statement about; the **Immediate Subordinate** is the one directly below.
_Avoid_: Child, member

**Trust Anchor**:
An Entity whose Entity Configuration ends Trust Chains and whose keys the relying side trusts; it may itself have Superiors in another federation (Section 4.1).
_Avoid_: Root, root of trust (except for its keys), CA

**Intermediate Entity**:
An Entity between a Trust Anchor and other Entities, issuing Subordinate Statements about its Immediate Subordinates.
_Avoid_: Sub-anchor, intermediary

**Leaf Entity**:
An Entity with no Subordinates, typically playing a protocol role such as OpenID Provider or Relying Party.
_Avoid_: End entity

**Resolver**:
An Entity that resolves Trust Chains and metadata for others through its resolve endpoint; ideally the Trust Anchor (Section 17.3).

### Statements and chains

**Entity Statement**:
A signed JWT typed `entity-statement+jwt` that an issuer makes about a subject; either an Entity Configuration or a Subordinate Statement.
_Avoid_: Statement token, federation JWT

**Entity Configuration**:
The Entity Statement an Entity makes about itself (`iss` equals `sub`), published at `/.well-known/openid-federation`.
_Avoid_: Self-statement, well-known document

**Subordinate Statement**:
The Entity Statement a Superior makes about an Immediate Subordinate, carrying the keys it endorses and, optionally, metadata, metadata policy and constraints.
_Avoid_: Entity Statement when this kind is meant, SS

**Federation Entity Keys**:
The keys in an Entity Statement's `jwks`, used only to sign federation artifacts, never for other protocols.
_Avoid_: Signing keys without qualification, protocol keys

**Trust Chain**:
The ordered Entity Statements from a subject's Entity Configuration, through one Subordinate Statement per Superior, to a Trust Anchor's Entity Configuration.
_Avoid_: Chain of trust, certificate chain

**Trust Chain subject**:
The Entity whose Entity Configuration begins a Trust Chain; usually, but not always, a Leaf Entity.
_Avoid_: Leaf when the subject is not one

**Endorsed keys**:
The Federation Entity Keys a Superior's Subordinate Statement vouches for, which authenticate the next statement down the Trust Chain.
_Avoid_: Trusted keys, verified keys

**Discovery**:
Fetching Entity Statements along `authority_hints` to assemble Trust Chains: **anchored discovery** stops at given Trust Anchors, **all-chains discovery** follows every branch and reports the ones it skips.
_Avoid_: Crawling, resolution (which also covers applying policies)

### Metadata and policy

**Metadata**:
The `metadata` claim: per Entity Type, the parameters an Entity declares or a Superior supplies.

**Metadata Policy**:
Rules from Superiors, made of operators such as `value`, `subset_of` and `essential`, that check or modify a subordinate's metadata per Entity Type and parameter.
_Avoid_: Policy alone when constraints are meant

**Resolved Metadata**:
A Trust Chain subject's metadata after its Immediate Superior's metadata, the Entity Type constraints and the merged Metadata Policy are applied.
_Avoid_: Effective metadata, final metadata

**Constraints**:
Limits a Superior places on the Trust Chains below it: `max_path_length`, `naming_constraints` and `allowed_entity_types`.
_Avoid_: Restrictions, policy

### Trust Marks

**Trust Mark**:
A signed JWT typed `trust-mark+jwt` in which a Trust Mark Issuer states that an Entity conforms to criteria of a given Trust Mark type.
_Avoid_: Badge, certificate, accreditation

**Trust Mark Issuer**:
An Entity that signs Trust Marks; the Trust Anchor's `trust_mark_issuers` says which issuers the federation accepts for which type.

**Trust Mark Owner**:
The Entity that owns a Trust Mark type and delegates issuance of it, listed in the Trust Anchor's `trust_mark_owners`.

**Trust Mark delegation**:
A signed JWT typed `trust-mark-delegation+jwt` by which a Trust Mark Owner authorises a Trust Mark Issuer for a type.

### This crate

**Relying side**:
The part of the crate that discovers, authenticates and evaluates Trust Chains and Trust Marks for an Entity that consumes federation data.
_Avoid_: Client side when the resolver or a Trust Anchor's own checks are meant

**Issuing side**:
The part of the crate that a Trust Anchor or Intermediate Entity uses to sign Entity Statements and Trust Marks and serve the federation endpoints.
_Avoid_: Server side, admin side
