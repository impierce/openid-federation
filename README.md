# OpenID Federation

A Rust implementation of the OpenID Federation 1.0 standard.

This library provides comprehensive support for OpenID Federation, enabling the creation of trust relationships between OpenID Connect providers and relying parties through a federation of trust anchors.

## Features

- **Subordinate Statements and Entity Configurations**: Create and validate federation subordinate statements and entity configurations
- **Trust Chain Management**: Build and validate trust chains for federation entities
- **JWT Processing**: Sign and verify JWTs with federation-specific extensions
- **Metadata Handling**: Support for all entity types (Federation Entity, OpenID Provider, Relying Party, etc.)
- **Policy Operators**: Implementation of federation metadata policy operators
- **HTTP Client**: Built-in client for fetching entity configurations and statements
- **Comprehensive Validation**: Full validation of subordinate statements, entity configurations, trust chains, and metadata

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
openid-federation = "0.1.0"
```

### Basic Usage

```rust
use openid_federation::{
    EntityConfiguration, SubordinateStatement, JwkSet, FederationEntityMetadata,
    EntityMetadata, TrustChain
};
use chrono::{Duration, Utc};
use url::Url;

// Create an entity configuration
let entity_id = Url::parse("https://example.com")?;
let jwks = JwkSet::new();
let exp = Utc::now() + Duration::hours(24);
let iat = Utc::now();

let mut config = EntityConfiguration::new(entity_id, jwks, exp, iat);

// Add metadata
let mut metadata = EntityMetadata::new();
metadata.federation_entity = Some(FederationEntityMetadata {
    organization_name: Some("Example Organization".to_string()),
    homepage_uri: Some(Url::parse("https://example.com")?),
    ..Default::default()
});

config = config.with_metadata(metadata);

// Create and validate trust chains
let trust_chain = TrustChain::try_new(vec![
    "entity_config_jwt".to_string(),
    "intermediate_statement_jwt".to_string(), 
    "trust_anchor_config_jwt".to_string(),
]);

```

### HTTP Client Usage

```rust
use openid_federation::{FederationClient, UrlValidator};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = FederationClient::new();
    let entity_id = Url::parse("https://example.com")?;
    
    // Validate entity ID
    UrlValidator::validate_entity_id(&entity_id)?;
    
    // Fetch entity configuration
    let config_jwt = client.fetch_entity_configuration(&entity_id).await?;
    println!("Fetched entity configuration: {}", config_jwt);
    
    Ok(())
}
```

## Standards Compliance

This implementation follows the OpenID Federation 1.0 specification (draft 43) and includes:

- Subordinate Statement format and validation
- Entity Configuration format and validation  
- Trust Chain construction and validation
- Federation metadata policy operators
- Well-known endpoint discovery
- Federation-specific JWT claims and headers
- Comprehensive error handling

## Entity Types Supported

- **Federation Entity**: Core federation infrastructure
- **OpenID Connect Provider**: Identity providers in the federation
- **OpenID Connect Relying Party**: Clients in the federation
- **OAuth Authorization Server**: OAuth 2.0 authorization servers
- **OAuth Protected Resource**: Resource servers
- **OAuth Client**: OAuth 2.0 clients

## Architecture

The library is organized into several key modules:

- `entity`: Subordinate Statement and Entity Configuration structures
- `trust_chain`: Trust chain validation and processing
- `metadata`: All metadata types for different entity kinds
- `jwk`: JSON Web Key and JWK Set utilities
- `jwt`: JWT processing with federation extensions
- `types`: Common types and enums
- `utils`: Utility functions for HTTP, validation, and time handling
- `error`: Comprehensive error types

## License

Licensed under the Apache License, Version 2.0.
