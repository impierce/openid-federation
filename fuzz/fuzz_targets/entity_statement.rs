//! Entity Statements as JSON (Entity Statement section): arbitrary bytes deserialize into an
//! `EntityConfiguration`, a `SubordinateStatement` or an `EntityMetadata` without panicking,
//! `validate` and `SubordinateStatement::builder` never panic on what parses, and whatever parses
//! serializes back to a value that parses to the same statement.
#![no_main]

use libfuzzer_sys::fuzz_target;
use openid_federation::{EntityConfiguration, EntityId, EntityMetadata, EntityType, SubordinateStatement};

fn roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("a parsed statement serializes");
    let again: T = serde_json::from_str(&json).expect("a serialized statement parses");
    assert_eq!(&again, value);
    again
}

fuzz_target!(|data: &[u8]| {
    if let Ok(configuration) = serde_json::from_slice::<EntityConfiguration>(data) {
        let _ = configuration.validate();
        let subject = EntityId::parse("https://subject.example").expect("a fixed Entity Identifier parses");
        // A Superior issuing a statement about the configuration's entity, carrying its claims
        // through the builder's producer checks.
        let mut builder = SubordinateStatement::builder(subject, configuration.claims.sub.clone(), configuration.jwks.clone())
            .issued_at(configuration.claims.iat)
            .expires_at(configuration.claims.exp);
        for (name, value) in &configuration.claims.additional {
            builder = builder.extension_claim(name.clone(), value.clone());
        }
        if let Some(crit) = &configuration.crit {
            builder = builder.crit(crit.clone());
        }
        let _ = builder.build();
        roundtrip(&configuration);
    }
    if let Ok(statement) = serde_json::from_slice::<SubordinateStatement>(data) {
        let _ = statement.validate();
        roundtrip(&statement);
    }
    if let Ok(metadata) = serde_json::from_slice::<EntityMetadata>(data) {
        for entity_type in [
            EntityType::FederationEntity,
            EntityType::OpenIdProvider,
            EntityType::OpenIdRelyingParty,
            EntityType::OauthAuthorizationServer,
            EntityType::OauthResource,
            EntityType::OauthClient,
        ] {
            let _ = metadata.has_entity_type(&entity_type);
        }
        // Every extension member is an additional Entity Type the metadata has.
        for identifier in metadata.extensions.keys() {
            assert!(metadata.has_entity_type(&EntityType::Other(identifier.clone())));
        }
        roundtrip(&metadata);
    }
});
