//! # OpenID Federation
//!
//! A Rust implementation of the OpenID Federation 1.0 standard.
//!
//! This library provides support for OpenID Federation, which allows
//! for the creation of trust relationships between OpenID Connect providers
//! and relying parties through a federation of trust anchors.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod entity;
pub mod error;
pub mod jwk;
pub mod jwt;
pub mod metadata;
pub mod trust_chain;
pub mod types;
pub mod utils;

pub use entity::*;
pub use error::*;
pub use jwk::{Jwk, JwkSet};
pub use jwt::*;
pub use metadata::*;
pub use trust_chain::*;
pub use types::*;
pub use utils::*;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use url::Url;

    #[test]
    fn test_entity_configuration_creation() {
        let entity_id = Url::parse("https://example.com").unwrap();
        let jwks = JwkSet::new();
        let exp = Utc::now() + Duration::hours(24);
        let iat = Utc::now();

        let config = EntityConfiguration::new(entity_id.clone(), jwks, exp, iat);

        assert_eq!(config.claims.iss, entity_id);
        assert_eq!(config.claims.sub, entity_id);
        assert!(config.is_self_signed());
    }

    #[test]
    fn test_entity_statement_creation() {
        let issuer = Url::parse("https://issuer.example.com").unwrap();
        let subject = Url::parse("https://subject.example.com").unwrap();
        let exp = Utc::now() + Duration::hours(1);
        let iat = Utc::now();

        let statement = EntityStatement::new(issuer.clone(), subject.clone(), exp, iat);

        assert_eq!(statement.claims.iss, issuer);
        assert_eq!(statement.claims.sub, subject);
        assert!(!statement.is_self_signed());
    }

    #[test]
    fn test_trust_chain_creation() {
        let chain = TrustChain::new(vec![
            "jwt1".to_string(),
            "jwt2".to_string(),
            "jwt3".to_string(),
        ]);

        assert_eq!(chain.len(), 3);
        assert!(!chain.is_empty());
    }

    #[test]
    fn test_jwk_creation() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            alg: Some("RS256".to_string()),
            kid: Some("key1".to_string()),
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            n: Some("test_modulus".to_string()),
            e: Some("AQAB".to_string()),
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            crv: None,
            x: None,
            y: None,
            k: None,
        };

        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.kid, Some("key1".to_string()));
    }

    #[test]
    fn test_jwk_set_operations() {
        let mut jwks = JwkSet::new();
        
        let jwk = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            alg: Some("RS256".to_string()),
            kid: Some("key1".to_string()),
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            n: Some("test_modulus".to_string()),
            e: Some("AQAB".to_string()),
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            crv: None,
            x: None,
            y: None,
            k: None,
        };

        jwks.add_key(jwk);
        assert_eq!(jwks.keys.len(), 1);

        let found_key = jwks.find_key("key1");
        assert!(found_key.is_some());
        assert_eq!(found_key.unwrap().kid, Some("key1".to_string()));

        let not_found = jwks.find_key("nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_metadata_entity_type_check() {
        let mut metadata = EntityMetadata::new();
        
        // Initially no entity types
        assert!(!metadata.has_entity_type(&EntityType::FederationEntity));
        assert!(!metadata.has_entity_type(&EntityType::OpenkConnectProvider));
        
        // Add federation entity metadata
        metadata.federation_entity = Some(FederationEntityMetadata {
            organization_name: Some("Test Organization".to_string()),
            homepage_uri: None,
            policy_uri: None,
            logo_uri: None,
            contacts: None,
            federation_fetch_endpoint: None,
            federation_list_endpoint: None,
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });
        
        assert!(metadata.has_entity_type(&EntityType::FederationEntity));
        assert!(!metadata.has_entity_type(&EntityType::OpenkConnectProvider));
    }

    #[test]
    fn test_url_validation() {
        let valid_https_url = Url::parse("https://example.com").unwrap();
        let http_url = Url::parse("http://example.com").unwrap();
        let url_with_fragment = Url::parse("https://example.com#fragment").unwrap();

        // Valid HTTPS URL should pass
        assert!(UrlValidator::validate_entity_id(&valid_https_url).is_ok());
        
        // HTTP URL should fail
        assert!(UrlValidator::validate_entity_id(&http_url).is_err());
        
        // URL with fragment should fail
        assert!(UrlValidator::validate_entity_id(&url_with_fragment).is_err());
    }

    #[test]
    fn test_time_utilities() {
        use crate::utils::time;

        let now = time::now();
        let future = time::expires_in(Duration::hours(1));
        let past = time::issued_ago(Duration::hours(1));

        assert!(future > now);
        assert!(past < now);
        assert!(!time::is_expired(future));
        assert!(time::is_expired(past));
        assert!(time::is_not_yet_valid(future));
        assert!(!time::is_not_yet_valid(past));
    }
}
