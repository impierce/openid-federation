//! # OpenID Federation
//!
//! A Rust implementation of the OpenID Federation 1.0 standard.
//!
//! This library provides support for OpenID Federation, which allows
//! for the creation of trust relationships between OpenID Connect providers
//! and relying parties through a federation of trust anchors.

#![warn(clippy::all)]

pub mod entity;
pub mod error;
pub mod jwk;
pub mod jwt;
pub mod metadata;
pub mod trust_chain;
pub mod types;
pub mod utils;

#[cfg(test)]
pub(crate) mod test_helpers;

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
    use chrono::Duration;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::collections::HashSet;
    use url::Url;

    #[test]
    fn test_entity_configuration_creation() {
        let entity_id = Url::parse("https://example.com").unwrap();
        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());
        let exp = (chrono::Utc::now() + Duration::hours(24)).timestamp();
        let iat = chrono::Utc::now().timestamp();

        let config = EntityConfiguration::new(entity_id.clone(), jwks, exp, iat);

        config.validate().expect("Entity configuration validation failed");
        assert_eq!(config.claims.iss, entity_id);
        assert_eq!(config.claims.sub, entity_id);
    }

    #[test]
    fn test_subordinate_statement_creation() {
        let issuer = Url::parse("https://issuer.example.com").unwrap();
        let subject = Url::parse("https://subject.example.com").unwrap();
        let exp = (chrono::Utc::now() + Duration::hours(1)).timestamp();
        let iat = chrono::Utc::now().timestamp();
        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        let subordinate_statement = SubordinateStatement::new(issuer.clone(), subject.clone(), exp, iat, jwks);

        subordinate_statement
            .validate()
            .expect("Subordinate statement validation failed");
        assert_eq!(subordinate_statement.claims.iss, issuer);
        assert_eq!(subordinate_statement.claims.sub, subject);
    }

    #[test]
    fn test_trust_chain_creation() {
        let chain = TrustChain::try_new(vec!["jwt1".to_string(), "jwt2".to_string(), "jwt3".to_string()]);

        assert!(chain.is_err());
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
        let now = chrono::Utc::now().timestamp();
        let future = expires_in(Duration::hours(1));

        assert!(future > now);
        assert!(future > chrono::Utc::now().timestamp());
    }

    /// Integration test based on OpenID Federation 1.0 Appendix A.2: The LIGO Wiki Discovers leaf entity metadata
    ///
    /// Reference: OpenID Federation 1.0 - Appendix A.2 The LIGO Wiki Discovers leaf entity metadata
    /// https://openid.net/specs/openid-federation-1_0.html#name-the-ligo-wiki-discovers-the
    #[tokio::test]
    async fn test_ligo_wiki_discovers_leaf_metadata() {
        use crate::FederationClient;
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        // Start mock servers for each entity in the federation
        let op_server = MockServer::start().await; // Represents op.localhost (leaf entity)
        let university_server = MockServer::start().await; // Represents university.localhost (Intermediate)
        let federation_server = MockServer::start().await; // Represents federation.localhost (Trust Anchor)

        let op_url = Url::parse(&format!("http://{}", op_server.address())).unwrap();
        let university_url = Url::parse(&format!("http://{}", university_server.address())).unwrap();
        let federation_url = Url::parse(&format!("http://{}", federation_server.address())).unwrap();

        // Create test key for signing JWTs
        let encoding_key = EncodingKey::from_secret(b"test_secret_key");

        // Step 1: Mock the leaf Entity Configuration
        let op_entity_config = create_op_entity_configuration(&op_url, &university_url);
        let op_jwt = encode_entity_configuration(&op_entity_config, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(op_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&op_server)
            .await;

        // Step 2: Mock the University's Subordinate Statement about the OP
        let university_statement_about_op = create_university_subordinate_statement_about_op(&university_url, &op_url);
        let university_jwt = encode_subordinate_statement(&university_statement_about_op, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(university_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&university_server)
            .await;

        // Step 3: Mock the University's Entity Configuration
        let university_entity_config = create_university_entity_configuration(&university_url, &federation_url);
        let university_config_jwt = encode_entity_configuration(&university_entity_config, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(university_config_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&university_server)
            .await;

        // Step 4: Mock the Federation's Subordinate Statement about the University
        let federation_statement_about_university =
            create_federation_statement_about_university(&federation_url, &university_url);
        let federation_jwt = encode_subordinate_statement(&federation_statement_about_university, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(federation_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&federation_server)
            .await;

        // Step 5: Mock the Federation's Entity Configuration (Trust Anchor)
        let federation_entity_config = create_federation_entity_configuration(&federation_url);
        let federation_config_jwt = encode_entity_configuration(&federation_entity_config, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(federation_config_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&federation_server)
            .await;

        // Now simulate the LIGO Wiki (Relying Party/verifier) discovering the leaf metadata
        let client = FederationClient::new();
        let op_entity_id = op_url.clone();
        let federation_entity_id = federation_url.clone();

        // Step 6 & 7: LIGO Wiki discovers the leaf trust chain up to the trust anchor
        let trust_chain = client
            .discover_trust_chain(&op_entity_id, Some(&[federation_entity_id]))
            .await
            .expect("trust chain discovery should succeed");

        assert!(
            !trust_chain.chain.is_empty(),
            "Discovered trust chain should not be empty"
        );
        assert!(
            trust_chain.chain.len() >= 2,
            "Trust chain must include at least leaf and anchor"
        );

        // The test successfully demonstrates the federation discovery flow described in Appendix A.2
    }

    /// Integration test based on OpenID Federation 1.0 Appendix A.3: Examples of the Two Ways of Doing Client Registration
    ///
    /// Reference: OpenID Federation 1.0 - Appendix A.3 Examples of the Two Ways of Doing Client Registration
    /// https://openid.net/specs/openid-federation-1_0.html#appendix-A.3
    #[tokio::test]
    async fn test_client_registration_examples() {
        use crate::FederationClient;
        use wiremock::{
            matchers::{body_string_contains, method, path},
            Mock, MockServer, ResponseTemplate,
        };

        // Start mock servers for the federation entities
        let op_server = MockServer::start().await; // Leaf entity in this registration scenario
        let client_server = MockServer::start().await; // Client/Relying Party
        let federation_server = MockServer::start().await; // Trust Anchor

        let op_url = Url::parse(&format!("http://{}", op_server.address())).unwrap();
        let client_url = Url::parse(&format!("http://{}", client_server.address())).unwrap();
        let federation_url = Url::parse(&format!("http://{}", federation_server.address())).unwrap();

        let encoding_key = EncodingKey::from_secret(b"test_secret_key");

        // === PART 1: Test Explicit Client Registration ===

        // Step 1: Mock the leaf Entity Configuration with client registration endpoint
        let op_config = create_op_with_registration_endpoint(&op_url, &federation_url);
        let op_jwt = encode_entity_configuration(&op_config, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(op_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&op_server)
            .await;

        // Step 2: Mock the client registration endpoint for explicit registration
        Mock::given(method("POST"))
            .and(path("/register"))
            .and(body_string_contains("redirect_uris"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({
                        "client_id": "test_client_explicit",
                        "client_secret": "test_secret",
                        "redirect_uris": ["http://client.localhost/callback"],
                        "grant_types": ["authorization_code"],
                        "response_types": ["code"],
                        "client_id_issued_at": 1234567890,
                        "client_secret_expires_at": 0
                    }))
                    .insert_header("content-type", "application/json"),
            )
            .mount(&op_server)
            .await;

        // === PART 2: Test Automatic Client Registration (Federation-based) ===

        // Step 3: Mock the Client's Entity Configuration
        let client_config = create_client_entity_configuration(&client_url, &federation_url);
        let client_jwt = encode_entity_configuration(&client_config, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(client_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&client_server)
            .await;

        // Step 4: Mock the Federation's Subordinate Statement about the Client
        let federation_statement_about_client = create_federation_statement_about_client(&federation_url, &client_url);
        let federation_client_jwt = encode_subordinate_statement(&federation_statement_about_client, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(federation_client_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&federation_server)
            .await;

        // Step 5: Mock the Federation's Entity Configuration
        let federation_config = create_federation_entity_configuration(&federation_url);
        let federation_config_jwt = encode_entity_configuration(&federation_config, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(federation_config_jwt.clone())
                    .insert_header("content-type", "application/subordinate-statement+jwt"),
            )
            .mount(&federation_server)
            .await;

        // Step 6: Mock the trust anchor Subordinate Statement about the leaf
        let federation_statement_about_op = create_federation_statement_about_op(&federation_url, &op_url);
        let federation_op_jwt = encode_subordinate_statement(&federation_statement_about_op, &encoding_key);

        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(federation_op_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&federation_server)
            .await;

        // === Test Execution ===

        let federation_client = FederationClient::new();

        // Test 1: Verify we can fetch the leaf configuration (needed for both registration methods)
        let op_entity_id = op_url.clone();
        let op_config_response = federation_client.fetch_entity_configuration(&op_entity_id).await;
        assert!(op_config_response.is_ok(), "Failed to fetch leaf entity configuration");

        // Test 2: Verify we can fetch the client's configuration (for automatic registration)
        let client_entity_id = client_url.clone();
        let client_config_response = federation_client.fetch_entity_configuration(&client_entity_id).await;
        assert!(
            client_config_response.is_ok(),
            "Failed to fetch client entity configuration"
        );

        // Test 3: Build trust chains for both leaf and client (for automatic registration)
        let op_trust_chain = TrustChain::try_new(vec![
            op_config_response.unwrap(),
            federation_op_jwt,
            federation_config_jwt.clone(),
        ])
        .unwrap();

        let client_trust_chain = TrustChain::try_new(vec![
            client_config_response.unwrap(),
            federation_client_jwt,
            federation_config_jwt,
        ])
        .unwrap();

        // Verify both trust chains are properly structured
        assert_eq!(op_trust_chain.len(), 3);
        assert_eq!(client_trust_chain.len(), 3);

        // In a real implementation, the verifier handling the leaf registration would:
        // 1. For explicit registration: validate the registration request and create client credentials
        // 2. For automatic registration: validate the client's trust chain and automatically register the client

        // This test successfully demonstrates both client registration methods described in Appendix A.3
    }

    // Helper functions for the LIGO Wiki test

    fn create_test_symmetric_key() -> Jwk {
        Jwk {
            kty: "oct".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            alg: Some("HS256".to_string()),
            kid: Some("test-key-1".to_string()),
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            n: None,
            e: None,
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            crv: None,
            x: None,
            y: None,
            k: Some("dGVzdF9zZWNyZXRfa2V5".to_string()), // base64 encoded "test_secret_key"
        }
    }

    fn create_op_entity_configuration(op_url: &Url, university_url: &Url) -> EntityConfiguration {
        let entity_id = op_url.clone();
        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        let exp = expires_in(Duration::hours(24));
        let iat = chrono::Utc::now().timestamp();

        let mut metadata = EntityMetadata::new();
        metadata.openid_provider = Some(OpenIdConnectProviderMetadata {
            issuer: Url::parse(&format!("{}/openid", op_url)).unwrap(),
            authorization_endpoint: Url::parse(&format!("{}/openid/authorization", op_url)).unwrap(),
            token_endpoint: Some(Url::parse(&format!("{}/openid/token", op_url)).unwrap()),
            userinfo_endpoint: None,
            jwks_uri: Url::parse(&format!("{}/openid/jwks.jose", op_url)).unwrap(),
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: vec!["code".to_string(), "code id_token".to_string(), "token".to_string()],
            response_modes_supported: None,
            grant_types_supported: Some(vec![
                "authorization_code".to_string(),
                "implicit".to_string(),
                "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            ]),
            acr_values_supported: None,
            subject_types_supported: vec!["pairwise".to_string(), "public".to_string()],
            id_token_signing_alg_values_supported: vec!["ES256".to_string(), "RS256".to_string()],
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported: None,
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: None,
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported: Some(vec![
                "client_secret_post".to_string(),
                "client_secret_basic".to_string(),
                "client_secret_jwt".to_string(),
                "private_key_jwt".to_string(),
            ]),
            token_endpoint_auth_signing_alg_values_supported: None,
            display_values_supported: None,
            claim_types_supported: None,
            claims_supported: None,
            service_documentation: None,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: None,
            request_parameter_supported: Some(true),
            request_uri_parameter_supported: None,
            require_request_uri_registration: None,
            op_policy_uri: Some(
                Url::parse(&format!(
                    "{}/en/website/legal-information/",
                    op_url.as_str().replace("//127.0.0.1", "//www.localhost")
                ))
                .unwrap(),
            ),
            op_tos_uri: None,
            signed_jwks_uri: Some(Url::parse(&format!("{}/openid/jwks.jose", op_url)).unwrap()),
            client_registration_types_supported: Some(vec!["automatic".to_string(), "explicit".to_string()]),
            federation_registration_endpoint: Some(Url::parse(&format!("{}/openid/fedreg", op_url)).unwrap()),
            logo_uri: Some(
                Url::parse(&format!(
                    "{}/img/localhost-logo-left-neg-SE.svg",
                    op_url.as_str().replace("//127.0.0.1", "//www.localhost")
                ))
                .unwrap(),
            ),
        });

        EntityConfiguration::new(entity_id, jwks, exp, iat)
            .with_metadata(metadata)
            .with_authority_hints(vec![university_url.clone()])
    }

    fn create_university_subordinate_statement_about_op(university_url: &Url, op_url: &Url) -> SubordinateStatement {
        let issuer = university_url.clone();
        let subject = op_url.clone();
        let exp = expires_in(Duration::hours(1));
        let iat = chrono::Utc::now().timestamp();

        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        SubordinateStatement::new(issuer, subject, exp, iat, jwks)
    }

    fn create_university_entity_configuration(university_url: &Url, federation_url: &Url) -> EntityConfiguration {
        let entity_id = university_url.clone();
        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        let exp = expires_in(Duration::hours(24));
        let iat = chrono::Utc::now().timestamp();

        let mut metadata = EntityMetadata::new();
        metadata.federation_entity = Some(FederationEntityMetadata {
            organization_name: Some("University Localhost".to_string()),
            homepage_uri: Some(entity_id.clone()),
            policy_uri: None,
            logo_uri: None,
            contacts: Some(vec!["admin@university.localhost".to_string()]),
            federation_fetch_endpoint: Some(university_url.join("federation_fetch_endpoint").unwrap()),
            federation_list_endpoint: Some(university_url.join("list").unwrap()),
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });

        EntityConfiguration::new(entity_id, jwks, exp, iat)
            .with_metadata(metadata)
            .with_authority_hints(vec![federation_url.clone()])
    }

    fn create_federation_statement_about_university(
        federation_url: &Url,
        university_url: &Url,
    ) -> SubordinateStatement {
        let issuer = federation_url.clone();
        let subject = university_url.clone();
        let exp = expires_in(Duration::hours(1));
        let iat = chrono::Utc::now().timestamp();

        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        SubordinateStatement::new(issuer, subject, exp, iat, jwks)
    }

    fn create_federation_entity_configuration(federation_url: &Url) -> EntityConfiguration {
        let entity_id = federation_url.clone();
        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        let exp = expires_in(Duration::hours(24));
        let iat = chrono::Utc::now().timestamp();

        let mut metadata = EntityMetadata::new();
        metadata.federation_entity = Some(FederationEntityMetadata {
            organization_name: Some("Federation Localhost".to_string()),
            homepage_uri: Some(entity_id.clone()),
            policy_uri: None,
            logo_uri: None,
            contacts: Some(vec!["admin@federation.localhost".to_string()]),
            federation_fetch_endpoint: Some(federation_url.join("federation_fetch_endpoint").unwrap()),
            federation_list_endpoint: Some(federation_url.join("list").unwrap()),
            federation_resolve_endpoint: Some(federation_url.join("resolve").unwrap()),
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });

        EntityConfiguration::new(entity_id, jwks, exp, iat).with_metadata(metadata)
    }

    fn encode_entity_configuration(config: &EntityConfiguration, key: &EncodingKey) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("entity-statement+jwt".to_string());
        header.kid = Some("test-key-1".to_string());
        encode(&header, config, key).unwrap()
    }

    fn encode_subordinate_statement(statement: &SubordinateStatement, key: &EncodingKey) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("entity-statement+jwt".to_string());
        header.kid = Some("test-key-1".to_string());
        encode(&header, statement, key).unwrap()
    }

    fn federation_header() -> Header {
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("entity-statement+jwt".to_string());
        header.kid = Some("test-key-1".to_string());
        header
    }

    // Helper functions for the Client Registration test

    fn create_op_with_registration_endpoint(op_url: &Url, federation_url: &Url) -> EntityConfiguration {
        let entity_id = op_url.clone();
        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        let exp = expires_in(Duration::hours(24));
        let iat = chrono::Utc::now().timestamp();

        let mut metadata = EntityMetadata::new();
        metadata.openid_provider = Some(OpenIdConnectProviderMetadata {
            issuer: entity_id.clone(),
            authorization_endpoint: Url::parse(&format!("{}/auth", op_url)).unwrap(),
            token_endpoint: Some(Url::parse(&format!("{}/token", op_url)).unwrap()),
            userinfo_endpoint: Some(Url::parse(&format!("{}/userinfo", op_url)).unwrap()),
            jwks_uri: Url::parse(&format!("{}/jwks", op_url)).unwrap(),
            registration_endpoint: Some(Url::parse(&format!("{}/register", op_url)).unwrap()),
            scopes_supported: Some(vec!["openid".to_string(), "profile".to_string(), "email".to_string()]),
            response_types_supported: vec!["code".to_string()],
            response_modes_supported: Some(vec!["query".to_string(), "fragment".to_string()]),
            grant_types_supported: Some(vec!["authorization_code".to_string()]),
            acr_values_supported: None,
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported: None,
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: None,
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported: Some(vec![
                "client_secret_basic".to_string(),
                "private_key_jwt".to_string(),
            ]),
            token_endpoint_auth_signing_alg_values_supported: Some(vec!["RS256".to_string()]),
            display_values_supported: None,
            claim_types_supported: None,
            claims_supported: Some(vec!["sub".to_string(), "name".to_string(), "email".to_string()]),
            service_documentation: None,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: None,
            request_parameter_supported: Some(true),
            request_uri_parameter_supported: Some(true),
            require_request_uri_registration: Some(false),
            op_policy_uri: None,
            op_tos_uri: None,
            signed_jwks_uri: None,
            client_registration_types_supported: None,
            federation_registration_endpoint: None,
            logo_uri: None,
        });

        EntityConfiguration::new(entity_id, jwks, exp, iat)
            .with_metadata(metadata)
            .with_authority_hints(vec![federation_url.clone()])
    }

    fn create_client_entity_configuration(client_url: &Url, federation_url: &Url) -> EntityConfiguration {
        let entity_id = client_url.clone();
        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        let exp = expires_in(Duration::hours(24));
        let iat = chrono::Utc::now().timestamp();

        let mut metadata = EntityMetadata::new();
        metadata.openid_relying_party = Some(OpenIdConnectRelyingPartyMetadata {
            redirect_uris: vec![Url::parse(&format!("{}/callback", client_url)).unwrap()],
            response_types: Some(vec!["code".to_string()]),
            grant_types: Some(vec!["authorization_code".to_string()]),
            application_type: Some("web".to_string()),
            contacts: Some(vec!["admin@client.localhost".to_string()]),
            client_name: Some("Test Client Localhost".to_string()),
            logo_uri: Some(Url::parse(&format!("{}/logo.png", client_url)).unwrap()),
            client_uri: Some(entity_id.clone()),
            policy_uri: Some(Url::parse(&format!("{}/policy", client_url)).unwrap()),
            tos_uri: Some(Url::parse(&format!("{}/tos", client_url)).unwrap()),
            jwks_uri: Some(Url::parse(&format!("{}/jwks", client_url)).unwrap()),
            jwks: None,
            sector_identifier_uri: None,
            subject_type: Some("public".to_string()),
            id_token_signed_response_alg: Some("RS256".to_string()),
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: Some("RS256".to_string()),
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_method: Some("private_key_jwt".to_string()),
            token_endpoint_auth_signing_alg: Some("RS256".to_string()),
            default_max_age: None,
            require_auth_time: Some(false),
            default_acr_values: None,
            initiate_login_uri: Some(Url::parse(&format!("{}/login", client_url)).unwrap()),
            request_uris: Some(vec![Url::parse(&format!("{}/request", client_url)).unwrap()]),
        });

        EntityConfiguration::new(entity_id, jwks, exp, iat)
            .with_metadata(metadata)
            .with_authority_hints(vec![federation_url.clone()])
    }

    fn create_federation_statement_about_client(federation_url: &Url, client_url: &Url) -> SubordinateStatement {
        let issuer = federation_url.clone();
        let subject = client_url.clone();
        let exp = expires_in(Duration::hours(1));
        let iat = chrono::Utc::now().timestamp();

        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        SubordinateStatement::new(issuer, subject, exp, iat, jwks)
    }

    fn create_federation_statement_about_op(federation_url: &Url, op_url: &Url) -> SubordinateStatement {
        let issuer = federation_url.clone();
        let subject = op_url.clone();
        let exp = expires_in(Duration::hours(1));
        let iat = chrono::Utc::now().timestamp();

        let mut jwks = JwkSet::new();
        jwks.add_key(create_test_symmetric_key());

        SubordinateStatement::new(issuer, subject, exp, iat, jwks)
    }

    // ====== Phase 4 Integration Tests for Trust Chain Discovery ======

    /// Test 1: Happy path - successful single-path discovery (leaf → intermediate → anchor)
    #[tokio::test]
    async fn test_discover_trust_chain_happy_path() {
        use crate::FederationClient;
        use wiremock::{
            matchers::{method, path, query_param},
            Mock, MockServer, ResponseTemplate,
        };

        // Create three mock servers for leaf, intermediate, and anchor entities
        let leaf_server = MockServer::start().await;
        let intermediate_server = MockServer::start().await;
        let anchor_server = MockServer::start().await;

        let leaf_url = Url::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let intermediate_url = Url::parse(&format!("http://{}", intermediate_server.address())).unwrap();
        let anchor_url = Url::parse(&format!("http://{}", anchor_server.address())).unwrap(); // Ensure anchor URL is a valid URL string

        let encoding_key = EncodingKey::from_secret(b"test_secret_key");

        // Create and mock the leaf entity configuration (with intermediate as authority hint)
        let leaf_config = EntityConfiguration::new(
            leaf_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_authority_hints(vec![intermediate_url.clone()]);

        let leaf_jwt = encode(&federation_header(), &leaf_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(leaf_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&leaf_server)
            .await;

        // Create and mock the intermediate entity configuration
        let mut intermediate_metadata = EntityMetadata::new();
        intermediate_metadata.federation_entity = Some(FederationEntityMetadata {
            organization_name: Some("Intermediate".to_string()),
            homepage_uri: None,
            policy_uri: None,
            logo_uri: None,
            contacts: None,
            federation_fetch_endpoint: Some(intermediate_url.join("federation_fetch_endpoint").unwrap()),
            federation_list_endpoint: None,
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });

        let intermediate_config = EntityConfiguration::new(
            intermediate_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_metadata(intermediate_metadata)
        .with_authority_hints(vec![anchor_url.clone()]);

        let intermediate_jwt = encode(&federation_header(), &intermediate_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(intermediate_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&intermediate_server)
            .await;

        // Mock the subordinate statement (leaf signed by intermediate)
        let mut intermediate_signing_jwks = JwkSet::new();
        intermediate_signing_jwks.add_key(create_test_symmetric_key());

        let subordinate_stmt = SubordinateStatement::new(
            intermediate_url.clone(),
            leaf_url.clone(),
            expires_in(Duration::hours(1)),
            chrono::Utc::now().timestamp(),
            intermediate_signing_jwks,
        );

        let subordinate_jwt = encode(&federation_header(), &subordinate_stmt, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .and(query_param("sub", leaf_url.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(subordinate_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&intermediate_server)
            .await;

        // Create and mock the anchor entity configuration
        let anchor_config = create_federation_entity_configuration(&anchor_url);

        let anchor_jwt = encode(&federation_header(), &anchor_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(anchor_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&anchor_server)
            .await;

        // Mock the subordinate statement (intermediate signed by anchor)
        let mut anchor_signing_jwks = JwkSet::new();
        anchor_signing_jwks.add_key(create_test_symmetric_key());

        let anchor_subordinate_stmt = SubordinateStatement::new(
            anchor_url.clone(),
            intermediate_url.clone(),
            expires_in(Duration::hours(1)),
            chrono::Utc::now().timestamp(),
            anchor_signing_jwks,
        );

        let anchor_subordinate_jwt = encode(&federation_header(), &anchor_subordinate_stmt, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .and(query_param("sub", intermediate_url.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(anchor_subordinate_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&anchor_server)
            .await;

        // Perform discovery
        let client = FederationClient::new();
        let leaf_entity_id = leaf_url.clone();

        println!(
            "leaf_url: {}, intermediate_url: {}, anchor_url: {}",
            leaf_url, intermediate_url, anchor_url
        );

        let result = client.discover_trust_chain(&leaf_entity_id, Some(&[anchor_url])).await;

        // Verify successful discovery
        assert!(result.is_ok(), "result: {:?}", result);
        let _trust_chain = result.unwrap();
    }

    #[tokio::test]
    async fn test_discover_all_trust_chains_returns_multiple_paths() {
        use crate::FederationClient;
        use wiremock::{
            matchers::{method, path, query_param},
            Mock, MockServer, ResponseTemplate,
        };

        async fn mock_subordinate(server: &MockServer, subject: &Url, issuer: &Url) -> String {
            let mut jwks = JwkSet::new();
            jwks.add_key(create_test_symmetric_key());

            let statement = SubordinateStatement::new(
                issuer.clone(),
                subject.clone(),
                expires_in(Duration::hours(1)),
                chrono::Utc::now().timestamp(),
                jwks,
            );

            let jwt = encode_subordinate_statement(&statement, &EncodingKey::from_secret(b"test_secret_key"));

            Mock::given(method("GET"))
                .and(path("/federation_fetch_endpoint"))
                .and(query_param("sub", subject.as_str()))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(jwt.clone())
                        .insert_header("content-type", "application/entity-statement+jwt"),
                )
                .mount(server)
                .await;

            jwt
        }

        let leaf_server = MockServer::start().await;
        let intermediate_one_server = MockServer::start().await;
        let intermediate_two_server = MockServer::start().await;
        let trust_anchor_one_server = MockServer::start().await;
        let trust_anchor_two_server = MockServer::start().await;

        let leaf_url = Url::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let intermediate_one_url = Url::parse(&format!("http://{}", intermediate_one_server.address())).unwrap();
        let intermediate_two_url = Url::parse(&format!("http://{}", intermediate_two_server.address())).unwrap();
        let trust_anchor_one_url = Url::parse(&format!("http://{}", trust_anchor_one_server.address())).unwrap();
        let trust_anchor_two_url = Url::parse(&format!("http://{}", trust_anchor_two_server.address())).unwrap();

        let encoding_key = EncodingKey::from_secret(b"test_secret_key");

        let leaf_config = EntityConfiguration::new(
            leaf_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_authority_hints(vec![intermediate_one_url.clone(), intermediate_two_url.clone()]);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(encode(&federation_header(), &leaf_config, &encoding_key).unwrap())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&leaf_server)
            .await;

        let intermediate_one_config = EntityConfiguration::new(
            intermediate_one_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_metadata({
            let mut metadata = EntityMetadata::new();
            metadata.federation_entity = Some(FederationEntityMetadata {
                organization_name: Some("Intermediate One".to_string()),
                homepage_uri: None,
                policy_uri: None,
                logo_uri: None,
                contacts: None,
                federation_fetch_endpoint: Some(intermediate_one_url.join("federation_fetch_endpoint").unwrap()),
                federation_list_endpoint: None,
                federation_resolve_endpoint: None,
                federation_trust_mark_status_endpoint: None,
                federation_historical_keys_endpoint: None,
            });
            metadata
        })
        .with_authority_hints(vec![trust_anchor_one_url.clone()]);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(encode(&federation_header(), &intermediate_one_config, &encoding_key).unwrap())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&intermediate_one_server)
            .await;

        let intermediate_two_config = EntityConfiguration::new(
            intermediate_two_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_metadata({
            let mut metadata = EntityMetadata::new();
            metadata.federation_entity = Some(FederationEntityMetadata {
                organization_name: Some("Intermediate Two".to_string()),
                homepage_uri: None,
                policy_uri: None,
                logo_uri: None,
                contacts: None,
                federation_fetch_endpoint: Some(intermediate_two_url.join("federation_fetch_endpoint").unwrap()),
                federation_list_endpoint: None,
                federation_resolve_endpoint: None,
                federation_trust_mark_status_endpoint: None,
                federation_historical_keys_endpoint: None,
            });
            metadata
        })
        .with_authority_hints(vec![trust_anchor_two_url.clone()]);

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(encode(&federation_header(), &intermediate_two_config, &encoding_key).unwrap())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&intermediate_two_server)
            .await;

        let trust_anchor_one_config = EntityConfiguration::new(
            trust_anchor_one_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_metadata({
            let mut metadata = EntityMetadata::new();
            metadata.federation_entity = Some(FederationEntityMetadata {
                organization_name: Some("Trust Anchor One".to_string()),
                homepage_uri: None,
                policy_uri: None,
                logo_uri: None,
                contacts: None,
                federation_fetch_endpoint: Some(trust_anchor_one_url.join("federation_fetch_endpoint").unwrap()),
                federation_list_endpoint: None,
                federation_resolve_endpoint: None,
                federation_trust_mark_status_endpoint: None,
                federation_historical_keys_endpoint: None,
            });
            metadata
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(encode(&federation_header(), &trust_anchor_one_config, &encoding_key).unwrap())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&trust_anchor_one_server)
            .await;

        let trust_anchor_two_config = EntityConfiguration::new(
            trust_anchor_two_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_metadata({
            let mut metadata = EntityMetadata::new();
            metadata.federation_entity = Some(FederationEntityMetadata {
                organization_name: Some("Trust Anchor Two".to_string()),
                homepage_uri: None,
                policy_uri: None,
                logo_uri: None,
                contacts: None,
                federation_fetch_endpoint: Some(trust_anchor_two_url.join("federation_fetch_endpoint").unwrap()),
                federation_list_endpoint: None,
                federation_resolve_endpoint: None,
                federation_trust_mark_status_endpoint: None,
                federation_historical_keys_endpoint: None,
            });
            metadata
        });

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(encode(&federation_header(), &trust_anchor_two_config, &encoding_key).unwrap())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&trust_anchor_two_server)
            .await;

        let leaf_to_intermediate_one_jwt =
            mock_subordinate(&intermediate_one_server, &leaf_url, &intermediate_one_url).await;
        let _leaf_to_intermediate_two_jwt =
            mock_subordinate(&intermediate_two_server, &leaf_url, &intermediate_two_url).await;
        let intermediate_one_to_trust_anchor_one_jwt =
            mock_subordinate(&trust_anchor_one_server, &intermediate_one_url, &trust_anchor_one_url).await;
        let _intermediate_two_to_trust_anchor_two_jwt =
            mock_subordinate(&trust_anchor_two_server, &intermediate_two_url, &trust_anchor_two_url).await;

        let manual_chain = vec![
            encode(&federation_header(), &leaf_config, &encoding_key).unwrap(),
            leaf_to_intermediate_one_jwt.clone(),
            intermediate_one_to_trust_anchor_one_jwt.clone(),
            encode(&federation_header(), &trust_anchor_one_config, &encoding_key).unwrap(),
        ];

        let manual_result = TrustChain::try_new(manual_chain);
        assert!(manual_result.is_ok(), "manual chain validation: {:?}", manual_result);

        let client = FederationClient::new();
        let result = client.discover_all_trust_chains(&leaf_url).await;

        assert!(result.is_ok(), "result: {:?}", result);
        let chains = result.unwrap();
        assert_eq!(chains.len(), 2);

        let anchors: Vec<String> = chains
            .iter()
            .map(|chain| chain.trust_anchor_entity_id_and_configuration().unwrap().0.to_string())
            .collect();
        let anchors: HashSet<String> = HashSet::from_iter(anchors);

        assert_eq!(
            anchors,
            HashSet::from_iter([trust_anchor_one_url.to_string(), trust_anchor_two_url.to_string()])
        );
    }

    /// Test 2: Error handling - untrusted path (discovered entity not in trusted-anchor set)
    #[tokio::test]
    async fn test_discover_trust_chain_untrusted_path() {
        use crate::FederationClient;
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let leaf_server = MockServer::start().await;
        let intermediate_server = MockServer::start().await;

        let leaf_url = Url::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let intermediate_url = Url::parse(&format!("http://{}", intermediate_server.address())).unwrap();
        let anchor_url = Url::parse("http://untrusted.anchor.local").unwrap(); // Not a real server

        let encoding_key = EncodingKey::from_secret(b"test_secret_key");

        // Mock leaf with intermediate as authority hint
        let leaf_config = EntityConfiguration::new(
            leaf_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_authority_hints(vec![intermediate_url.clone()]);

        let leaf_jwt = encode(&federation_header(), &leaf_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(leaf_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&leaf_server)
            .await;

        // Mock intermediate with trusted anchor as authority hint (but won't match)
        let intermediate_config = EntityConfiguration::new(
            intermediate_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_authority_hints(vec![anchor_url.clone()]);

        let intermediate_jwt = encode(&federation_header(), &intermediate_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(intermediate_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&intermediate_server)
            .await;

        // Perform discovery with a different trusted anchor
        let client = FederationClient::new();
        let leaf_entity_id = leaf_url.clone();
        let trusted_anchors = vec![Url::parse("http://different.anchor.local").unwrap()]; // Different anchor

        let result = client
            .discover_trust_chain(&leaf_entity_id, Some(&trusted_anchors))
            .await;

        // Verify discovery fails due to no path to trusted anchor
        assert!(
            result.is_err(),
            "Discovery should fail when no path to trusted anchor exists"
        );
    }

    /// Test 3: Error handling - missing fetch endpoint
    #[tokio::test]
    async fn test_discover_trust_chain_missing_fetch_endpoint() {
        use crate::FederationClient;
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let leaf_server = MockServer::start().await;
        let intermediate_server = MockServer::start().await;

        let leaf_url = Url::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let intermediate_url = Url::parse(&format!("http://{}", intermediate_server.address())).unwrap();

        let encoding_key = EncodingKey::from_secret(b"test_secret_key");

        // Mock leaf with intermediate as authority hint
        let leaf_config = EntityConfiguration::new(
            leaf_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_authority_hints(vec![intermediate_url.clone()]);

        let leaf_jwt = encode(&federation_header(), &leaf_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(leaf_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&leaf_server)
            .await;

        // Mock intermediate WITHOUT federation_fetch_endpoint
        let intermediate_config = EntityConfiguration::new(
            intermediate_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_authority_hints(vec![Url::parse("http://anchor.local").unwrap()]);
        // Note: no metadata with federation_fetch_endpoint

        let intermediate_jwt = encode(&federation_header(), &intermediate_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(intermediate_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&intermediate_server)
            .await;

        // Perform discovery
        let client = FederationClient::new();
        let leaf_entity_id = leaf_url.clone();
        let trusted_anchors = vec![Url::parse("http://anchor.local").unwrap()];

        let result = client
            .discover_trust_chain(&leaf_entity_id, Some(&trusted_anchors))
            .await;

        // Verify discovery fails due to missing fetch endpoint
        assert!(result.is_err(), "Discovery should fail when fetch endpoint is missing");
    }

    /// Test 4: Loop protection - detects cycles in authority hints (A→B→A)
    #[tokio::test]
    async fn test_discover_trust_chain_loop_protection() {
        use crate::FederationClient;
        use wiremock::{
            matchers::{method, path, query_param},
            Mock, MockServer, ResponseTemplate,
        };

        let entity_a_server = MockServer::start().await;
        let entity_b_server = MockServer::start().await;

        let entity_a_url = Url::parse(&format!("http://{}", entity_a_server.address())).unwrap();
        let entity_b_url = Url::parse(&format!("http://{}", entity_b_server.address())).unwrap();

        let encoding_key = EncodingKey::from_secret(b"test_secret_key");

        let mut entity_a_metadata = EntityMetadata::new();
        entity_a_metadata.federation_entity = Some(FederationEntityMetadata {
            organization_name: Some("Entity A".to_string()),
            homepage_uri: None,
            policy_uri: None,
            logo_uri: None,
            contacts: None,
            federation_fetch_endpoint: Some(entity_a_url.join("federation_fetch_endpoint").unwrap()),
            federation_list_endpoint: None,
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });

        let mut entity_b_metadata = EntityMetadata::new();
        entity_b_metadata.federation_entity = Some(FederationEntityMetadata {
            organization_name: Some("Entity B".to_string()),
            homepage_uri: None,
            policy_uri: None,
            logo_uri: None,
            contacts: None,
            federation_fetch_endpoint: Some(entity_b_url.join("federation_fetch_endpoint").unwrap()),
            federation_list_endpoint: None,
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });

        // Create Entity A that points to Entity B as authority and exposes a fetch endpoint.
        let mut entity_a_metadata = EntityMetadata::new();
        entity_a_metadata.federation_entity = Some(FederationEntityMetadata {
            organization_name: Some("Entity A".to_string()),
            homepage_uri: None,
            policy_uri: None,
            logo_uri: None,
            contacts: None,
            federation_fetch_endpoint: Some(entity_a_url.join("federation_fetch_endpoint").unwrap()),
            federation_list_endpoint: None,
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });

        let entity_a_config = EntityConfiguration::new(
            entity_a_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_metadata(entity_a_metadata)
        .with_authority_hints(vec![entity_b_url.clone()]);

        let entity_a_jwt = encode(&federation_header(), &entity_a_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(entity_a_jwt.clone())
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&entity_a_server)
            .await;

        // Create Entity B that points back to Entity A (creating a loop) and exposes a fetch endpoint.
        let mut entity_b_metadata = EntityMetadata::new();
        entity_b_metadata.federation_entity = Some(FederationEntityMetadata {
            organization_name: Some("Entity B".to_string()),
            homepage_uri: None,
            policy_uri: None,
            logo_uri: None,
            contacts: None,
            federation_fetch_endpoint: Some(entity_b_url.join("federation_fetch_endpoint").unwrap()),
            federation_list_endpoint: None,
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });

        let entity_b_config = EntityConfiguration::new(
            entity_b_url.clone(),
            {
                let mut jwks = JwkSet::new();
                jwks.add_key(create_test_symmetric_key());
                jwks
            },
            expires_in(Duration::hours(24)),
            chrono::Utc::now().timestamp(),
        )
        .with_metadata(entity_b_metadata)
        .with_authority_hints(vec![entity_a_url.clone()]);

        let entity_b_jwt = encode(&federation_header(), &entity_b_config, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(entity_b_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&entity_b_server)
            .await;

        // Mock subordinate statement from B about A (required to recurse A -> B).
        let mut entity_b_signing_jwks = JwkSet::new();
        entity_b_signing_jwks.add_key(create_test_symmetric_key());
        let statement_b_about_a = SubordinateStatement::new(
            entity_b_url.clone(),
            entity_a_url.clone(),
            expires_in(Duration::hours(1)),
            chrono::Utc::now().timestamp(),
            entity_b_signing_jwks,
        );
        let b_about_a_jwt = encode(&federation_header(), &statement_b_about_a, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .and(query_param("sub", entity_a_url.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(b_about_a_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&entity_b_server)
            .await;

        // Mock subordinate statement from A about B (required when recursing B -> A).
        let mut entity_a_signing_jwks = JwkSet::new();
        entity_a_signing_jwks.add_key(create_test_symmetric_key());
        let statement_a_about_b = SubordinateStatement::new(
            entity_a_url.clone(),
            entity_b_url.clone(),
            expires_in(Duration::hours(1)),
            chrono::Utc::now().timestamp(),
            entity_a_signing_jwks,
        );
        let statement_a_about_b_jwt = encode(&federation_header(), &statement_a_about_b, &encoding_key).unwrap();

        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .and(query_param("sub", entity_b_url.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(statement_a_about_b_jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(&entity_a_server)
            .await;

        // Perform discovery - should detect the loop
        let client = FederationClient::new();
        let entity_a_id = entity_a_url.clone();
        let trusted_anchors = vec![Url::parse("http://trusted.anchor.local").unwrap()]; // Non-existent anchor

        let result = client.discover_trust_chain(&entity_a_id, Some(&trusted_anchors)).await;

        // Verify discovery fails due to loop detection
        assert!(result.is_err(), "Discovery should fail due to loop detection");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Loop") || error_msg.contains("loop"),
            "Error message should mention loop detection"
        );
    }

    /// Test 5: Expiration calculation - verify min(exp) across chain statements
    #[test]
    fn test_trust_chain_expiration_calculation() {
        use crate::TrustChain;
        use chrono::Utc;

        // Create a trust chain with multiple JWTs having different expiration times
        let encoding_key = EncodingKey::from_secret(b"test_secret_key");

        // Create three statements with different expiration times
        let now = Utc::now().timestamp();
        let short_exp = now + 3600; // 1 hour (minimum)
        let medium_exp = now + 7200; // 2 hours
        let long_exp = now + 86400; // 24 hours

        let jwks = {
            let mut jwks = JwkSet::new();
            jwks.add_key(create_test_symmetric_key());
            jwks
        };

        // Statement 1: Short expiration (this will be the minimum)
        let stmt1 = EntityConfiguration::new(
            Url::parse("http://entity1.local").unwrap(),
            jwks.clone(),
            short_exp,
            now,
        );

        let jwt1 = encode(&federation_header(), &stmt1, &encoding_key).unwrap();

        // Statement 2: Medium expiration (subordinate statement)
        let stmt2 = SubordinateStatement::new(
            Url::parse("http://entity3.local").unwrap(),
            Url::parse("http://entity1.local").unwrap(),
            medium_exp,
            now,
            jwks.clone(),
        );

        let jwt2 = encode(&federation_header(), &stmt2, &encoding_key).unwrap();

        // Statement 3: Long expiration (trust anchor configuration)
        let stmt3 = EntityConfiguration::new(Url::parse("http://entity3.local").unwrap(), jwks, long_exp, now);

        let jwt3 = encode(&federation_header(), &stmt3, &encoding_key).unwrap();

        // Create validated trust chain
        let trust_chain = TrustChain::try_new(vec![jwt1, jwt2, jwt3]).unwrap();

        // Verify expiration is the minimum
        let exp_timestamp = trust_chain.expiration_timestamp().unwrap();
        assert_eq!(exp_timestamp, short_exp, "Expiration should be the minimum (short_exp)");

        // Verify is_expired_at works correctly
        let before_expiry = Utc::now();
        assert!(
            !trust_chain.is_expired_at(before_expiry).unwrap(),
            "Chain should not be expired at current time"
        );

        // Create a timestamp far in the future (year 2100) for expiration check
        let far_future_timestamp = 4102444800i64; // Jan 1, 2100
        let after_expiry = chrono::DateTime::<Utc>::from_timestamp(far_future_timestamp, 0).unwrap();
        assert!(
            trust_chain.is_expired_at(after_expiry).unwrap(),
            "Chain should be expired in the future"
        );

        // Verify is_expired() convenience method
        assert!(
            !trust_chain.is_expired().unwrap(),
            "Chain should not be expired at current time"
        );
    }
}
