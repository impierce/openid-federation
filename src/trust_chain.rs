//! Trust Chain structures and validation logic.
//!
//! This module provides both Push and Pull methods for trust chain construction:
//! - **Push method**: Validates a pre-compiled trust chain (provided inline)
//! - **Pull method**: Dynamically resolves a trust chain via `FederationClient::discover_trust_chain`

use crate::{
    extract_claims_unverified, EntityConfiguration, EntityId, FederationError, FederationResult, JwtArtifactType,
    JwtProcessor, SubordinateStatement,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Trust Chain as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 4 Trust Chains  
/// <https://openid.net/specs/openid-federation-1_0.html#name-trust-chains>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustChain {
    /// Array of Entity Configurations and Subordinate Statements that form the trust chain
    /// The first element is the leaf entity's Entity Configuration
    /// The last element is the Trust Anchor's Entity Configuration
    /// Everything in between are Subordinate Statements that link the leaf to the trust anchor via intermediary entities.
    pub chain: Vec<String>, // JWT strings
    /// Metadata obtained from the trust chain resolution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<crate::EntityMetadata>,
    /// Trust marks obtained from the trust chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_marks: Option<Vec<crate::TrustMark>>,
}

impl TrustChain {
    /// Calculate the minimum expiration timestamp across all JWT statements in the chain.
    ///
    /// Reference: OpenID Federation 1.0 - Section 10.4 Calculating Trust Chain Expiration
    /// <https://openid.net/specs/openid-federation-1_0.html#name-calculating-trust-chain-expi>
    ///
    /// # Returns
    /// The UNIX timestamp (seconds) when the trust chain expires (the minimum of all exp claims).
    pub fn expiration_timestamp(&self) -> FederationResult<i64> {
        if self.chain.is_empty() {
            return Err(FederationError::TrustChainValidation(
                "Cannot calculate expiration of empty trust chain".to_string(),
            ));
        }

        let mut min_exp: Option<i64> = None;

        for jwt_string in &self.chain {
            // Extract exp claim without verification (we just need the timestamp)
            let claims: crate::JwtClaims = extract_claims_unverified(jwt_string)?;

            let exp = claims.exp;
            min_exp = Some(match min_exp {
                None => exp,
                Some(current_min) => current_min.min(exp),
            });
        }

        min_exp.ok_or_else(|| {
            FederationError::TrustChainValidation("No valid expiration time found in trust chain".to_string())
        })
    }

    /// Check if the trust chain is expired at a given point in time.
    ///
    /// # Arguments
    /// * `now` - The reference time to check expiration against
    ///
    /// # Returns
    /// `true` if the chain's minimum expiration time has passed, `false` otherwise.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> FederationResult<bool> {
        let min_exp_timestamp = self.expiration_timestamp()?;
        Ok(now.timestamp() >= min_exp_timestamp)
    }

    /// Check if the trust chain is expired at the current time.
    ///
    /// This is a convenience wrapper that uses the current UTC time.
    pub fn is_expired(&self) -> FederationResult<bool> {
        self.is_expired_at(Utc::now())
    }
}

/// Validated entity statement (either a configuration or a subordinate statement).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EntityStatement {
    /// Entity Configuration (self-signed, only at leaf or trust anchor)
    Configuration(EntityConfiguration),
    /// Subordinate Statement (signed by another entity, only between leaf and anchor)
    SubordinateStatement(SubordinateStatement),
}

impl From<EntityConfiguration> for EntityStatement {
    fn from(config: EntityConfiguration) -> Self {
        Self::Configuration(config)
    }
}

impl From<SubordinateStatement> for EntityStatement {
    fn from(statement: SubordinateStatement) -> Self {
        Self::SubordinateStatement(statement)
    }
}

impl TrustChain {
    /// Get the number of statements in the chain.
    /// This struct should only be created via `try_new`, which validates it's at least 2 (leaf + anchor).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Validate and construct a validated trust chain from raw JWT statements.
    ///
    /// The chain is authenticated from the Trust Anchor down to the leaf, so that every signature
    /// is verified with keys that were themselves endorsed by the statement above:
    ///
    /// 1. The last statement must be the Trust Anchor's Entity Configuration, self-signed with a key
    ///    from its own `jwks`. Those keys are the root of trust for the rest of the chain. Whether
    ///    this Trust Anchor is one the caller trusts is a separate decision; discovery binds the
    ///    configuration to the entity identifier it was fetched from, and callers of this
    ///    constructor must compare the anchor's entity identifier against their own trust list.
    /// 2. Each Subordinate Statement, walking downwards, must be issued by the entity whose keys
    ///    were just authenticated (`iss` equals the previous `sub`) and must be signed with one of
    ///    those keys. Its `jwks` then becomes the set of authenticated keys for its `sub`.
    /// 3. The first statement must be the leaf's Entity Configuration about the entity endorsed by
    ///    the lowest Subordinate Statement, signed with a key endorsed there, and self-signed with
    ///    a key from its own `jwks`.
    ///
    /// Structural checks (`exp`, `nbf`, non-empty `jwks`, JWT `typ` header, `iss`/`sub` rules) are
    /// applied to every statement as well.
    ///
    /// Reference: OpenID Federation 1.0 - Section 10.2 Validating a Trust Chain
    /// <https://openid.net/specs/openid-federation-1_0.html#name-validating-a-trust-chain>
    pub fn try_new(trust_chain: Vec<String>) -> FederationResult<Self> {
        let chain_len = trust_chain.len();

        if chain_len < 2 {
            return Err(FederationError::TrustChainValidation(
                "Trust chain must contain at least 2 statements".to_string(),
            ));
        }

        // Step 1: the Trust Anchor's Entity Configuration is the root of trust for this chain.
        let anchor_jwt = &trust_chain[chain_len - 1];
        let anchor_unverified: EntityConfiguration = extract_claims_unverified(anchor_jwt)?;
        let anchor =
            EntityConfiguration::from_verified_jwt(anchor_jwt, &anchor_unverified.claims.sub).map_err(|err| {
                FederationError::TrustChainValidation(format!("Invalid trust anchor entity configuration: {}", err))
            })?;

        // The entity whose keys are currently authenticated, and those keys.
        let mut endorsed_entity = anchor.claims.sub.clone();
        let mut endorsed_keys = anchor.jwks.clone();

        // Step 2: walk the Subordinate Statements from the anchor towards the leaf. Each one must be
        // issued by `endorsed_entity` and signed with `endorsed_keys`; it then endorses its subject.
        for jwt_string in trust_chain[1..chain_len - 1].iter().rev() {
            let unverified: SubordinateStatement = extract_claims_unverified(jwt_string)?;

            if unverified.claims.iss != endorsed_entity {
                return Err(FederationError::TrustChainValidation(format!(
                    "Trust chain is not properly linked: expected a subordinate statement issued by {}, got one issued by {}",
                    endorsed_entity, unverified.claims.iss
                )));
            }

            let statement = SubordinateStatement::from_verified_jwt(
                jwt_string,
                &endorsed_entity,
                &unverified.claims.sub,
                &endorsed_keys,
            )
            .map_err(|err| FederationError::TrustChainValidation(format!("Invalid subordinate statement: {}", err)))?;

            endorsed_entity = statement.claims.sub;
            endorsed_keys = statement.jwks;
        }

        // Step 3: the leaf's Entity Configuration must be about the entity endorsed by the lowest
        // Subordinate Statement and signed with a key that statement endorses.
        let leaf_jwt = &trust_chain[0];
        let leaf_unverified: EntityConfiguration = extract_claims_unverified(leaf_jwt)?;

        if leaf_unverified.claims.sub != endorsed_entity {
            return Err(FederationError::TrustChainValidation(format!(
                "Trust chain subject mismatch: leaf entity configuration is about {}, but the chain endorses {}",
                leaf_unverified.claims.sub, endorsed_entity
            )));
        }

        // Self-signed with its own keys, and identity-consistent.
        EntityConfiguration::from_verified_jwt(leaf_jwt, &endorsed_entity).map_err(|err| {
            FederationError::TrustChainValidation(format!("Invalid leaf entity configuration: {}", err))
        })?;

        // Signed with a key endorsed by its superior, so key substitution by the leaf is rejected.
        JwtProcessor::new()
            .verify_jwt_with_jwks::<EntityConfiguration>(leaf_jwt, &endorsed_keys, JwtArtifactType::EntityStatement)
            .map_err(|err| {
                FederationError::TrustChainValidation(format!(
                    "Leaf entity configuration of {} is not signed with a key endorsed by its superior: {}",
                    endorsed_entity, err
                ))
            })?;

        Ok(Self {
            chain: trust_chain,
            metadata: None,
            trust_marks: None,
        })
    }

    /// Get the leaf entity ID and leaf configuration as a tuple.
    pub fn leaf_entity_id_and_configuration(&self) -> FederationResult<(EntityId, EntityConfiguration)> {
        let Some(jwt) = self.chain.first() else {
            return Err(FederationError::TrustChainValidation(
                "Cannot retrieve leaf entity from empty trust chain".to_string(),
            ));
        };

        let config: EntityConfiguration = extract_claims_unverified(jwt)?;
        Ok((config.claims.sub.clone(), config))
    }

    /// Get the trust anchor entity ID and trust anchor configuration as a tuple.
    pub fn trust_anchor_entity_id_and_configuration(&self) -> FederationResult<(EntityId, EntityConfiguration)> {
        let Some(jwt) = self.chain.last() else {
            return Err(FederationError::TrustChainValidation(
                "Cannot retrieve trust anchor from empty trust chain".to_string(),
            ));
        };

        let config: EntityConfiguration = extract_claims_unverified(jwt)?;
        Ok((config.claims.iss.clone(), config))
    }
}

#[cfg(test)]
mod tests {
    use crate::{extract_claims_unverified, EntityMetadata, FederationClient, JwkSet};

    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::Duration;
    use jsonwebtoken::{Algorithm, EncodingKey};
    use url::Url;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    const TEST_SECRET: &str = "your-256-bit-secret-key-here-minimum-32-bytes!!!!";

    fn test_encoding_key() -> EncodingKey {
        EncodingKey::from_secret(TEST_SECRET.as_bytes())
    }

    fn test_jwk_set() -> JwkSet {
        let mut jwks = JwkSet::new();
        jwks.add_key(crate::Jwk {
            kty: "oct".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            alg: Some("HS256".to_string()),
            kid: Some("test-key".to_string()),
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
            k: Some(URL_SAFE_NO_PAD.encode(TEST_SECRET.as_bytes())),
        });
        jwks
    }

    fn future_expiration() -> i64 {
        (chrono::Utc::now() + Duration::hours(1)).timestamp()
    }

    fn build_federation_metadata(fetch_endpoint: Url) -> EntityMetadata {
        let mut metadata = EntityMetadata::new();
        metadata.federation_entity = Some(crate::FederationEntityMetadata {
            organization_name: Some("Test Federation".to_string()),
            display_name: None,
            description: None,
            keywords: None,
            contacts: None,
            logo_uri: None,
            policy_uri: None,
            information_uri: None,
            organization_uri: None,
            federation_fetch_endpoint: Some(fetch_endpoint),
            federation_list_endpoint: None,
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });
        metadata
    }

    fn build_entity_configuration(
        entity_id: &EntityId,
        authority_hints: Option<Vec<EntityId>>,
        fetch_endpoint: Option<Url>,
    ) -> EntityConfiguration {
        let mut config = EntityConfiguration::new(
            entity_id.clone(),
            test_jwk_set(),
            future_expiration(),
            chrono::Utc::now().timestamp(),
        );

        if let Some(hints) = authority_hints {
            config.authority_hints = Some(hints);
        }

        if let Some(endpoint) = fetch_endpoint {
            config.metadata = Some(build_federation_metadata(endpoint));
        }

        config
    }

    fn build_subordinate_statement(issuer: &EntityId, subject: &EntityId) -> SubordinateStatement {
        SubordinateStatement::new(
            issuer.clone(),
            subject.clone(),
            future_expiration(),
            chrono::Utc::now().timestamp(),
            test_jwk_set(),
        )
    }

    fn build_fetch_endpoint(entity_id: &EntityId) -> Url {
        let mut endpoint = entity_id.as_url().clone();
        endpoint.set_path("/federation_fetch_endpoint");
        endpoint.set_query(None);
        endpoint
    }

    fn encode_entity_configuration(config: &EntityConfiguration) -> String {
        let processor = JwtProcessor::new();
        processor
            .sign_jwt(
                config,
                &test_encoding_key(),
                Algorithm::HS256,
                JwtArtifactType::EntityStatement,
                Some("test-key".to_string()),
            )
            .expect("entity configuration JWT should sign")
    }

    fn encode_entity_statement(statement: &SubordinateStatement) -> String {
        let processor = JwtProcessor::new();
        processor
            .sign_jwt(
                statement,
                &test_encoding_key(),
                Algorithm::HS256,
                JwtArtifactType::EntityStatement,
                Some("test-key".to_string()),
            )
            .expect("entity statement JWT should sign")
    }

    async fn mock_entity_configuration(server: &MockServer, jwt: String) {
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-federation"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(server)
            .await;
    }

    async fn mock_subordinate_statement(server: &MockServer, subject: &EntityId, jwt: String) {
        Mock::given(method("GET"))
            .and(path("/federation_fetch_endpoint"))
            .and(query_param("sub", subject.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn resolve_trust_chain_with_two_intermediates() {
        let leaf_server = MockServer::start().await;
        let intermediate_one_server = MockServer::start().await;
        let intermediate_two_server = MockServer::start().await;
        let trust_anchor_server = MockServer::start().await;

        let leaf_url = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let intermediate_one_url = EntityId::parse(&format!("http://{}", intermediate_one_server.address())).unwrap();
        let intermediate_two_url = EntityId::parse(&format!("http://{}", intermediate_two_server.address())).unwrap();
        let trust_anchor_url = EntityId::parse(&format!("http://{}", trust_anchor_server.address())).unwrap();

        let leaf_fetch_endpoint = build_fetch_endpoint(&leaf_url);
        let intermediate_one_fetch_endpoint = build_fetch_endpoint(&intermediate_one_url);
        let intermediate_two_fetch_endpoint = build_fetch_endpoint(&intermediate_two_url);
        let trust_anchor_fetch_endpoint = build_fetch_endpoint(&trust_anchor_url);

        let leaf_config = build_entity_configuration(
            &leaf_url,
            Some(vec![intermediate_one_url.clone()]),
            Some(leaf_fetch_endpoint),
        );
        let intermediate_one_config = build_entity_configuration(
            &intermediate_one_url,
            Some(vec![intermediate_two_url.clone()]),
            Some(intermediate_one_fetch_endpoint.clone()),
        );
        let intermediate_two_config = build_entity_configuration(
            &intermediate_two_url,
            Some(vec![trust_anchor_url.clone()]),
            Some(intermediate_two_fetch_endpoint.clone()),
        );
        let trust_anchor_config =
            build_entity_configuration(&trust_anchor_url, None, Some(trust_anchor_fetch_endpoint));

        mock_entity_configuration(&leaf_server, encode_entity_configuration(&leaf_config)).await;
        mock_entity_configuration(
            &intermediate_one_server,
            encode_entity_configuration(&intermediate_one_config),
        )
        .await;
        mock_entity_configuration(
            &intermediate_two_server,
            encode_entity_configuration(&intermediate_two_config),
        )
        .await;
        mock_entity_configuration(&trust_anchor_server, encode_entity_configuration(&trust_anchor_config)).await;

        mock_subordinate_statement(
            &intermediate_one_server,
            &leaf_url,
            encode_entity_statement(&build_subordinate_statement(&intermediate_one_url, &leaf_url)),
        )
        .await;
        mock_subordinate_statement(
            &intermediate_two_server,
            &intermediate_one_url,
            encode_entity_statement(&build_subordinate_statement(
                &intermediate_two_url,
                &intermediate_one_url,
            )),
        )
        .await;
        mock_subordinate_statement(
            &trust_anchor_server,
            &intermediate_two_url,
            encode_entity_statement(&build_subordinate_statement(&trust_anchor_url, &intermediate_two_url)),
        )
        .await;

        let fed_client = FederationClient::new();

        let validated_trustchain = fed_client
            .discover_trust_chain(&leaf_url, Some(&[trust_anchor_url]))
            .await
            .expect("trust chain should resolve");

        // Pedantic checks: only the leaf and trust anchor are configurations.
        assert_eq!(
            validated_trustchain.chain.len(),
            5,
            "Chain must have 5 statements (leaf config + 3 subordinate statements + anchor config)"
        );
        let leaf = extract_claims_unverified::<EntityConfiguration>(&validated_trustchain.chain[0]).unwrap();
        assert_eq!(leaf.claims.sub, leaf.claims.iss);
        for statement in validated_trustchain.chain.iter().take(4).skip(1) {
            let statement = extract_claims_unverified::<SubordinateStatement>(statement).unwrap();
            assert_ne!(statement.claims.sub, statement.claims.iss);
        }
        let anchor = extract_claims_unverified::<EntityConfiguration>(&validated_trustchain.chain[4]).unwrap();
        assert_eq!(anchor.claims.sub, anchor.claims.iss);
        for statement in validated_trustchain.chain.iter() {
            let statement = extract_claims_unverified::<EntityStatement>(statement).unwrap();
            match statement {
                EntityStatement::Configuration(config) => {
                    assert!(!config.jwks.keys.is_empty(), "Configuration must have non-empty JWKS");
                }
                EntityStatement::SubordinateStatement(statement) => {
                    assert!(
                        !statement.jwks.keys.is_empty(),
                        "Subordinate statement must have non-empty JWKS"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn resolve_trust_chain_with_leaf_and_trust_anchor_only() {
        let leaf_server = MockServer::start().await;
        let trust_anchor_server = MockServer::start().await;

        let leaf_url = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let trust_anchor_url = EntityId::parse(&format!("http://{}", trust_anchor_server.address())).unwrap();

        let leaf_config = build_entity_configuration(
            &leaf_url,
            Some(vec![trust_anchor_url.clone()]),
            Some(build_fetch_endpoint(&leaf_url)),
        );
        let trust_anchor_config =
            build_entity_configuration(&trust_anchor_url, None, Some(build_fetch_endpoint(&trust_anchor_url)));

        mock_entity_configuration(&leaf_server, encode_entity_configuration(&leaf_config)).await;
        mock_entity_configuration(&trust_anchor_server, encode_entity_configuration(&trust_anchor_config)).await;
        mock_subordinate_statement(
            &trust_anchor_server,
            &leaf_url,
            encode_entity_statement(&build_subordinate_statement(&trust_anchor_url, &leaf_url)),
        )
        .await;

        let fed_client = FederationClient::new();

        let validated_trustchain = fed_client
            .discover_trust_chain(&leaf_url, Some(&[trust_anchor_url]))
            .await
            .expect("trust chain should resolve");

        // Must be exactly 3 statements: leaf config + subordinate statement + anchor config
        assert_eq!(
            validated_trustchain.chain.len(),
            3,
            "Minimal chain must have 3 statements"
        );
        let leaf = extract_claims_unverified::<EntityConfiguration>(&validated_trustchain.chain[0]).unwrap();
        assert_eq!(leaf.claims.sub, leaf.claims.iss);
        let statement = extract_claims_unverified::<SubordinateStatement>(&validated_trustchain.chain[1]).unwrap();
        assert_ne!(statement.claims.sub, statement.claims.iss);
        let anchor = extract_claims_unverified::<EntityConfiguration>(&validated_trustchain.chain[2]).unwrap();
        assert_eq!(anchor.claims.sub, anchor.claims.iss);
        for statement in validated_trustchain.chain.iter() {
            let statement = extract_claims_unverified::<EntityStatement>(statement).unwrap();
            match statement {
                EntityStatement::Configuration(config) => {
                    assert!(!config.jwks.keys.is_empty(), "Configuration must have non-empty JWKS");
                }
                EntityStatement::SubordinateStatement(statement) => {
                    assert!(
                        !statement.jwks.keys.is_empty(),
                        "Subordinate statement must have non-empty JWKS"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn resolve_trust_chain_fails_when_sub_query_param_is_wrong() {
        let leaf_server = MockServer::start().await;
        let intermediate_server = MockServer::start().await;
        let trust_anchor_server = MockServer::start().await;

        let leaf_url = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let intermediate_url = EntityId::parse(&format!("http://{}", intermediate_server.address())).unwrap();
        let trust_anchor_url = EntityId::parse(&format!("http://{}", trust_anchor_server.address())).unwrap();

        let leaf_config = build_entity_configuration(
            &leaf_url,
            Some(vec![intermediate_url.clone()]),
            Some(build_fetch_endpoint(&leaf_url)),
        );
        let intermediate_config = build_entity_configuration(
            &intermediate_url,
            Some(vec![trust_anchor_url.clone()]),
            Some(build_fetch_endpoint(&intermediate_url)),
        );
        let trust_anchor_config =
            build_entity_configuration(&trust_anchor_url, None, Some(build_fetch_endpoint(&trust_anchor_url)));

        mock_entity_configuration(&leaf_server, encode_entity_configuration(&leaf_config)).await;
        mock_entity_configuration(&intermediate_server, encode_entity_configuration(&intermediate_config)).await;
        mock_entity_configuration(&trust_anchor_server, encode_entity_configuration(&trust_anchor_config)).await;

        // Deliberately register a mismatching `sub` to prove the resolver must send the exact query.
        let wrong_subject = EntityId::parse("https://wrong.example.test").unwrap();
        mock_subordinate_statement(
            &intermediate_server,
            &wrong_subject,
            encode_entity_statement(&build_subordinate_statement(&intermediate_url, &leaf_url)),
        )
        .await;
        mock_subordinate_statement(
            &trust_anchor_server,
            &intermediate_url,
            encode_entity_statement(&build_subordinate_statement(&trust_anchor_url, &intermediate_url)),
        )
        .await;

        let fed_client = FederationClient::new();

        let err = fed_client
            .discover_trust_chain(&leaf_url, Some(&[trust_anchor_url]))
            .await
            .unwrap_err();

        match err {
            FederationError::EntityResolution(message) => {
                assert!(message.contains("No superior for"));
            }
            other => panic!("expected EntityResolution error, got: {:?}", other),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Regression tests for signature and identity binding. Every entity below uses its own key so
    // that a chain only validates when each statement is signed with keys endorsed from the anchor.
    // ---------------------------------------------------------------------------------------------

    const LEAF_SECRET: &str = "leaf-secret-key-0123456789-0123456789-0123456789";
    const INTERMEDIATE_SECRET: &str = "intermediate-secret-key-0123456789-0123456789";
    const ANCHOR_SECRET: &str = "anchor-secret-key-0123456789-0123456789-01234";
    const ATTACKER_SECRET: &str = "attacker-secret-key-0123456789-0123456789-012";

    fn keyed_jwk_set(secret: &str, kid: &str) -> JwkSet {
        let mut jwks = JwkSet::new();
        jwks.add_key(crate::Jwk {
            kty: "oct".to_string(),
            use_: Some("sig".to_string()),
            key_ops: None,
            alg: Some("HS256".to_string()),
            kid: Some(kid.to_string()),
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
            k: Some(URL_SAFE_NO_PAD.encode(secret.as_bytes())),
        });
        jwks
    }

    fn sign_with<T: serde::Serialize>(claims: &T, secret: &str, kid: &str) -> String {
        JwtProcessor::new()
            .sign_jwt(
                claims,
                &EncodingKey::from_secret(secret.as_bytes()),
                Algorithm::HS256,
                JwtArtifactType::EntityStatement,
                Some(kid.to_string()),
            )
            .expect("JWT should sign")
    }

    fn keyed_configuration(
        entity_id: &EntityId,
        jwks: JwkSet,
        authority_hints: Option<Vec<EntityId>>,
        fetch_endpoint: Option<Url>,
    ) -> EntityConfiguration {
        let mut config = EntityConfiguration::new(
            entity_id.clone(),
            jwks,
            future_expiration(),
            chrono::Utc::now().timestamp(),
        );
        config.authority_hints = authority_hints;
        if let Some(endpoint) = fetch_endpoint {
            config.metadata = Some(build_federation_metadata(endpoint));
        }
        config
    }

    fn keyed_statement(issuer: &EntityId, subject: &EntityId, subject_keys: JwkSet) -> SubordinateStatement {
        SubordinateStatement::new(
            issuer.clone(),
            subject.clone(),
            future_expiration(),
            chrono::Utc::now().timestamp(),
            subject_keys,
        )
    }

    /// A valid leaf -> intermediate -> anchor chain where every entity signs with its own key.
    /// Returns (leaf_jwt, intermediate_about_leaf_jwt, anchor_about_intermediate_jwt, anchor_jwt).
    fn distinct_key_chain() -> (String, String, String, String, EntityId, EntityId, EntityId) {
        let leaf_url = EntityId::parse("https://leaf.example.test").unwrap();
        let intermediate_url = EntityId::parse("https://intermediate.example.test").unwrap();
        let anchor_url = EntityId::parse("https://anchor.example.test").unwrap();

        let leaf_jwt = sign_with(
            &keyed_configuration(
                &leaf_url,
                keyed_jwk_set(LEAF_SECRET, "leaf-key"),
                Some(vec![intermediate_url.clone()]),
                None,
            ),
            LEAF_SECRET,
            "leaf-key",
        );
        let intermediate_about_leaf_jwt = sign_with(
            &keyed_statement(&intermediate_url, &leaf_url, keyed_jwk_set(LEAF_SECRET, "leaf-key")),
            INTERMEDIATE_SECRET,
            "intermediate-key",
        );
        let anchor_about_intermediate_jwt = sign_with(
            &keyed_statement(
                &anchor_url,
                &intermediate_url,
                keyed_jwk_set(INTERMEDIATE_SECRET, "intermediate-key"),
            ),
            ANCHOR_SECRET,
            "anchor-key",
        );
        let anchor_jwt = sign_with(
            &keyed_configuration(&anchor_url, keyed_jwk_set(ANCHOR_SECRET, "anchor-key"), None, None),
            ANCHOR_SECRET,
            "anchor-key",
        );

        (
            leaf_jwt,
            intermediate_about_leaf_jwt,
            anchor_about_intermediate_jwt,
            anchor_jwt,
            leaf_url,
            intermediate_url,
            anchor_url,
        )
    }

    #[test]
    fn try_new_accepts_chain_with_distinct_keys_per_entity() {
        let (leaf, intermediate_about_leaf, anchor_about_intermediate, anchor, leaf_url, _, anchor_url) =
            distinct_key_chain();

        let chain = TrustChain::try_new(vec![leaf, intermediate_about_leaf, anchor_about_intermediate, anchor])
            .expect("chain with per-entity keys should validate");

        assert_eq!(chain.leaf_entity_id_and_configuration().unwrap().0, leaf_url);
        assert_eq!(chain.trust_anchor_entity_id_and_configuration().unwrap().0, anchor_url);
    }

    #[test]
    fn try_new_accepts_direct_leaf_to_anchor_chain_with_distinct_keys() {
        let leaf_url = EntityId::parse("https://leaf.example.test").unwrap();
        let anchor_url = EntityId::parse("https://anchor.example.test").unwrap();

        let leaf = sign_with(
            &keyed_configuration(
                &leaf_url,
                keyed_jwk_set(LEAF_SECRET, "leaf-key"),
                Some(vec![anchor_url.clone()]),
                None,
            ),
            LEAF_SECRET,
            "leaf-key",
        );
        let anchor_about_leaf = sign_with(
            &keyed_statement(&anchor_url, &leaf_url, keyed_jwk_set(LEAF_SECRET, "leaf-key")),
            ANCHOR_SECRET,
            "anchor-key",
        );
        let anchor = sign_with(
            &keyed_configuration(&anchor_url, keyed_jwk_set(ANCHOR_SECRET, "anchor-key"), None, None),
            ANCHOR_SECRET,
            "anchor-key",
        );

        TrustChain::try_new(vec![leaf, anchor_about_leaf, anchor]).expect("direct chain should validate");
    }

    #[test]
    fn try_new_rejects_subordinate_statement_signed_with_unrelated_key() {
        let (leaf, intermediate_about_leaf, _, anchor, _, intermediate_url, anchor_url) = distinct_key_chain();

        // Claims are well formed and name the real anchor as issuer, but the signature was made
        // with an attacker key. Reusing the anchor's `kid` makes sure the signature itself is checked.
        let forged_anchor_about_intermediate = sign_with(
            &keyed_statement(
                &anchor_url,
                &intermediate_url,
                keyed_jwk_set(INTERMEDIATE_SECRET, "intermediate-key"),
            ),
            ATTACKER_SECRET,
            "anchor-key",
        );

        let err = TrustChain::try_new(vec![
            leaf,
            intermediate_about_leaf,
            forged_anchor_about_intermediate,
            anchor,
        ])
        .expect_err("subordinate statement with an unrelated signature must be rejected");
        assert!(
            matches!(err, FederationError::TrustChainValidation(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn try_new_rejects_tampered_subordinate_statement_payload() {
        let (leaf, intermediate_about_leaf, anchor_about_intermediate, anchor, _, _, _) = distinct_key_chain();

        // Replace the payload of a correctly signed statement with a modified one, keeping the
        // original signature. The claims still link structurally.
        let mut parts: Vec<&str> = anchor_about_intermediate.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let mut payload: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();
        payload["exp"] = serde_json::Value::from(future_expiration() + 3600);
        let tampered_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");

        TrustChain::try_new(vec![leaf, intermediate_about_leaf, tampered, anchor])
            .expect_err("tampered subordinate statement must be rejected");
    }

    #[test]
    fn try_new_rejects_leaf_key_not_endorsed_by_superior() {
        let (leaf, _, anchor_about_intermediate, anchor, leaf_url, intermediate_url, _) = distinct_key_chain();

        // The intermediate's statement about the leaf is correctly signed, but endorses a key that is
        // not the one the leaf used to sign its configuration.
        let intermediate_about_leaf_wrong_keys = sign_with(
            &keyed_statement(&intermediate_url, &leaf_url, keyed_jwk_set(ATTACKER_SECRET, "leaf-key")),
            INTERMEDIATE_SECRET,
            "intermediate-key",
        );

        let err = TrustChain::try_new(vec![
            leaf,
            intermediate_about_leaf_wrong_keys,
            anchor_about_intermediate,
            anchor,
        ])
        .expect_err("leaf signed with a key its superior did not endorse must be rejected");
        assert!(
            err.to_string()
                .contains("not signed with a key endorsed by its superior"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn try_new_rejects_subordinate_statement_from_unexpected_issuer() {
        let (leaf, intermediate_about_leaf, _, anchor, _, intermediate_url, _) = distinct_key_chain();
        let other_url = EntityId::parse("https://other.example.test").unwrap();

        // Signed with the anchor's key, but claims to be issued by someone else than the anchor.
        let wrong_issuer = sign_with(
            &keyed_statement(
                &other_url,
                &intermediate_url,
                keyed_jwk_set(INTERMEDIATE_SECRET, "intermediate-key"),
            ),
            ANCHOR_SECRET,
            "anchor-key",
        );

        let err = TrustChain::try_new(vec![leaf, intermediate_about_leaf, wrong_issuer, anchor])
            .expect_err("subordinate statement from an unexpected issuer must be rejected");
        assert!(
            err.to_string().contains("not properly linked"),
            "unexpected error: {err}"
        );
    }

    /// The combined L/S/V scenario from the bug report: an attacker-controlled leaf and superior
    /// where the superior serves a configuration claiming the real anchor's identity.
    #[tokio::test]
    async fn all_chains_discovery_rejects_superior_claiming_another_anchors_identity() {
        let leaf_server = MockServer::start().await;
        let superior_server = MockServer::start().await;

        let leaf_url = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let superior_url = EntityId::parse(&format!("http://{}", superior_server.address())).unwrap();
        // The victim anchor is never contacted; only its identifier is claimed.
        let victim_url = EntityId::parse("https://victim-anchor.example.test").unwrap();

        let leaf_config = keyed_configuration(
            &leaf_url,
            keyed_jwk_set(LEAF_SECRET, "leaf-key"),
            Some(vec![superior_url.clone()]),
            None,
        );
        mock_entity_configuration(&leaf_server, sign_with(&leaf_config, LEAF_SECRET, "leaf-key")).await;

        // Served by S, but claims iss = sub = V, self-signed with attacker keys, terminal.
        let forged_victim_config = keyed_configuration(
            &victim_url,
            keyed_jwk_set(ATTACKER_SECRET, "attacker-key"),
            None,
            Some(build_fetch_endpoint(&superior_url)),
        );
        mock_entity_configuration(
            &superior_server,
            sign_with(&forged_victim_config, ATTACKER_SECRET, "attacker-key"),
        )
        .await;

        // The fetch endpoint on S returns "V says L is a subordinate", signed with the attacker key.
        mock_subordinate_statement(
            &superior_server,
            &leaf_url,
            sign_with(
                &keyed_statement(&victim_url, &leaf_url, keyed_jwk_set(LEAF_SECRET, "leaf-key")),
                ATTACKER_SECRET,
                "attacker-key",
            ),
        )
        .await;

        let client = FederationClient::new();

        let err = client
            .discover_all_trust_chains(&leaf_url)
            .await
            .expect_err("forged anchor identity must not yield a trust chain");
        assert!(
            matches!(err, FederationError::EntityResolution(_)),
            "unexpected error: {err:?}"
        );

        // Sanity check: the raw document S serves does claim V and is internally consistent, so the
        // rejection comes from binding it to the requested identity.
        let raw = client.fetch_entity_configuration(&superior_url).await.unwrap();
        let claimed: EntityConfiguration = extract_claims_unverified(&raw).unwrap();
        assert_eq!(claimed.claims.iss, victim_url);
        assert!(EntityConfiguration::from_verified_jwt(&raw, &victim_url).is_ok());
        assert!(EntityConfiguration::from_verified_jwt(&raw, &superior_url).is_err());
    }

    #[tokio::test]
    async fn anchored_discovery_rejects_start_configuration_claiming_another_identity() {
        let leaf_server = MockServer::start().await;
        let anchor_server = MockServer::start().await;

        let leaf_url = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let anchor_url = EntityId::parse(&format!("http://{}", anchor_server.address())).unwrap();
        let other_url = EntityId::parse("https://other-leaf.example.test").unwrap();

        // Served from the leaf server, but claims to be `other`.
        let impostor_config = keyed_configuration(
            &other_url,
            keyed_jwk_set(LEAF_SECRET, "leaf-key"),
            Some(vec![anchor_url.clone()]),
            None,
        );
        mock_entity_configuration(&leaf_server, sign_with(&impostor_config, LEAF_SECRET, "leaf-key")).await;

        let anchor_config = keyed_configuration(
            &anchor_url,
            keyed_jwk_set(ANCHOR_SECRET, "anchor-key"),
            None,
            Some(build_fetch_endpoint(&anchor_url)),
        );
        mock_entity_configuration(&anchor_server, sign_with(&anchor_config, ANCHOR_SECRET, "anchor-key")).await;
        mock_subordinate_statement(
            &anchor_server,
            &other_url,
            sign_with(
                &keyed_statement(&anchor_url, &other_url, keyed_jwk_set(LEAF_SECRET, "leaf-key")),
                ANCHOR_SECRET,
                "anchor-key",
            ),
        )
        .await;

        let client = FederationClient::new();

        let err = client
            .discover_trust_chain(&leaf_url, Some(std::slice::from_ref(&anchor_url)))
            .await
            .expect_err("start configuration with a foreign identity must be rejected");
        assert!(err.to_string().contains("identity mismatch"), "unexpected error: {err}");

        client
            .discover_all_trust_chains(&leaf_url)
            .await
            .expect_err("all-chains discovery must reject it as well");
    }

    #[tokio::test]
    async fn anchored_discovery_rejects_subordinate_statement_signed_with_unrelated_key() {
        let leaf_server = MockServer::start().await;
        let anchor_server = MockServer::start().await;

        let leaf_url = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let anchor_url = EntityId::parse(&format!("http://{}", anchor_server.address())).unwrap();

        let leaf_config = keyed_configuration(
            &leaf_url,
            keyed_jwk_set(LEAF_SECRET, "leaf-key"),
            Some(vec![anchor_url.clone()]),
            None,
        );
        mock_entity_configuration(&leaf_server, sign_with(&leaf_config, LEAF_SECRET, "leaf-key")).await;

        let anchor_config = keyed_configuration(
            &anchor_url,
            keyed_jwk_set(ANCHOR_SECRET, "anchor-key"),
            None,
            Some(build_fetch_endpoint(&anchor_url)),
        );
        mock_entity_configuration(&anchor_server, sign_with(&anchor_config, ANCHOR_SECRET, "anchor-key")).await;

        // Well-formed claims, but not signed by the anchor.
        mock_subordinate_statement(
            &anchor_server,
            &leaf_url,
            sign_with(
                &keyed_statement(&anchor_url, &leaf_url, keyed_jwk_set(LEAF_SECRET, "leaf-key")),
                ATTACKER_SECRET,
                "anchor-key",
            ),
        )
        .await;

        let client = FederationClient::new();

        let err = client
            .discover_trust_chain(&leaf_url, Some(&[anchor_url]))
            .await
            .expect_err("unverifiable subordinate statement must be rejected");
        assert!(
            err.to_string().contains("not signed with an authenticated key"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn all_chains_discovery_returns_only_authenticated_branches() {
        let leaf_server = MockServer::start().await;
        let good_anchor_server = MockServer::start().await;
        let bad_anchor_server = MockServer::start().await;

        let leaf_url = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let good_anchor_url = EntityId::parse(&format!("http://{}", good_anchor_server.address())).unwrap();
        let bad_anchor_url = EntityId::parse(&format!("http://{}", bad_anchor_server.address())).unwrap();

        let leaf_config = keyed_configuration(
            &leaf_url,
            keyed_jwk_set(LEAF_SECRET, "leaf-key"),
            Some(vec![bad_anchor_url.clone(), good_anchor_url.clone()]),
            None,
        );
        mock_entity_configuration(&leaf_server, sign_with(&leaf_config, LEAF_SECRET, "leaf-key")).await;

        // Good branch: properly signed everywhere.
        let good_anchor_config = keyed_configuration(
            &good_anchor_url,
            keyed_jwk_set(ANCHOR_SECRET, "anchor-key"),
            None,
            Some(build_fetch_endpoint(&good_anchor_url)),
        );
        mock_entity_configuration(
            &good_anchor_server,
            sign_with(&good_anchor_config, ANCHOR_SECRET, "anchor-key"),
        )
        .await;
        mock_subordinate_statement(
            &good_anchor_server,
            &leaf_url,
            sign_with(
                &keyed_statement(&good_anchor_url, &leaf_url, keyed_jwk_set(LEAF_SECRET, "leaf-key")),
                ANCHOR_SECRET,
                "anchor-key",
            ),
        )
        .await;

        // Bad branch: the anchor's statement about the leaf endorses a key the leaf does not use.
        let bad_anchor_config = keyed_configuration(
            &bad_anchor_url,
            keyed_jwk_set(INTERMEDIATE_SECRET, "bad-anchor-key"),
            None,
            Some(build_fetch_endpoint(&bad_anchor_url)),
        );
        mock_entity_configuration(
            &bad_anchor_server,
            sign_with(&bad_anchor_config, INTERMEDIATE_SECRET, "bad-anchor-key"),
        )
        .await;
        mock_subordinate_statement(
            &bad_anchor_server,
            &leaf_url,
            sign_with(
                &keyed_statement(&bad_anchor_url, &leaf_url, keyed_jwk_set(ATTACKER_SECRET, "leaf-key")),
                INTERMEDIATE_SECRET,
                "bad-anchor-key",
            ),
        )
        .await;

        let client = FederationClient::new();

        let chains = client
            .discover_all_trust_chains(&leaf_url)
            .await
            .expect("the valid sibling branch should still be discovered");

        assert_eq!(chains.len(), 1, "only the authenticated branch may be returned");
        assert_eq!(
            chains[0].trust_anchor_entity_id_and_configuration().unwrap().0,
            good_anchor_url
        );
        assert_eq!(chains[0].leaf_entity_id_and_configuration().unwrap().0, leaf_url);
    }

    /// Serves `anchor_url`'s configuration from `server`, signed with `secret`, and its statement
    /// about `leaf_url` endorsing `leaf_keys`.
    async fn mock_anchor_endorsing(
        server: &MockServer,
        anchor_url: &EntityId,
        secret: &str,
        leaf_url: &EntityId,
        leaf_keys: JwkSet,
    ) {
        let anchor_config = keyed_configuration(
            anchor_url,
            keyed_jwk_set(secret, "anchor-key"),
            None,
            Some(build_fetch_endpoint(anchor_url)),
        );
        mock_entity_configuration(server, sign_with(&anchor_config, secret, "anchor-key")).await;
        mock_subordinate_statement(
            server,
            leaf_url,
            sign_with(&keyed_statement(anchor_url, leaf_url, leaf_keys), secret, "anchor-key"),
        )
        .await;
    }

    #[tokio::test]
    async fn all_chains_discovery_reports_every_skipped_branch() {
        let leaf_server = MockServer::start().await;
        let good_anchor_server = MockServer::start().await;
        let unreachable_server = MockServer::start().await;
        let no_fetch_endpoint_server = MockServer::start().await;
        let no_statement_server = MockServer::start().await;
        let unendorsed_server = MockServer::start().await;

        let url_of = |server: &MockServer| EntityId::parse(&format!("http://{}", server.address())).unwrap();
        let leaf_url = url_of(&leaf_server);
        let good_anchor_url = url_of(&good_anchor_server);
        let unreachable_url = url_of(&unreachable_server);
        let no_fetch_endpoint_url = url_of(&no_fetch_endpoint_server);
        let no_statement_url = url_of(&no_statement_server);
        let unendorsed_url = url_of(&unendorsed_server);

        let leaf_keys = || keyed_jwk_set(LEAF_SECRET, "leaf-key");
        let leaf_config = keyed_configuration(
            &leaf_url,
            leaf_keys(),
            Some(vec![
                unreachable_url.clone(),
                no_fetch_endpoint_url.clone(),
                no_statement_url.clone(),
                unendorsed_url.clone(),
                good_anchor_url.clone(),
            ]),
            None,
        );
        mock_entity_configuration(&leaf_server, sign_with(&leaf_config, LEAF_SECRET, "leaf-key")).await;

        mock_anchor_endorsing(
            &good_anchor_server,
            &good_anchor_url,
            ANCHOR_SECRET,
            &leaf_url,
            leaf_keys(),
        )
        .await;

        // `unreachable_server` serves nothing.

        let no_fetch_endpoint_config = keyed_configuration(
            &no_fetch_endpoint_url,
            keyed_jwk_set(ANCHOR_SECRET, "anchor-key"),
            None,
            None,
        );
        mock_entity_configuration(
            &no_fetch_endpoint_server,
            sign_with(&no_fetch_endpoint_config, ANCHOR_SECRET, "anchor-key"),
        )
        .await;

        // Has a fetch endpoint, but no statement about the leaf.
        let no_statement_config = keyed_configuration(
            &no_statement_url,
            keyed_jwk_set(ANCHOR_SECRET, "anchor-key"),
            None,
            Some(build_fetch_endpoint(&no_statement_url)),
        );
        mock_entity_configuration(
            &no_statement_server,
            sign_with(&no_statement_config, ANCHOR_SECRET, "anchor-key"),
        )
        .await;

        // Correctly signed statement, but it endorses a key the leaf does not sign with.
        mock_anchor_endorsing(
            &unendorsed_server,
            &unendorsed_url,
            INTERMEDIATE_SECRET,
            &leaf_url,
            keyed_jwk_set(ATTACKER_SECRET, "leaf-key"),
        )
        .await;

        let client = FederationClient::new();

        let discovery = client
            .discover_all_trust_chains_with_failures(&leaf_url)
            .await
            .expect("the leaf itself is resolvable");

        assert_eq!(discovery.chains.len(), 1);
        assert_eq!(
            discovery.chains[0]
                .trust_anchor_entity_id_and_configuration()
                .unwrap()
                .0,
            good_anchor_url
        );

        let failure_for = |entity_id: &EntityId| {
            let failures: Vec<_> = discovery
                .failures
                .iter()
                .filter(|failure| &failure.entity_id == entity_id)
                .collect();
            assert_eq!(
                failures.len(),
                1,
                "expected one failure for {entity_id}: {:?}",
                discovery.failures
            );
            failures[0].error.to_string()
        };
        assert_eq!(discovery.failures.len(), 4, "failures: {:?}", discovery.failures);
        assert!(failure_for(&unreachable_url).contains("HTTP 404"));
        assert!(failure_for(&no_fetch_endpoint_url).contains("has no federation_fetch_endpoint"));
        assert!(failure_for(&no_statement_url).contains("federation_fetch_endpoint?sub="));
        assert!(failure_for(&unendorsed_url).contains("not signed with a key endorsed by its superior"));

        let chains = client
            .discover_all_trust_chains(&leaf_url)
            .await
            .expect("all-chains discovery still returns the valid branch");
        assert_eq!(chains.len(), 1);
    }

    #[tokio::test]
    async fn all_chains_discovery_reports_failures_when_no_chain_is_found() {
        let leaf_server = MockServer::start().await;
        let unreachable_server = MockServer::start().await;

        let leaf_url = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let unreachable_url = EntityId::parse(&format!("http://{}", unreachable_server.address())).unwrap();

        let leaf_config = keyed_configuration(
            &leaf_url,
            keyed_jwk_set(LEAF_SECRET, "leaf-key"),
            Some(vec![unreachable_url.clone()]),
            None,
        );
        mock_entity_configuration(&leaf_server, sign_with(&leaf_config, LEAF_SECRET, "leaf-key")).await;

        let client = FederationClient::new();

        let discovery = client
            .discover_all_trust_chains_with_failures(&leaf_url)
            .await
            .expect("the leaf itself is resolvable");
        assert!(discovery.chains.is_empty());
        assert_eq!(discovery.failures.len(), 1, "failures: {:?}", discovery.failures);
        assert_eq!(discovery.failures[0].entity_id, unreachable_url);

        client
            .discover_all_trust_chains(&leaf_url)
            .await
            .expect_err("all-chains discovery keeps failing without chains");
    }

    #[tokio::test]
    async fn all_chains_discovery_with_failures_fails_for_unresolvable_start_entity() {
        let unreachable_server = MockServer::start().await;
        let unreachable_url = EntityId::parse(&format!("http://{}", unreachable_server.address())).unwrap();

        FederationClient::new()
            .discover_all_trust_chains_with_failures(&unreachable_url)
            .await
            .expect_err("the start entity must be resolvable");
    }

    /// A superior's fetch endpoint may compare `sub` as a string, so discovery asks about an entity
    /// under the identifier the entity publishes, not under the spelling of the authority hint or
    /// start identifier that led to it. The servers publish their identifiers without a trailing
    /// `/`; the leaf's authority hint and the identifier discovery starts from carry one.
    #[tokio::test]
    async fn discovery_asks_superiors_about_the_identifier_the_entity_publishes() {
        let leaf_server = MockServer::start().await;
        let superior_server = MockServer::start().await;

        let leaf_id = EntityId::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let superior_id = EntityId::parse(&format!("http://{}", superior_server.address())).unwrap();
        let with_slash = |entity_id: &EntityId| EntityId::parse(&format!("{entity_id}/")).unwrap();

        let leaf_config = build_entity_configuration(&leaf_id, Some(vec![with_slash(&superior_id)]), None);
        mock_entity_configuration(&leaf_server, encode_entity_configuration(&leaf_config)).await;
        let superior_config = build_entity_configuration(&superior_id, None, Some(build_fetch_endpoint(&superior_id)));
        mock_entity_configuration(&superior_server, encode_entity_configuration(&superior_config)).await;
        // Answers only `sub` spelled as the leaf publishes it.
        mock_subordinate_statement(
            &superior_server,
            &leaf_id,
            encode_entity_statement(&build_subordinate_statement(&superior_id, &leaf_id)),
        )
        .await;

        let client = FederationClient::new();

        let discovery = client
            .discover_all_trust_chains_with_failures(&with_slash(&leaf_id))
            .await
            .expect("the leaf itself is resolvable");
        assert!(discovery.failures.is_empty(), "failures: {:?}", discovery.failures);
        assert_eq!(discovery.chains.len(), 1);
        let (anchor_id, _) = discovery.chains[0].trust_anchor_entity_id_and_configuration().unwrap();
        assert_eq!(anchor_id.as_str(), superior_id.as_str());

        client
            .discover_trust_chain(&with_slash(&leaf_id), Some(&[with_slash(&superior_id)]))
            .await
            .expect("anchored discovery asks about the published identifier too");
    }
}
