//! Trust Chain structures and validation logic.
//!
//! This module provides both Push and Pull methods for trust chain construction:
//! - **Push method**: Validates a pre-compiled trust chain (provided inline)
//! - **Pull method**: Dynamically resolves a trust chain from public endpoints given an entity ID

use crate::{
    EntityConfiguration, EntityId, EntityStatement, FederationClient, FederationError, FederationResult,
    JwtArtifactType, JwtProcessor,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trust Chain as defined in the OpenID Federation specification.
///
/// Reference: OpenID Federation 1.0 - Section 4 Trust Chains  
/// https://openid.net/specs/openid-federation-1_0.html#name-trust-chains
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustChain {
    /// Array of Entity Statements that form the trust chain
    /// The first element is the leaf entity's Entity Statement
    /// The last element is the Trust Anchor's Entity Configuration
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
    /// https://openid.net/specs/openid-federation-1_0.html#name-calculating-trust-chain-expi
    ///
    /// # Returns
    /// The UNIX timestamp (seconds) when the trust chain expires (the minimum of all exp claims).
    pub fn expiration_timestamp(&self) -> FederationResult<i64> {
        if self.chain.is_empty() {
            return Err(FederationError::TrustChainValidation(
                "Cannot calculate expiration of empty trust chain".to_string(),
            ));
        }

        let jwt_processor = JwtProcessor::new();
        let mut min_exp: Option<i64> = None;

        for jwt_string in &self.chain {
            // Extract exp claim without verification (we just need the timestamp)
            let claims: crate::JwtClaims = jwt_processor.extract_claims_unverified(jwt_string)?;

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

/// Trust Chain Validator for OpenID Federation.
pub struct TrustChainValidator {
    jwt_processor: JwtProcessor,
}

impl TrustChainValidator {
    /// Create a new trust chain validator.
    pub fn new() -> Self {
        Self {
            jwt_processor: JwtProcessor::new(),
        }
    }

    /// Validate a trust chain.
    ///
    /// Reference: OpenID Federation 1.0 - Section 4.2 Trust Chain Validation
    /// https://openid.net/specs/openid-federation-1_0.html#name-trust-chain-validation
    pub fn validate_trust_chain(&self, trust_chain: &TrustChain) -> FederationResult<ValidatedTrustChain> {
        if trust_chain.chain.is_empty() {
            return Err(FederationError::TrustChainValidation(
                "Trust chain cannot be empty".to_string(),
            ));
        }

        let mut validated_statements = Vec::new();
        let mut current_subject: Option<EntityId> = None;

        // Process each JWT in the chain
        for (index, jwt_string) in trust_chain.chain.iter().enumerate() {
            if index == 0 {
                // First element should be a leaf entity configuration (self-signed)
                let entity_config: EntityConfiguration = self.jwt_processor.extract_claims_unverified(jwt_string)?;

                entity_config.validate()?;

                // Verify signature using the entity's own keys
                let verified_config: EntityConfiguration = self.jwt_processor.verify_jwt_with_jwks(
                    jwt_string,
                    &entity_config.jwks,
                    JwtArtifactType::EntityStatement,
                )?;

                current_subject = Some(verified_config.claims.sub.clone());
                validated_statements.push(ValidatedEntityStatement::Configuration(verified_config));
            } else if index == trust_chain.chain.len() - 1 {
                // Last element should be the trust anchor's entity configuration
                let trust_anchor_config: EntityConfiguration =
                    self.jwt_processor.extract_claims_unverified(jwt_string)?;

                trust_anchor_config.validate()?;

                // Verify signature using the trust anchor's own keys
                let verified_anchor: EntityConfiguration = self.jwt_processor.verify_jwt_with_jwks(
                    jwt_string,
                    &trust_anchor_config.jwks,
                    JwtArtifactType::EntityStatement,
                )?;

                validated_statements.push(ValidatedEntityStatement::Configuration(verified_anchor));
            } else {
                // Intermediate subordinate statements
                let entity_statement: EntityStatement = self.jwt_processor.extract_claims_unverified(jwt_string)?;

                entity_statement.validate()?;

                // Verify that the subject matches the expected entity
                if let Some(expected_subject) = &current_subject {
                    if &entity_statement.claims.sub != expected_subject {
                        return Err(FederationError::TrustChainValidation(
                            "Trust chain subject mismatch".to_string(),
                        ));
                    }
                } else {
                    return Err(FederationError::TrustChainValidation(
                        "Subordinate statement without expected subject".to_string(),
                    ));
                }

                // For now, we'll store the unverified statement
                // In a full implementation, we'd verify it against the issuer's keys
                // TODO: why cant we verify the signature like the other match arms?
                current_subject = Some(entity_statement.claims.iss.clone());
                validated_statements.push(ValidatedEntityStatement::SubordinateStatement(entity_statement));
            }
        }

        // Additional validation: check that the chain is properly linked
        self.validate_chain_linkage(&validated_statements)?;

        Ok(ValidatedTrustChain {
            leaf_entity_id: self.get_leaf_entity_id(&validated_statements)?,
            trust_anchor_id: self.get_trust_anchor_id(&validated_statements)?,
            statements: validated_statements,
        })
    }

    /// Validate that the trust chain statements are properly linked.
    /// Enforces: leaf configuration at index 0, trust anchor configuration at last index,
    /// only subordinate statements in between.
    fn validate_chain_linkage(&self, statements: &[ValidatedEntityStatement]) -> FederationResult<()> {
        if statements.len() < 2 {
            return Err(FederationError::TrustChainValidation(
                "Trust chain must contain at least 2 statements".to_string(),
            ));
        }

        // First statement must be a configuration (leaf)
        match statements.first() {
            Some(ValidatedEntityStatement::Configuration(_)) => {}
            _ => {
                return Err(FederationError::TrustChainValidation(
                    "First statement in trust chain must be a leaf entity configuration".to_string(),
                ))
            }
        }

        // Last statement must be a configuration (trust anchor)
        match statements.last() {
            Some(ValidatedEntityStatement::Configuration(_)) => {}
            _ => {
                return Err(FederationError::TrustChainValidation(
                    "Last statement in trust chain must be a trust anchor configuration".to_string(),
                ))
            }
        }

        // All intermediate statements must be subordinate statements
        for (i, statement) in statements.iter().enumerate().take(statements.len() - 1).skip(1) {
            match statement {
                ValidatedEntityStatement::SubordinateStatement(_) => {}
                ValidatedEntityStatement::Configuration(_) => {
                    return Err(FederationError::TrustChainValidation(format!(
                        "Entity configuration found at position {} (only leaf and trust anchor allowed)",
                        i
                    )));
                }
            }
        }

        // Verify linkage: next statement's subject must equal current statement's issuer
        for i in 0..(statements.len() - 1) {
            let current_entity_id = match &statements[i] {
                ValidatedEntityStatement::Configuration(config) => &config.claims.sub,
                ValidatedEntityStatement::SubordinateStatement(stmt) => &stmt.claims.iss,
            };

            let next_subject = match &statements[i + 1] {
                ValidatedEntityStatement::SubordinateStatement(next_stmt) => &next_stmt.claims.sub,
                ValidatedEntityStatement::Configuration(next_config) => &next_config.claims.sub,
            };

            if next_subject != current_entity_id {
                return Err(FederationError::TrustChainValidation(
                    "Trust chain is not properly linked".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Get the leaf entity ID from the validated statements.
    /// The leaf must be an entity configuration.
    fn get_leaf_entity_id(&self, statements: &[ValidatedEntityStatement]) -> FederationResult<EntityId> {
        match statements.first() {
            Some(ValidatedEntityStatement::Configuration(config)) => Ok(config.claims.sub.clone()),
            Some(ValidatedEntityStatement::SubordinateStatement(_)) => Err(FederationError::TrustChainValidation(
                "Leaf entity must be an entity configuration, not a subordinate statement".to_string(),
            )),
            None => Err(FederationError::TrustChainValidation("Empty trust chain".to_string())),
        }
    }

    /// Get the trust anchor ID from the validated statements.
    /// The trust anchor must be an entity configuration.
    fn get_trust_anchor_id(&self, statements: &[ValidatedEntityStatement]) -> FederationResult<EntityId> {
        match statements.last() {
            Some(ValidatedEntityStatement::Configuration(config)) => Ok(config.claims.iss.clone()),
            Some(ValidatedEntityStatement::SubordinateStatement(_)) => Err(FederationError::TrustChainValidation(
                "Trust anchor must be an entity configuration, not a subordinate statement".to_string(),
            )),
            None => Err(FederationError::TrustChainValidation("Empty trust chain".to_string())),
        }
    }
}

impl Default for TrustChainValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Validated trust chain with parsed and verified statements.
#[derive(Debug, Clone)]
pub struct ValidatedTrustChain {
    /// Array of validated Entity Statements
    pub statements: Vec<ValidatedEntityStatement>,
    /// The leaf entity ID
    pub leaf_entity_id: EntityId,
    /// The trust anchor ID
    pub trust_anchor_id: EntityId,
}

/// Validated entity statement (either a configuration or a subordinate statement).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ValidatedEntityStatement {
    /// Entity Configuration (self-signed, only at leaf or trust anchor)
    Configuration(EntityConfiguration),
    /// Subordinate Statement (signed by another entity, only between leaf and anchor)
    SubordinateStatement(EntityStatement),
}

impl ValidatedTrustChain {
    /// Get the leaf entity configuration.
    /// Returns an error if the trust chain is malformed (first statement is not a configuration).
    pub fn leaf_entity(&self) -> FederationResult<&EntityConfiguration> {
        match self.statements.first() {
            Some(ValidatedEntityStatement::Configuration(config)) => Ok(config),
            Some(ValidatedEntityStatement::SubordinateStatement(_)) => Err(FederationError::TrustChainValidation(
                "Trust chain corruption: first statement must be a leaf entity configuration".to_string(),
            )),
            None => Err(FederationError::TrustChainValidation(
                "Cannot retrieve leaf entity from empty trust chain".to_string(),
            )),
        }
    }

    /// Get the trust anchor configuration.
    /// Returns an error if the trust chain is malformed (last statement is not a configuration).
    pub fn trust_anchor(&self) -> FederationResult<&EntityConfiguration> {
        match self.statements.last() {
            Some(ValidatedEntityStatement::Configuration(config)) => Ok(config),
            Some(ValidatedEntityStatement::SubordinateStatement(_)) => Err(FederationError::TrustChainValidation(
                "Trust chain corruption: last statement must be a trust anchor configuration".to_string(),
            )),
            None => Err(FederationError::TrustChainValidation(
                "Cannot retrieve trust anchor from empty trust chain".to_string(),
            )),
        }
    }

    /// Get all intermediate subordinate statements.
    /// Returns an error if any intermediate statement is not a subordinate statement (indicating chain corruption).
    pub fn intermediate_statements(&self) -> FederationResult<Vec<&EntityStatement>> {
        let mut intermediates = Vec::new();

        for (i, stmt) in self
            .statements
            .iter()
            .skip(1) // Skip the leaf
            .take(self.statements.len().saturating_sub(2)) // Take all except trust anchor
            .enumerate()
        {
            match stmt {
                ValidatedEntityStatement::SubordinateStatement(s) => intermediates.push(s),
                ValidatedEntityStatement::Configuration(_) => {
                    return Err(FederationError::TrustChainValidation(format!(
                        "Trust chain corruption: entity configuration found at intermediate position {}",
                        i + 1
                    )));
                }
            }
        }

        Ok(intermediates)
    }

    /// Get the final resolved metadata for the leaf entity.
    ///
    /// Reference: OpenID Federation 1.0 - Section 4.3 Metadata Resolution
    /// https://openid.net/specs/openid-federation-1_0.html#name-metadata-resolution
    pub fn resolve_metadata(&self) -> FederationResult<crate::EntityMetadata> {
        // Start with the leaf entity's metadata
        let leaf_config = self.leaf_entity()?;
        let mut final_metadata = leaf_config.metadata.clone().unwrap_or_default();

        // Apply metadata policies from each subordinate statement in the chain
        for statement in self.intermediate_statements()? {
            if let Some(metadata_policy) = &statement.metadata_policy {
                // Apply metadata policy to the final metadata
                // This is a simplified implementation - a full implementation
                // would properly apply all policy language operators
                self.apply_metadata_policy(&mut final_metadata, metadata_policy)?;
            }
        }

        Ok(final_metadata)
    }

    /// Apply a metadata policy to the metadata (simplified implementation).
    fn apply_metadata_policy(
        &self,
        _metadata: &mut crate::EntityMetadata,
        _policy: &std::collections::HashMap<String, std::collections::HashMap<String, crate::PolicyLanguage>>,
    ) -> FederationResult<()> {
        // TODO: Implement full metadata policy application logic
        // This would involve applying each policy operator (essential, default, one_of, etc.)
        // to the corresponding metadata fields
        Ok(())
    }
}

/// Trust Chain Resolver for the Pull method.
///
/// This struct implements dynamic trust chain resolution as defined in OpenID Federation 1.0.
/// Starting with only an entity ID, it fetches configurations and statements from public
/// endpoints to build a complete trust chain up to a known trust anchor.
///
/// Reference: OpenID Federation 1.0 - Section 4.1 Trust Chain Resolution
/// https://openid.net/specs/openid-federation-1_0.html#name-trust-chain-resolution
pub struct TrustChainResolver {
    http_client: FederationClient,
    jwt_processor: JwtProcessor,
    /// Set of known trust anchor entity IDs that are already trusted
    /// Maps entity_id -> (EntityConfiguration, JWT string)
    trusted_anchors: HashMap<EntityId, (EntityConfiguration, String)>,
}

impl TrustChainResolver {
    /// Create a new trust chain resolver.
    pub fn new() -> Self {
        Self {
            http_client: FederationClient::new(),
            jwt_processor: JwtProcessor::new(),
            trusted_anchors: HashMap::new(),
        }
    }

    /// Add a known trusted anchor with its JWT representation.
    pub fn add_trusted_anchor(&mut self, anchor_config: EntityConfiguration, anchor_jwt: String) {
        self.trusted_anchors
            .insert(anchor_config.claims.iss.clone(), (anchor_config, anchor_jwt));
    }

    /// Resolve a trust chain for an entity starting from its entity ID.
    ///
    /// This implements the Pull method: given an entity ID (URL), this method:
    /// 1. Fetches the entity's configuration from `/.well-known/openid-federation`
    /// 2. Extracts `authority_hints` from each entity configuration to find superior entities
    /// 3. For each authority, fetches its configuration and `federation_fetch_endpoint`
    /// 4. Queries the endpoint to get subordinate statements
    /// 5. Continues up the chain until reaching a known trust anchor
    ///
    /// # Arguments
    /// * `entity_id` - The entity ID (URL) to resolve the trust chain for
    ///
    /// # Returns
    /// A validated trust chain if resolution succeeds
    pub async fn resolve_trust_chain(&self, entity_id: &EntityId) -> FederationResult<ValidatedTrustChain> {
        // Vec<TrustAnchorId>
        // Step 1: Fetch the target entity's configuration
        let leaf_jwt = self.http_client.fetch_entity_configuration(entity_id).await?;
        let leaf_config: EntityConfiguration = self.jwt_processor.extract_claims_unverified(&leaf_jwt)?;

        // Step 2: Initialize chain with the leaf entity's configuration JWT
        let mut chain_jws = vec![leaf_jwt];

        // Step 3: Get authority hints from the leaf configuration
        let authority_hints = leaf_config.authority_hints.as_ref().ok_or_else(|| {
            FederationError::EntityResolution("No authority hints found in leaf entity configuration".to_string())
        })?;

        if authority_hints.is_empty() {
            return Err(FederationError::EntityResolution(
                "Authority hints cannot be empty".to_string(),
            ));
        }

        // Step 4: Build the chain upward
        let mut current_subject = entity_id.clone();
        let mut current_authorities = authority_hints.clone();

        loop {
            // Check if any of the current authorities is a known trust anchor
            let mut found_anchor = false;

            for authority_id in &current_authorities {
                if let Some((_anchor_config, anchor_jwt)) = self.trusted_anchors.get(authority_id) {
                    // Found a known anchor - add it to chain and finish
                    chain_jws.push(anchor_jwt.clone());
                    found_anchor = true;
                    break;
                }
            }

            if found_anchor {
                break;
            }

            // None of the current authorities is a known anchor, so we need to fetch subordinate statements
            if current_authorities.len() != 1 {
                return Err(FederationError::EntityResolution(
                    "Expected exactly one authority at this level (or a known anchor)".to_string(),
                ));
            }

            let authority_id = current_authorities.first().unwrap().clone();

            // Fetch the authority's configuration
            let authority_jwt = self.http_client.fetch_entity_configuration(&authority_id).await?;
            let authority_config: EntityConfiguration = self.jwt_processor.extract_claims_unverified(&authority_jwt)?;

            // The next hop must come from the authority's configuration, not from the subordinate statement.
            current_authorities = authority_config
                .authority_hints
                .as_ref()
                .ok_or_else(|| {
                    FederationError::EntityResolution(format!(
                        "No authority hints found in authority configuration for {}",
                        authority_id
                    ))
                })?
                .clone();

            if current_authorities.is_empty() {
                return Err(FederationError::EntityResolution(
                    "Authority hints cannot be empty in authority configuration".to_string(),
                ));
            }

            // Get the federation_fetch_endpoint from the authority's metadata
            let federation_fetch_endpoint = authority_config
                .metadata
                .as_ref()
                .and_then(|m| m.federation_entity.as_ref())
                .and_then(|fe| fe.federation_fetch_endpoint.clone())
                .ok_or_else(|| {
                    FederationError::EntityResolution(format!(
                        "Authority {} does not have a federation_fetch_endpoint",
                        authority_id
                    ))
                })?;

            // Fetch the subordinate statement for the current subject
            let subordinate_statement_jwt = self
                .http_client
                .fetch_subordinate_statement(&federation_fetch_endpoint, &current_subject)
                .await?;

            let subordinate_statement: EntityStatement = self
                .jwt_processor
                .extract_claims_unverified(&subordinate_statement_jwt)?;

            // Validate the subordinate statement
            subordinate_statement.validate()?;

            // Add to chain
            chain_jws.push(subordinate_statement_jwt);

            // Move up: the issuer of this statement becomes the current subject for the next iteration
            current_subject = subordinate_statement.claims.iss.clone();
        }

        // Step 5: Validate the complete trust chain
        let trust_chain = TrustChain::new(chain_jws);
        let validator = TrustChainValidator::new();
        validator.validate_trust_chain(&trust_chain)
    }
}

impl Default for TrustChainResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustChain {
    /// Create a new trust chain.
    pub fn new(chain: Vec<String>) -> Self {
        Self {
            chain,
            metadata: None,
            trust_marks: None,
        }
    }

    /// Add a JWT to the trust chain.
    pub fn add_jwt(&mut self, jwt: String) {
        self.chain.push(jwt);
    }

    /// Get the number of statements in the chain.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
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
            homepage_uri: None,
            policy_uri: None,
            logo_uri: None,
            contacts: None,
            federation_fetch_endpoint: Some(fetch_endpoint),
            federation_list_endpoint: None,
            federation_resolve_endpoint: None,
            federation_trust_mark_status_endpoint: None,
            federation_historical_keys_endpoint: None,
        });
        metadata
    }

    fn build_entity_configuration(
        entity_id: &Url,
        authority_hints: Option<Vec<Url>>,
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

    fn build_subordinate_statement(issuer: &Url, subject: &Url) -> EntityStatement {
        EntityStatement::new(
            issuer.clone(),
            subject.clone(),
            future_expiration(),
            chrono::Utc::now().timestamp(),
        )
        .with_jwks(test_jwk_set())
    }

    fn build_fetch_endpoint(entity_id: &Url) -> Url {
        let mut endpoint = entity_id.clone();
        endpoint.set_path("/fetch");
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

    fn encode_entity_statement(statement: &EntityStatement) -> String {
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

    async fn mock_subordinate_statement(server: &MockServer, subject: &Url, jwt: String) {
        Mock::given(method("GET"))
            .and(path("/fetch"))
            .and(query_param("sub", subject.as_str()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(jwt)
                    .insert_header("content-type", "application/entity-statement+jwt"),
            )
            .mount(server)
            .await;
    }

    // TODO: something is def still wrong since this test doesnt add an entity config for the trust anchor, neither does it fetch it, but this absolutely mandatory by the spec, or not?
    #[tokio::test]
    async fn resolve_trust_chain_with_two_intermediates() {
        let leaf_server = MockServer::start().await;
        let intermediate_one_server = MockServer::start().await;
        let intermediate_two_server = MockServer::start().await;
        let trust_anchor_server = MockServer::start().await;

        let leaf_url = Url::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let intermediate_one_url = Url::parse(&format!("http://{}", intermediate_one_server.address())).unwrap();
        let intermediate_two_url = Url::parse(&format!("http://{}", intermediate_two_server.address())).unwrap();
        let trust_anchor_url = Url::parse(&format!("http://{}", trust_anchor_server.address())).unwrap();

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

        let mut resolver = TrustChainResolver::new();
        resolver.add_trusted_anchor(
            trust_anchor_config.clone(),
            encode_entity_configuration(&trust_anchor_config),
        );

        let fed_client = FederationClient::new();

        let validated_trustchain = fed_client
            .discover_trust_chain(&leaf_url, &[trust_anchor_url])
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
            let statement = extract_claims_unverified::<EntityStatement>(statement).unwrap();
            assert_ne!(statement.claims.sub, statement.claims.iss);
        }
        let anchor = extract_claims_unverified::<EntityConfiguration>(&validated_trustchain.chain[4]).unwrap();
        assert_eq!(anchor.claims.sub, anchor.claims.iss);
        for statement in &validated_trustchain.chain {
            let statement = extract_claims_unverified::<ValidatedEntityStatement>(statement).unwrap();
            match statement {
                ValidatedEntityStatement::Configuration(config) => {
                    assert!(!config.jwks.keys.is_empty(), "Configuration must have non-empty JWKS");
                }
                ValidatedEntityStatement::SubordinateStatement(statement) => {
                    assert!(
                        statement.jwks.is_some() && !statement.jwks.unwrap().keys.is_empty(),
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

        let leaf_url = Url::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let trust_anchor_url = Url::parse(&format!("http://{}", trust_anchor_server.address())).unwrap();

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
            .discover_trust_chain(&leaf_url, &[trust_anchor_url])
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
        let statement = extract_claims_unverified::<EntityStatement>(&validated_trustchain.chain[1]).unwrap();
        assert_ne!(statement.claims.sub, statement.claims.iss);
        let anchor = extract_claims_unverified::<EntityConfiguration>(&validated_trustchain.chain[2]).unwrap();
        assert_eq!(anchor.claims.sub, anchor.claims.iss);
        for statement in &validated_trustchain.chain {
            let statement = extract_claims_unverified::<ValidatedEntityStatement>(statement).unwrap();
            match statement {
                ValidatedEntityStatement::Configuration(config) => {
                    assert!(!config.jwks.keys.is_empty(), "Configuration must have non-empty JWKS");
                }
                ValidatedEntityStatement::SubordinateStatement(statement) => {
                    assert!(
                        statement.jwks.is_some() && !statement.jwks.unwrap().keys.is_empty(),
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

        let leaf_url = Url::parse(&format!("http://{}", leaf_server.address())).unwrap();
        let intermediate_url = Url::parse(&format!("http://{}", intermediate_server.address())).unwrap();
        let trust_anchor_url = Url::parse(&format!("http://{}", trust_anchor_server.address())).unwrap();

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
        let wrong_subject = Url::parse("https://wrong.example.test").unwrap();
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
            .discover_trust_chain(&leaf_url, &[trust_anchor_url])
            .await
            .unwrap_err();

        println!("error === {:?}", err); // TODO:

        match err {
            FederationError::EntityResolution(message) => {
                assert!(message.contains("No superior for"));
            }
            other => panic!("expected EntityResolution error, got: {:?}", other),
        }
    }
}
