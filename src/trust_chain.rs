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
/// https://openid.net/specs/openid-federation-1_0.html#name-trust-chains
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
    /// Reference: OpenID Federation 1.0 - Section 4.2 Trust Chain Validation
    /// https://openid.net/specs/openid-federation-1_0.html#name-trust-chain-validation
    pub fn try_new(trust_chain: Vec<String>) -> FederationResult<Self> {
        let chain_len = trust_chain.len();

        if chain_len < 2 {
            return Err(FederationError::TrustChainValidation(
                "Trust chain must contain at least 2 statements".to_string(),
            ));
        }

        let jwt_processor = JwtProcessor::new();
        let mut validated_statements = Vec::with_capacity(chain_len);

        // First element must be a self-signed leaf entity configuration.
        let leaf_jwt = &trust_chain[0];
        let leaf_config: EntityConfiguration = extract_claims_unverified(leaf_jwt)?;
        leaf_config.validate()?;
        let verified_leaf: EntityConfiguration =
            jwt_processor.verify_jwt_with_jwks(leaf_jwt, &leaf_config.jwks, JwtArtifactType::EntityStatement)?;

        let mut current_subject = verified_leaf.claims.sub.clone();
        validated_statements.push(EntityStatement::Configuration(verified_leaf));

        // Intermediate statements must all be subordinate statements and link correctly.
        for jwt_string in trust_chain.iter().skip(1).take(chain_len - 2) {
            let statement: SubordinateStatement = extract_claims_unverified(jwt_string)?;
            statement.validate()?;

            if statement.claims.sub != current_subject {
                return Err(FederationError::TrustChainValidation(
                    "Trust chain subject mismatch".to_string(),
                ));
            }

            current_subject = statement.claims.iss.clone();
            validated_statements.push(EntityStatement::SubordinateStatement(statement));
        }

        // Last element must be the trust anchor configuration and link to previous issuer.
        let anchor_jwt = &trust_chain[chain_len - 1];
        let anchor_config: EntityConfiguration = extract_claims_unverified(anchor_jwt)?;
        anchor_config.validate()?;
        let verified_anchor: EntityConfiguration =
            jwt_processor.verify_jwt_with_jwks(anchor_jwt, &anchor_config.jwks, JwtArtifactType::EntityStatement)?;

        if verified_anchor.claims.sub != current_subject {
            return Err(FederationError::TrustChainValidation(
                "Trust chain is not properly linked".to_string(),
            ));
        }

        validated_statements.push(EntityStatement::Configuration(verified_anchor));

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
    use crate::{extract_claims_unverified, test_helpers::*, FederationClient};

    use super::*;
    use url::Url;
    use wiremock::MockServer;

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
}
