//! JWT utilities for OpenID Federation.

use crate::jwk::JwkSet;
use crate::{EntityId, FederationError, FederationResult};
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT Header with federation-specific extensions.
///
/// Reference: OpenID Federation 1.0 - Section 3.1.3 Entity Statement Format
/// https://openid.net/specs/openid-federation-1_0.html#name-entity-statement-format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationJwtHeader {
    /// Algorithm
    pub alg: String,
    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// JWT type for federation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jtyp: Option<String>,
}

/// Standard JWT claims for OpenID Federation.
///
/// Reference: OpenID Federation 1.0 - Section 3.1.4 Entity Statement Claims
/// https://openid.net/specs/openid-federation-1_0.html#name-entity-statement-claims
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer
    pub iss: EntityId,
    /// Subject
    pub sub: EntityId,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>, // Can be string or array of strings
    /// Expiration timestamp
    pub exp: DateTime<Utc>,
    /// Not before timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<DateTime<Utc>>,
    /// Issued at timestamp
    pub iat: DateTime<Utc>,
    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Additional claims
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// JWT utilities for federation operations.
pub struct JwtProcessor {
    /// Default validation settings
    validation: Validation,
}

impl JwtProcessor {
    /// Create a new JWT processor with default validation settings.
    pub fn new() -> Self {
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 60; // 60 seconds leeway for clock skew

        Self { validation }
    }

    /// Create a JWT processor with custom validation settings.
    pub fn with_validation(validation: Validation) -> Self {
        Self { validation }
    }

    /// Sign a JWT with the given claims and key.
    pub fn sign_jwt<T: Serialize>(
        &self,
        claims: &T,
        key: &EncodingKey,
        algorithm: Algorithm,
        kid: Option<String>,
    ) -> FederationResult<String> {
        let mut header = Header::new(algorithm);
        header.kid = kid;
        header.typ = Some("JWT".to_string());

        encode(&header, claims, key).map_err(FederationError::from)
    }

    /// Verify and decode a JWT using a specific key.
    pub fn verify_jwt<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        key: &DecodingKey,
        algorithm: Algorithm,
    ) -> FederationResult<T> {
        let mut validation = self.validation.clone();
        validation.algorithms = vec![algorithm];

        decode::<T>(token, key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(FederationError::from)
    }

    /// Verify and decode a JWT using a JWK Set (tries all suitable keys).
    pub fn verify_jwt_with_jwks<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        jwks: &JwkSet,
    ) -> FederationResult<T> {
        // Parse the header to get the key ID and algorithm
        let header = jsonwebtoken::decode_header(token)?;

        let algorithm = header.alg;

        // Try to find the key by kid if present
        if let Some(kid) = &header.kid {
            if let Some(jwk) = jwks.find_key(kid) {
                let decoding_key = jwk.to_decoding_key()?;
                return self.verify_jwt(token, &decoding_key, algorithm);
            }
        }

        // If no kid or key not found, try all signature keys
        let signature_keys = jwks.signature_keys();
        for jwk in signature_keys {
            if let Ok(decoding_key) = jwk.to_decoding_key() {
                if let Ok(claims) = self.verify_jwt(token, &decoding_key, algorithm) {
                    return Ok(claims);
                }
            }
        }

        Err(FederationError::InvalidEntityStatement(
            "No suitable key found for JWT verification".to_string(),
        ))
    }

    /// Extract claims from a JWT without verification (for inspection purposes only).
    pub fn extract_claims_unverified<T: for<'de> Deserialize<'de>>(&self, token: &str) -> FederationResult<T> {
        let mut validation = Validation::default();
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        validation.validate_nbf = false;

        decode::<T>(token, &DecodingKey::from_secret(&[]), &validation)
            .map(|token_data| token_data.claims)
            .map_err(FederationError::from)
    }
}

impl Default for JwtProcessor {
    fn default() -> Self {
        Self::new()
    }
}
