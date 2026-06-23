//! JWT utilities for OpenID Federation.

use crate::jwk::JwkSet;
use crate::{EntityId, FederationError, FederationResult};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWT artifact type for OpenID Federation.
///
/// Reference: OpenID Federation 1.0 - Section 3 (various subsections)
/// Each JWT in Federation MUST have a specific `typ` header to prevent JWT confusion attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtArtifactType {
    /// Entity Statement: `typ: "entity-statement+jwt"`
    /// Reference: Section 3.2, Step 1-3
    EntityStatement,
    /// Trust Mark: `typ: "trust-mark+jwt"`
    /// Reference: Section 7.3, Step 2
    TrustMark,
    /// Resolve Response: `typ: "resolve-response+jwt"`
    /// Reference: Section 8.3.2
    ResolveResponse,
    /// Explicit Registration Response: `typ: "explicit-registration-response+jwt"`
    /// Reference: Section 12.2.3
    ExplicitRegistrationResponse,
    /// Signed JWK Set Response: `typ: "jwk-set+jwt"`
    /// Reference: Section 15.6
    SignedJwkSet,
    /// Trust Mark Delegation: `typ: "trust-mark-delegation+jwt"`
    /// Reference: Section 15.5
    TrustMarkDelegation,
    /// Trust Mark Status Response: `typ: "trust-mark-status-response+jwt"`
    /// Reference: Section 15.7
    TrustMarkStatusResponse,
}

impl JwtArtifactType {
    /// Get the REQUIRED `typ` header value for this artifact type.
    pub fn header_value(&self) -> &str {
        match self {
            JwtArtifactType::EntityStatement => "entity-statement+jwt",
            JwtArtifactType::TrustMark => "trust-mark+jwt",
            JwtArtifactType::ResolveResponse => "resolve-response+jwt",
            JwtArtifactType::ExplicitRegistrationResponse => "explicit-registration-response+jwt",
            JwtArtifactType::SignedJwkSet => "jwk-set+jwt",
            JwtArtifactType::TrustMarkDelegation => "trust-mark-delegation+jwt",
            JwtArtifactType::TrustMarkStatusResponse => "trust-mark-status-response+jwt",
        }
    }

    /// Validate that a JWT header has the correct `typ` for this artifact type.
    ///
    /// Per RFC 7519, the `typ` claim is used to declare a media type of the JWT.
    /// OpenID Federation extends this to prevent JWT confusion attacks by requiring
    /// specific media types for each artifact.
    ///
    /// # Arguments
    /// * `header_typ` - The value from the JWT header's `typ` claim (may be None)
    ///
    /// # Returns
    /// * `Ok(())` if the `typ` matches this artifact type
    /// * `Err(FederationError)` if the `typ` is missing or does not match
    pub fn validate_header_typ(&self, header_typ: Option<&str>) -> FederationResult<()> {
        let expected = self.header_value();
        match header_typ {
            None => Err(FederationError::InvalidEntityStatement(format!(
                "JWT header missing required 'typ' claim (expected: {})",
                expected
            ))),
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(FederationError::InvalidEntityStatement(format!(
                "JWT 'typ' mismatch: expected '{}', got '{}'",
                expected, actual
            ))),
        }
    }
}

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
    /// Expiration timestamp (seconds since Unix epoch, per RFC 7519 §4.1.4)
    pub exp: i64,
    /// Not before timestamp (seconds since Unix epoch, per RFC 7519 §4.1.5)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued at timestamp (seconds since Unix epoch, per RFC 7519 §4.1.6)
    pub iat: i64,
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
    ///
    /// This method enforces the correct `typ` header for the given artifact type,
    /// as required by OpenID Federation 1.0 to prevent JWT confusion attacks.
    ///
    /// # Arguments
    /// * `claims` - The JWT claims to encode
    /// * `key` - The signing key
    /// * `algorithm` - The signing algorithm
    /// * `artifact_type` - The federation artifact type (determines required `typ` header)
    /// * `kid` - Optional key ID header parameter
    ///
    /// # Returns
    /// A signed JWT string with correct `typ` header, or error if signing fails
    pub fn sign_jwt<T: Serialize>(
        &self,
        claims: &T,
        key: &EncodingKey,
        algorithm: Algorithm,
        artifact_type: JwtArtifactType,
        kid: Option<String>,
    ) -> FederationResult<String> {
        let mut header = Header::new(algorithm);
        header.kid = kid;
        // Set the federation-specific typ header (not the generic "JWT" value)
        header.typ = Some(artifact_type.header_value().to_string());

        encode(&header, claims, key).map_err(FederationError::from)
    }

    /// Verify and decode a JWT using a specific key, enforcing artifact type.
    ///
    /// This method validates that the JWT has the correct `typ` header for the
    /// specified artifact type, preventing JWT confusion attacks.
    ///
    /// # Arguments
    /// * `token` - The JWT string to verify
    /// * `key` - The decoding key
    /// * `algorithm` - The expected signing algorithm
    /// * `artifact_type` - The expected federation artifact type
    ///
    /// # Returns
    /// The decoded claims if verification and typ validation succeed
    pub fn verify_jwt<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        key: &DecodingKey,
        algorithm: Algorithm,
        artifact_type: JwtArtifactType,
    ) -> FederationResult<T> {
        // First validate the typ header before decoding
        let header = jsonwebtoken::decode_header(token)?;
        artifact_type.validate_header_typ(header.typ.as_deref())?;

        let mut validation = self.validation.clone();
        validation.algorithms = vec![algorithm];

        decode::<T>(token, key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(FederationError::from)
    }

    /// Verify and decode a JWT using a JWK Set, enforcing artifact type.
    ///
    /// This method tries all suitable keys in the JWK Set to verify the JWT,
    /// while validating the correct `typ` header for the artifact type.
    ///
    /// # Arguments
    /// * `token` - The JWT string to verify
    /// * `jwks` - The JWK Set containing candidate keys
    /// * `artifact_type` - The expected federation artifact type
    ///
    /// # Returns
    /// The decoded claims if verification succeeds, or error if no suitable key found
    pub fn verify_jwt_with_jwks<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        jwks: &JwkSet,
        artifact_type: JwtArtifactType,
    ) -> FederationResult<T> {
        // First validate the typ header before attempting key verification
        let header = jsonwebtoken::decode_header(token)?;
        artifact_type.validate_header_typ(header.typ.as_deref())?;

        let algorithm = header.alg;

        // Try to find the key by kid if present
        if let Some(kid) = &header.kid {
            if let Some(jwk) = jwks.find_key(kid) {
                let decoding_key = jwk.to_decoding_key()?;
                return self.verify_jwt(token, &decoding_key, algorithm, artifact_type);
            }
        }

        // If no kid or key not found, try all signature keys // TODO: is this desired behavior? especially an incorrect KID would probably rather just fail no?
        let signature_keys = jwks.signature_keys();
        for jwk in signature_keys {
            if let Ok(decoding_key) = jwk.to_decoding_key() {
                if let Ok(claims) = self.verify_jwt(token, &decoding_key, algorithm, artifact_type) {
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

/// Extract claims from a JWT without verification (for inspection purposes only).
pub fn extract_claims_unverified<T: for<'de> Deserialize<'de>>(token: &str) -> FederationResult<T> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_nbf = false;

    decode::<T>(token, &DecodingKey::from_secret(&[]), &validation)
        .map(|token_data| token_data.claims)
        .map_err(FederationError::from)
}

impl Default for JwtProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        iss: String,
        sub: String,
        iat: i64,
        exp: i64,
    }

    fn create_test_claims() -> TestClaims {
        let now = chrono::Utc::now().timestamp();
        TestClaims {
            iss: "https://example.com".to_string(),
            sub: "https://example.com".to_string(),
            iat: now,
            exp: now + 3600,
        }
    }

    fn create_test_key() -> (EncodingKey, String) {
        let secret = "your-256-bit-secret-key-here-minimum-32-bytes!!!!";
        let key = EncodingKey::from_secret(secret.as_bytes());
        (key, secret.to_string())
    }

    #[test]
    fn test_jwt_artifact_type_header_values() {
        assert_eq!(JwtArtifactType::EntityStatement.header_value(), "entity-statement+jwt");
        assert_eq!(JwtArtifactType::TrustMark.header_value(), "trust-mark+jwt");
        assert_eq!(JwtArtifactType::ResolveResponse.header_value(), "resolve-response+jwt");
        assert_eq!(
            JwtArtifactType::ExplicitRegistrationResponse.header_value(),
            "explicit-registration-response+jwt"
        );
        assert_eq!(JwtArtifactType::SignedJwkSet.header_value(), "jwk-set+jwt");
        assert_eq!(
            JwtArtifactType::TrustMarkDelegation.header_value(),
            "trust-mark-delegation+jwt"
        );
        assert_eq!(
            JwtArtifactType::TrustMarkStatusResponse.header_value(),
            "trust-mark-status-response+jwt"
        );
    }

    #[test]
    fn test_validate_header_typ_valid() {
        let artifact_type = JwtArtifactType::EntityStatement;
        assert!(artifact_type.validate_header_typ(Some("entity-statement+jwt")).is_ok());
    }

    #[test]
    fn test_validate_header_typ_missing() {
        let artifact_type = JwtArtifactType::EntityStatement;
        let result = artifact_type.validate_header_typ(None);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("missing required 'typ'"));
    }

    #[test]
    fn test_validate_header_typ_wrong() {
        let artifact_type = JwtArtifactType::EntityStatement;
        let result = artifact_type.validate_header_typ(Some("trust-mark+jwt"));
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("typ' mismatch"));
        assert!(err_msg.contains("entity-statement+jwt"));
        assert!(err_msg.contains("trust-mark+jwt"));
    }

    #[test]
    fn test_sign_jwt_with_correct_typ() {
        let processor = JwtProcessor::new();
        let claims = create_test_claims();
        let (key, _) = create_test_key();

        let token = processor
            .sign_jwt(&claims, &key, Algorithm::HS256, JwtArtifactType::EntityStatement, None)
            .expect("Should sign JWT");

        // Extract header to verify typ
        let header = jsonwebtoken::decode_header(&token).expect("Should decode header");
        assert_eq!(header.typ, Some("entity-statement+jwt".to_string()));
    }

    #[test]
    fn test_sign_different_artifact_types_have_different_typ() {
        let processor = JwtProcessor::new();
        let claims = create_test_claims();
        let (key, _) = create_test_key();

        let entity_statement_token = processor
            .sign_jwt(&claims, &key, Algorithm::HS256, JwtArtifactType::EntityStatement, None)
            .expect("Should sign JWT");

        let trust_mark_token = processor
            .sign_jwt(&claims, &key, Algorithm::HS256, JwtArtifactType::TrustMark, None)
            .expect("Should sign JWT");

        let entity_stmt_header = jsonwebtoken::decode_header(&entity_statement_token).unwrap();
        let trust_mark_header = jsonwebtoken::decode_header(&trust_mark_token).unwrap();

        assert_ne!(entity_stmt_header.typ, trust_mark_header.typ);
        assert_eq!(entity_stmt_header.typ, Some("entity-statement+jwt".to_string()));
        assert_eq!(trust_mark_header.typ, Some("trust-mark+jwt".to_string()));
    }

    #[test]
    fn test_verify_jwt_wrong_typ_rejected() {
        let processor = JwtProcessor::new();
        let claims = create_test_claims();
        let (key, secret) = create_test_key();

        // Sign as Entity Statement
        let token = processor
            .sign_jwt(&claims, &key, Algorithm::HS256, JwtArtifactType::EntityStatement, None)
            .expect("Should sign JWT");

        // Try to verify as Trust Mark (wrong type)
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        let result: Result<TestClaims, _> = processor.verify_jwt(
            &token,
            &decoding_key,
            Algorithm::HS256,
            JwtArtifactType::TrustMark, // Wrong type
        );

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("typ' mismatch") || err_msg.contains("expected: 'trust-mark+jwt'"));
    }

    #[test]
    fn test_verify_jwt_correct_typ_accepted() {
        let processor = JwtProcessor::new();
        let claims = create_test_claims();
        let (key, secret) = create_test_key();

        // Sign as Entity Statement
        let token = processor
            .sign_jwt(&claims, &key, Algorithm::HS256, JwtArtifactType::EntityStatement, None)
            .expect("Should sign JWT");

        // Verify as Entity Statement (correct type)
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        let result: Result<TestClaims, _> = processor.verify_jwt(
            &token,
            &decoding_key,
            Algorithm::HS256,
            JwtArtifactType::EntityStatement, // Correct type
        );

        assert!(result.is_ok());
        let verified_claims = result.unwrap();
        assert_eq!(verified_claims.iss, "https://example.com");
    }

    #[test]
    fn test_verify_all_artifact_types_with_correct_typ() {
        let processor = JwtProcessor::new();
        let claims = create_test_claims();
        let (key, secret) = create_test_key();
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let artifact_types = vec![
            JwtArtifactType::EntityStatement,
            JwtArtifactType::TrustMark,
            JwtArtifactType::ResolveResponse,
            JwtArtifactType::ExplicitRegistrationResponse,
            JwtArtifactType::SignedJwkSet,
            JwtArtifactType::TrustMarkDelegation,
            JwtArtifactType::TrustMarkStatusResponse,
        ];

        for artifact_type in artifact_types {
            let token = processor
                .sign_jwt(&claims, &key, Algorithm::HS256, artifact_type, None)
                .expect("Should sign JWT");

            let result: Result<TestClaims, _> =
                processor.verify_jwt(&token, &decoding_key, Algorithm::HS256, artifact_type);

            assert!(result.is_ok(), "Failed to verify {:?}", artifact_type);
            let verified = result.unwrap();
            assert_eq!(verified.iss, "https://example.com");
        }
    }

    #[test]
    fn test_jwt_confusion_attack_prevention() {
        // Demonstrates prevention of JWT confusion attacks:
        // A JWT signed as EntityStatement cannot be accepted as a TrustMark
        let processor = JwtProcessor::new();
        let claims = create_test_claims();
        let (key, secret) = create_test_key();

        let entity_stmt_token = processor
            .sign_jwt(&claims, &key, Algorithm::HS256, JwtArtifactType::EntityStatement, None)
            .expect("Should sign JWT");

        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        // Attempt 1: Verify as correct type (should succeed)
        let result1: Result<TestClaims, _> = processor.verify_jwt(
            &entity_stmt_token,
            &decoding_key,
            Algorithm::HS256,
            JwtArtifactType::EntityStatement,
        );
        assert!(result1.is_ok());

        // Attempt 2: Verify as wrong type (should fail)
        let result2: Result<TestClaims, _> = processor.verify_jwt(
            &entity_stmt_token,
            &decoding_key,
            Algorithm::HS256,
            JwtArtifactType::TrustMark,
        );
        assert!(result2.is_err());

        // Attempt 3: Verify as another wrong type (should fail)
        let result3: Result<TestClaims, _> = processor.verify_jwt(
            &entity_stmt_token,
            &decoding_key,
            Algorithm::HS256,
            JwtArtifactType::ResolveResponse,
        );
        assert!(result3.is_err());
    }

    #[test]
    fn test_kid_preserved_in_signed_jwt() {
        let processor = JwtProcessor::new();
        let claims = create_test_claims();
        let (key, _) = create_test_key();

        let token = processor
            .sign_jwt(
                &claims,
                &key,
                Algorithm::HS256,
                JwtArtifactType::EntityStatement,
                Some("my-key-id".to_string()),
            )
            .expect("Should sign JWT");

        let header = jsonwebtoken::decode_header(&token).expect("Should decode header");
        assert_eq!(header.kid, Some("my-key-id".to_string()));
        assert_eq!(header.typ, Some("entity-statement+jwt".to_string()));
    }
}
