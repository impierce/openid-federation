//! JWT utilities for OpenID Federation.

use crate::jwk::JwkSet;
use crate::{EntityId, FederationError, FederationResult, SignError};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, encode, Algorithm, AlgorithmFamily, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

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
            None => Err(FederationError::InvalidJwtHeaderTyp(format!(
                "JWT header missing required 'typ' claim (expected: {})",
                expected
            ))),
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(FederationError::InvalidJwtHeaderTyp(format!(
                "JWT 'typ' mismatch: expected '{}', got '{}'",
                expected, actual
            ))),
        }
    }
}

/// JWT Header with federation-specific extensions.
///
/// Reference: OpenID Federation 1.0 - Section 3.1.3 Entity Statement Format
/// <https://openid.net/specs/openid-federation-1_0.html#name-entity-statement-format>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationJwtHeader {
    // TODO: I think the KID and TYP fields are not optional
    pub alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jtyp: Option<String>,
}

/// Standard JWT claims for OpenID Federation.
///
/// Reference: OpenID Federation 1.0 - Section 3.1.4 Entity Statement Claims
/// <https://openid.net/specs/openid-federation-1_0.html#name-entity-statement-claims>
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
    #[serde(deserialize_with = "numeric_date::deserialize")]
    pub exp: i64,
    /// Not before timestamp (seconds since Unix epoch, per RFC 7519 §4.1.5)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "numeric_date::deserialize_option"
    )]
    pub nbf: Option<i64>,
    /// Issued at timestamp (seconds since Unix epoch, per RFC 7519 §4.1.6)
    #[serde(deserialize_with = "numeric_date::deserialize")]
    pub iat: i64,
    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Additional claims
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// Deserialization of a NumericDate, which RFC 7519 §2 defines as any JSON number of seconds:
/// "non-integer values can be represented". Some implementations send `1.7E9`, so a
/// non-integer is accepted and rounded to whole seconds, as `jsonwebtoken` does when validating.
///
/// Read through [`serde_json::Number`], which also understands how numbers are buffered inside
/// `#[serde(flatten)]` when `serde_json`'s `arbitrary_precision` feature is enabled.
///
/// Reference: <https://www.rfc-editor.org/rfc/rfc7519#section-2>
mod numeric_date {
    use serde::{de, Deserialize, Deserializer};

    /// A NumericDate wrapper, so an optional claim can reuse the conversion.
    struct NumericDate(i64);

    impl<'de> Deserialize<'de> for NumericDate {
        /// Read any JSON number, rounding a non-integer to whole seconds.
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let number = serde_json::Number::deserialize(deserializer)?;
            if let Some(seconds) = number.as_i64() {
                return Ok(NumericDate(seconds));
            }
            number
                .as_f64()
                .map(f64::round)
                .filter(|seconds| seconds.is_finite() && *seconds >= i64::MIN as f64 && *seconds < i64::MAX as f64)
                .map(|seconds| NumericDate(seconds as i64))
                .ok_or_else(|| de::Error::custom(format!("NumericDate {number} is out of range")))
        }
    }

    /// Deserialize a required NumericDate claim, for `#[serde(deserialize_with)]`.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
        NumericDate::deserialize(deserializer).map(|date| date.0)
    }

    /// Deserialize an optional NumericDate claim, for `#[serde(deserialize_with)]`.
    pub(super) fn deserialize_option<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
        Ok(Option::<NumericDate>::deserialize(deserializer)?.map(|date| date.0))
    }
}

/// The time claims of a JWT, read as NumericDates.
#[derive(Deserialize)]
struct TimeClaims {
    #[serde(default, deserialize_with = "numeric_date::deserialize_option")]
    exp: Option<i64>,
    #[serde(default, deserialize_with = "numeric_date::deserialize_option")]
    nbf: Option<i64>,
}

impl TimeClaims {
    /// Applies `validation`'s time checks the way `jsonwebtoken` does, including its leeway.
    fn validate(&self, validation: &Validation) -> FederationResult<()> {
        use jsonwebtoken::errors::{Error, ErrorKind};

        let now = chrono::Utc::now().timestamp();
        let leeway = i64::try_from(validation.leeway).unwrap_or(i64::MAX);

        for (claim, value) in [("exp", self.exp), ("nbf", self.nbf)] {
            if value.is_none() && validation.required_spec_claims.contains(claim) {
                return Err(Error::from(ErrorKind::MissingRequiredClaim(claim.to_string())).into());
            }
        }
        if validation.validate_exp {
            if let Some(exp) = self.exp {
                if exp < now.saturating_sub(leeway) {
                    return Err(Error::from(ErrorKind::ExpiredSignature).into());
                }
            }
        }
        if validation.validate_nbf {
            if let Some(nbf) = self.nbf {
                if nbf > now.saturating_add(leeway) {
                    return Err(Error::from(ErrorKind::ImmatureSignature).into());
                }
            }
        }
        Ok(())
    }
}

/// JWT utilities for federation operations.
pub struct JwtProcessor {
    /// Default validation settings
    validation: Validation,
}

impl JwtProcessor {
    /// Create a new JWT processor with default validation settings.
    pub fn new() -> Self {
        let validation = Validation {
            validate_exp: true,
            validate_nbf: true,
            leeway: 60, // 60 seconds leeway for clock skew
            ..Validation::default()
        };

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

        // `jsonwebtoken` cannot read a non-integer NumericDate when `serde_json`'s
        // `arbitrary_precision` feature is enabled anywhere in the build, and then reports `exp` as
        // missing. It only verifies the signature here; `exp` and `nbf` are checked below instead,
        // with the same settings.
        let time_validation = validation.clone();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.required_spec_claims.remove("exp");
        validation.required_spec_claims.remove("nbf");

        let claims = decode::<T>(token, key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(FederationError::from)?;

        let times: TimeClaims = extract_claims_unverified(token)?;
        times.validate(&time_validation)?;

        Ok(claims)
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

        Err(FederationError::InvalidSubordinateStatement(
            "No suitable key found for JWT verification".to_string(),
        ))
    }
}

/// Extract claims from a JWT without verification (for inspection purposes only).
pub fn extract_claims_unverified<T: for<'de> Deserialize<'de>>(token: &str) -> FederationResult<T> {
    // Nothing is validated here, not even the `exp` and `nbf` claims; `T` requires the claims it
    // needs. The header is still parsed, so a token that is not a JWT is rejected.
    jsonwebtoken::dangerous::insecure_decode::<T>(token)
        .map(|token_data| token_data.claims)
        .map_err(FederationError::from)
}

impl Default for JwtProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// Produces JWS signatures with one Federation Entity Key.
///
/// A signer binds one key, its `kid` and one algorithm. The private key lives behind it, in memory
/// ([`InMemorySigner`]), an HSM or a cloud key management service, which is why signing is
/// `async`. The signature is returned in the JWS form of the algorithm: raw `r || s` for ECDSA,
/// never DER. [`sign_compact_jws`] turns it into a compact JWS.
///
/// The trait has the shape of `identity_kit::jose::Signer`, so an application that keeps its keys
/// in `identity-kit` adapts them in a few lines, without this crate depending on it (ADR 0005):
///
/// ```rust,ignore
/// struct FederationSigner<S> {
///     inner: S,
///     kid: String,
/// }
///
/// #[async_trait::async_trait]
/// impl<S: identity_kit::jose::Signer> openid_federation::Signer for FederationSigner<S> {
///     fn alg(&self) -> jsonwebtoken::Algorithm {
///         match self.inner.alg() {
///             identity_kit::jose::JwsAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
///             identity_kit::jose::JwsAlgorithm::EdDSA => jsonwebtoken::Algorithm::EdDSA,
///             // ... one arm per algorithm the application uses
///             other => unimplemented!("{other:?} has no jsonwebtoken counterpart"),
///         }
///     }
///
///     fn kid(&self) -> &str {
///         &self.kid
///     }
///
///     async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, openid_federation::SignError> {
///         self.inner.sign(signing_input).await.map_err(openid_federation::SignError::new)
///     }
/// }
/// ```
///
/// Reference: OpenID Federation 1.0 - Section 3 Entity Statement
/// (<https://openid.net/specs/openid-federation-1_0.html#section-3>) and Appendix A.1
/// (<https://openid.net/specs/openid-federation-1_0.html#appendix-A.1>)
#[async_trait]
pub trait Signer: Send + Sync {
    /// The algorithm every signature of this signer uses.
    fn alg(&self) -> Algorithm;

    /// The `kid` of the key, as published in the issuer's `jwks`.
    fn kid(&self) -> &str;

    /// Signs `signing_input`, the ASCII bytes of `BASE64URL(header) || '.' || BASE64URL(payload)`.
    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// Encodes `claims` under `header` as a compact JWS signed by `signer`.
///
/// The header is serialized as given: its `alg` must equal the signer's algorithm, and `typ` and
/// `kid` are whatever the caller set.
///
/// # Errors
///
/// [`FederationError::Configuration`] when `header.alg` differs from [`Signer::alg`], checked
/// before the signer is called; [`FederationError::Signing`] when the signer fails.
///
/// Reference: RFC 7515 Section 7.1 (<https://www.rfc-editor.org/rfc/rfc7515#section-7.1>)
pub async fn sign_compact_jws<T: Serialize + ?Sized>(
    header: &Header,
    claims: &T,
    signer: &dyn Signer,
) -> FederationResult<String> {
    if header.alg != signer.alg() {
        return Err(FederationError::Configuration(format!(
            "JWS header alg {:?} differs from the algorithm {:?} of signer {:?}",
            header.alg,
            signer.alg(),
            signer.kid()
        )));
    }
    let mut token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?);
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?));
    let signature = signer.sign(token.as_bytes()).await?;
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(token)
}

/// Signs `claims` as a federation artifact of `artifact_type`: a compact JWS whose `typ` is the
/// artifact's media type and whose `kid` names the signer's key, as every federation artifact
/// requires.
///
/// This is the one signing path the artifact types share: Entity Configurations and Subordinate
/// Statements call it from their `sign` methods after their own checks.
///
/// # Errors
///
/// [`FederationError::Configuration`] when the signer has an empty `kid`, and the errors of
/// [`sign_compact_jws`].
///
/// Reference: OpenID Federation 1.0 - Section 3 Entity Statement
/// (<https://openid.net/specs/openid-federation-1_0.html#section-3>)
pub async fn sign_federation_jwt<T: Serialize + ?Sized>(
    claims: &T,
    artifact_type: JwtArtifactType,
    signer: &dyn Signer,
) -> FederationResult<String> {
    if signer.kid().is_empty() {
        return Err(FederationError::Configuration(
            "a federation artifact must name its signing key, but the signer's kid is empty".to_string(),
        ));
    }
    let mut header = Header::new(signer.alg());
    header.typ = Some(artifact_type.header_value().to_string());
    header.kid = Some(signer.kid().to_string());
    sign_compact_jws(&header, claims, signer).await
}

/// A [`Signer`] over a private key held in memory, signing through `jsonwebtoken`.
///
/// The key is DER-encoded, in the form `jsonwebtoken` takes it: PKCS#1 for RSA (`RS256`, `RS384`,
/// `RS512`, `PS256`, `PS384`, `PS512`), PKCS#8 for EC P-256 and P-384 (`ES256`, `ES384`) and for
/// Ed25519 (`EdDSA`). Signing runs on the crypto backend the application chose for
/// `jsonwebtoken`. Symmetric algorithms are refused: a Federation Entity Key is a public/private
/// key pair.
///
/// Reference: OpenID Federation 1.0 - Appendix A.1
/// (<https://openid.net/specs/openid-federation-1_0.html#appendix-A.1>)
pub struct InMemorySigner {
    alg: Algorithm,
    kid: String,
    key: EncodingKey,
}

impl InMemorySigner {
    /// A signer for the DER-encoded private key `der`, which signs with `alg` under `kid`.
    ///
    /// The key is used once here, so a malformed key, or one that does not fit `alg`, fails now
    /// rather than on the first statement.
    ///
    /// # Errors
    ///
    /// [`FederationError::Configuration`] for an empty `kid` or a symmetric algorithm, and
    /// [`FederationError::Signing`] when the key cannot sign with `alg`.
    pub fn from_der(alg: Algorithm, kid: impl Into<String>, der: &[u8]) -> FederationResult<Self> {
        let kid = kid.into();
        if kid.is_empty() {
            return Err(FederationError::Configuration(
                "a signer needs a non-empty kid".to_string(),
            ));
        }
        let key = match alg.family() {
            AlgorithmFamily::Rsa => EncodingKey::from_rsa_der(der),
            AlgorithmFamily::Ec => EncodingKey::from_ec_der(der),
            AlgorithmFamily::Ed => EncodingKey::from_ed_der(der),
            AlgorithmFamily::Hmac => {
                return Err(FederationError::Configuration(format!(
                    "{alg:?} is symmetric; a Federation Entity Key is a public/private key pair"
                )))
            }
        };
        let signer = Self { alg, kid, key };
        signer.sign_now(b"")?;
        Ok(signer)
    }

    fn sign_now(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        let signature = jsonwebtoken::crypto::sign(signing_input, &self.key, self.alg).map_err(SignError::new)?;
        URL_SAFE_NO_PAD.decode(signature).map_err(SignError::new)
    }
}

#[async_trait]
impl Signer for InMemorySigner {
    fn alg(&self) -> Algorithm {
        self.alg
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        self.sign_now(signing_input)
    }
}

/// Shows the algorithm and `kid`, never the key.
impl fmt::Debug for InMemorySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemorySigner")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
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

    /// Signs `claims` as an Entity Statement and verifies them again.
    fn verify_entity_statement(claims: serde_json::Value) -> FederationResult<serde_json::Value> {
        let (key, secret) = create_test_key();
        let processor = JwtProcessor::new();
        let token = processor
            .sign_jwt(&claims, &key, Algorithm::HS256, JwtArtifactType::EntityStatement, None)
            .unwrap();
        processor.verify_jwt(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            Algorithm::HS256,
            JwtArtifactType::EntityStatement,
        )
    }

    fn time_error(result: FederationResult<serde_json::Value>) -> jsonwebtoken::errors::ErrorKind {
        match result {
            Err(FederationError::Jwt(err)) => err.into_kind(),
            other => panic!("expected a JWT error, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_jwt_accepts_a_non_integer_exp() {
        let exp = chrono::Utc::now().timestamp() as f64 + 3600.5;

        assert!(verify_entity_statement(serde_json::json!({ "exp": exp })).is_ok());
    }

    #[test]
    fn test_verify_jwt_accepts_an_exp_within_the_leeway() {
        let exp = chrono::Utc::now().timestamp() - 30;

        assert!(verify_entity_statement(serde_json::json!({ "exp": exp })).is_ok());
    }

    #[test]
    fn test_verify_jwt_rejects_an_expired_jwt() {
        let exp = chrono::Utc::now().timestamp() - 120;

        assert_eq!(
            time_error(verify_entity_statement(serde_json::json!({ "exp": exp }))),
            jsonwebtoken::errors::ErrorKind::ExpiredSignature
        );
    }

    #[test]
    fn test_verify_jwt_rejects_a_jwt_that_is_not_yet_valid() {
        let now = chrono::Utc::now().timestamp();

        assert_eq!(
            time_error(verify_entity_statement(
                serde_json::json!({ "exp": now + 3600, "nbf": now + 120 })
            )),
            jsonwebtoken::errors::ErrorKind::ImmatureSignature
        );
    }

    #[test]
    fn test_verify_jwt_requires_exp() {
        assert_eq!(
            time_error(verify_entity_statement(
                serde_json::json!({ "iss": "https://example.com" })
            )),
            jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("exp".to_string())
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
