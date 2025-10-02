//! JSON Web Key (JWK) and JSON Web Key Set (JWKS) utilities.

use crate::{FederationError, FederationResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};

/// JSON Web Key as defined in RFC 7517.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC", "oct")
    pub kty: String,
    /// Key use (e.g., "sig", "enc")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Key operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    /// Algorithm intended for use with the key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// X.509 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    /// X.509 certificate chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// X.509 certificate SHA-1 thumbprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    /// X.509 certificate SHA-256 thumbprint
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    /// RSA modulus (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// RSA private exponent (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    /// RSA first prime factor (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    /// RSA second prime factor (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    /// RSA first factor CRT exponent (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    /// RSA second factor CRT exponent (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    /// RSA first CRT coefficient (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
    /// Elliptic curve (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// X coordinate (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y coordinate (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Key value (for symmetric keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
}

/// JSON Web Key Set as defined in RFC 7517.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwkSet {
    /// Array of JWK values
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Create a new empty JWK Set.
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Add a JWK to the set.
    pub fn add_key(&mut self, key: Jwk) {
        self.keys.push(key);
    }

    /// Find a key by its key ID.
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys
            .iter()
            .find(|key| key.kid.as_ref().map(|k| k == kid).unwrap_or(false))
    }

    /// Get all keys suitable for signature verification.
    pub fn signature_keys(&self) -> Vec<&Jwk> {
        self.keys
            .iter()
            .filter(|key| {
                key.use_.as_ref().map(|u| u == "sig").unwrap_or(true) // Default to signature use if not specified
            })
            .collect()
    }
}

impl Default for JwkSet {
    fn default() -> Self {
        Self::new()
    }
}

impl Jwk {
    /// Convert the JWK to a DecodingKey for JWT verification.
    pub fn to_decoding_key(&self) -> FederationResult<DecodingKey> {
        match self.kty.as_str() {
            "RSA" => {
                let n = self
                    .n
                    .as_ref()
                    .ok_or_else(|| FederationError::InvalidMetadata("RSA key missing modulus 'n'".to_string()))?;
                let e = self
                    .e
                    .as_ref()
                    .ok_or_else(|| FederationError::InvalidMetadata("RSA key missing exponent 'e'".to_string()))?;

                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| FederationError::InvalidMetadata(format!("Failed to create RSA decoding key: {}", e)))
            }
            "EC" => Err(FederationError::InvalidMetadata(
                "EC keys not yet supported".to_string(),
            )),
            "oct" => {
                let k = self
                    .k
                    .as_ref()
                    .ok_or_else(|| FederationError::InvalidMetadata("Symmetric key missing value 'k'".to_string()))?;
                let key_bytes = URL_SAFE_NO_PAD
                    .decode(k)
                    .map_err(|_| FederationError::InvalidMetadata("Invalid base64 in symmetric key".to_string()))?;
                Ok(DecodingKey::from_secret(&key_bytes))
            }
            _ => Err(FederationError::InvalidMetadata(format!(
                "Unsupported key type: {}",
                self.kty
            ))),
        }
    }

    /// Convert the JWK to an EncodingKey for JWT signing (if private key material is available).
    pub fn to_encoding_key(&self) -> FederationResult<EncodingKey> {
        match self.kty.as_str() {
            "RSA" => {
                let d = self.d.as_ref().ok_or_else(|| {
                    FederationError::InvalidMetadata("RSA private key missing private exponent 'd'".to_string())
                })?;

                let _d_bytes = URL_SAFE_NO_PAD.decode(d).map_err(|_| {
                    FederationError::InvalidMetadata("Invalid base64 in RSA private exponent".to_string())
                })?;

                // For simplicity, we'll create a minimal RSA private key structure
                // In a full implementation, you'd need to construct a proper PKCS#8 or PKCS#1 structure
                Err(FederationError::InvalidMetadata(
                    "RSA private key encoding not yet implemented".to_string(),
                ))
            }
            "oct" => {
                let k = self
                    .k
                    .as_ref()
                    .ok_or_else(|| FederationError::InvalidMetadata("Symmetric key missing value 'k'".to_string()))?;
                let key_bytes = URL_SAFE_NO_PAD
                    .decode(k)
                    .map_err(|_| FederationError::InvalidMetadata("Invalid base64 in symmetric key".to_string()))?;
                Ok(EncodingKey::from_secret(&key_bytes))
            }
            _ => Err(FederationError::InvalidMetadata(format!(
                "Unsupported key type for encoding: {}",
                self.kty
            ))),
        }
    }
}
