//! JSON Web Key (JWK) and JSON Web Key Set (JWKS) utilities.

use crate::{FederationError, FederationResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::jwk::ThumbprintHash;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// The members `Jwk` has a field for. `Jwk::additional` must not repeat them, or the key serializes
/// with a duplicate member name (RFC 7517 Section 4).
const NAMED_MEMBERS: [&str; 21] = [
    "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "n", "e", "d", "p", "q", "dp", "dq", "qi",
    "crv", "x", "y", "k",
];

/// The private or symmetric key members: `d`, `p`, `q`, `dp`, `dq`, `qi` and `oth`
/// (RFC 7518 Section 6.3.2) for RSA, `d` for EC (RFC 7518 Section 6.2.2) and OKP
/// (RFC 8037 Section 2), and `k` for `oct` (RFC 7518 Section 6.4.1).
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// JSON Web Key as defined in RFC 7517.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC", "oct")
    pub kty: String,
    /// Key use (e.g., "sig", "enc"), the `use` member
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
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
    /// Members this struct does not name, such as `iat` or `exp` on a historical key, kept so a key
    /// survives a round trip unchanged.
    ///
    /// Reference: <https://www.rfc-editor.org/rfc/rfc7517#section-4>
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
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
    ///
    /// Supports both exact matches and DID key references where the JWT `kid` is a full
    /// DID URL (e.g. `did:web:example.com#key-1`) and the JWK `kid` is just the fragment
    /// (e.g. `key-1`).
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        // Exact match first.
        if let Some(jwk) = self
            .keys
            .iter()
            .find(|key| key.kid.as_ref().map(|k| k == kid).unwrap_or(false))
        {
            return Some(jwk);
        }
        // If the supplied kid contains a '#', try matching against only the fragment part.
        if let Some(fragment) = kid.split_once('#').map(|x| x.1) {
            return self
                .keys
                .iter()
                .find(|key| key.kid.as_ref().map(|k| k == fragment).unwrap_or(false));
        }
        None
    }

    /// Check that the set can be published as the `jwks` of an Entity Statement: every key has a
    /// non-empty `kid`, no two keys share one, and no key carries private or symmetric key material.
    ///
    /// Publishing a private key in `jwks` hands it to every participant; for a Trust Anchor that
    /// compromises the whole federation. Use [`Jwk::to_public`] to strip the private members first.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.1 Claims that MUST or MAY Appear in both
    /// Entity Configurations and Subordinate Statements
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>)
    pub fn validate(&self) -> FederationResult<()> {
        let mut kids = HashSet::new();
        for (index, key) in self.keys.iter().enumerate() {
            let kid = match key.kid.as_deref() {
                Some(kid) if !kid.is_empty() => kid,
                _ => {
                    return Err(FederationError::InvalidMetadata(format!(
                        "JWK at index {index} in jwks has no kid"
                    )))
                }
            };
            if !kids.insert(kid) {
                return Err(FederationError::InvalidMetadata(format!(
                    "kid {kid:?} appears more than once in jwks"
                )));
            }
            if key.kty == "oct" {
                return Err(FederationError::InvalidMetadata(format!(
                    "JWK {kid:?} is a symmetric key; jwks may only carry public keys"
                )));
            }
            let private = key.private_members();
            if !private.is_empty() {
                return Err(FederationError::InvalidMetadata(format!(
                    "JWK {kid:?} carries private key material ({}); jwks may only carry public keys",
                    private.join(", ")
                )));
            }
            if let Some(name) = key
                .additional
                .keys()
                .find(|name| NAMED_MEMBERS.contains(&name.as_str()))
            {
                return Err(FederationError::InvalidMetadata(format!(
                    "JWK {kid:?} repeats the {name} member in its additional members"
                )));
            }
        }
        Ok(())
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
    /// The public half of this key: a copy without the private members `d`, `p`, `q`, `dp`, `dq`,
    /// `qi`, `oth` and `k`.
    ///
    /// A symmetric (`oct`) key has no public half; its result has no key value and fails
    /// [`JwkSet::validate`].
    ///
    /// Reference: <https://www.rfc-editor.org/rfc/rfc7518#section-6>
    pub fn to_public(&self) -> Jwk {
        let mut public = self.clone();
        public.d = None;
        public.p = None;
        public.q = None;
        public.dp = None;
        public.dq = None;
        public.qi = None;
        public.k = None;
        for member in PRIVATE_MEMBERS {
            public.additional.remove(member);
        }
        public
    }

    /// The RFC 7638 JWK Thumbprint of this key with SHA-256, base64url-encoded without padding.
    ///
    /// OpenID Federation recommends it as the `kid` of a Federation Entity Key. It covers the
    /// required public members only, so a private key and its public half have the same
    /// thumbprint. Supported for RSA, EC (P-256, P-384, P-521) and OKP (Ed25519) keys. The hash is
    /// computed by the crypto backend the application chose for `jsonwebtoken`.
    ///
    /// Reference: <https://www.rfc-editor.org/rfc/rfc7638#section-3> and OpenID Federation 1.0 -
    /// Section 3.1.1 (<https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>)
    pub fn thumbprint(&self) -> FederationResult<String> {
        let public = Jwk {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            ..Jwk::default()
        };
        // The copy has no `k`, so a symmetric key fails here too.
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(serde_json::to_value(&public)?).map_err(|e| {
            FederationError::InvalidMetadata(format!(
                "cannot compute the JWK Thumbprint of this {} key: {e}",
                self.kty
            ))
        })?;
        Ok(jwk.thumbprint(ThumbprintHash::SHA256)?)
    }

    /// The private or symmetric key members this key carries, as a field or in `additional`.
    fn private_members(&self) -> Vec<&'static str> {
        let named = [
            ("d", &self.d),
            ("p", &self.p),
            ("q", &self.q),
            ("dp", &self.dp),
            ("dq", &self.dq),
            ("qi", &self.qi),
            ("k", &self.k),
        ];
        PRIVATE_MEMBERS
            .into_iter()
            .filter(|member| {
                let as_field = named.iter().any(|(name, value)| name == member && value.is_some());
                as_field || self.additional.contains_key(*member)
            })
            .collect()
    }

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
            "EC" => {
                let x = self
                    .x
                    .as_ref()
                    .ok_or_else(|| FederationError::InvalidMetadata("EC key missing x coordinate".to_string()))?;
                let y = self
                    .y
                    .as_ref()
                    .ok_or_else(|| FederationError::InvalidMetadata("EC key missing y coordinate".to_string()))?;
                DecodingKey::from_ec_components(x, y)
                    .map_err(|e| FederationError::InvalidMetadata(format!("Failed to create EC decoding key: {}", e)))
            }
            "OKP" => {
                if self.crv.as_deref() != Some("Ed25519") {
                    return Err(FederationError::InvalidMetadata(format!(
                        "Unsupported OKP curve: {}",
                        self.crv.as_deref().unwrap_or("none")
                    )));
                }
                let x = self
                    .x
                    .as_ref()
                    .ok_or_else(|| FederationError::InvalidMetadata("OKP key missing public key 'x'".to_string()))?;
                DecodingKey::from_ed_components(x)
                    .map_err(|e| FederationError::InvalidMetadata(format!("Failed to create OKP decoding key: {}", e)))
            }
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

/// A previously used Federation Entity Key, as the historical keys endpoint publishes it: the
/// public key with its lifetime and, if it was revoked, the revocation.
///
/// `kid` is REQUIRED, which [`HistoricalKeys::validate`] checks; `exp` is REQUIRED, so a key
/// without it does not parse.
///
/// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
/// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HistoricalKey {
    /// The public key.
    #[serde(flatten)]
    pub key: Jwk,
    /// When the key was issued, as a NumericDate.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::jwt::numeric_date::deserialize_option"
    )]
    pub iat: Option<i64>,
    /// When the key expires, as a NumericDate. After this time the key MUST NOT be considered
    /// valid.
    #[serde(deserialize_with = "crate::jwt::numeric_date::deserialize")]
    pub exp: i64,
    /// The time before which the key is not valid, as a NumericDate.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::jwt::numeric_date::deserialize_option"
    )]
    pub nbf: Option<i64>,
    /// The revocation, if the key was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<KeyRevocation>,
}

impl HistoricalKey {
    /// A historical key: `key`, a public key with a `kid`, expiring at `exp`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
    /// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
    pub fn new(key: Jwk, exp: i64) -> Self {
        Self {
            key,
            iat: None,
            exp,
            nbf: None,
            revoked: None,
        }
    }
}

/// The revocation of a historical key: when, and optionally why.
///
/// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
/// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KeyRevocation {
    /// When the key was revoked, or must be considered revoked, as a NumericDate.
    #[serde(deserialize_with = "crate::jwt::numeric_date::deserialize")]
    pub revoked_at: i64,
    /// Why the key was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<RevocationReason>,
    /// Other members of the revocation, which federations may define.
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl KeyRevocation {
    /// A revocation at `revoked_at`, for `reason` if given.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
    /// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
    pub fn new(revoked_at: i64, reason: Option<RevocationReason>) -> Self {
        Self {
            revoked_at,
            reason,
            additional: HashMap::new(),
        }
    }
}

/// Why a Federation Entity Key was revoked.
///
/// The reasons the specification defines are variants; any other, which a federation may define,
/// is [`RevocationReason::Other`]. Parsing a reason the specification defines always yields its
/// variant.
///
/// Reference: OpenID Federation 1.0 - Section 8.7.3 Federation Historical Keys Revocation Reasons
/// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.3>
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    /// `unspecified`: a general or unspecified reason.
    Unspecified,
    /// `compromised`: the private key is believed to have been compromised.
    Compromised,
    /// `superseded`: the key is no longer active.
    Superseded,
    /// Any other reason, spelled as it is sent.
    Other(String),
}

impl RevocationReason {
    /// The reason as it is spelled on the wire.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.3
    /// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.3>
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Compromised => "compromised",
            Self::Superseded => "superseded",
            Self::Other(reason) => reason,
        }
    }
}

impl From<&str> for RevocationReason {
    fn from(reason: &str) -> Self {
        match reason {
            "unspecified" => Self::Unspecified,
            "compromised" => Self::Compromised,
            "superseded" => Self::Superseded,
            other => Self::Other(other.to_string()),
        }
    }
}

impl Serialize for RevocationReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RevocationReason {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|reason| Self::from(reason.as_str()))
    }
}

/// The claims of a historical keys JWT: the keys an entity used before, signed with one of its
/// current Federation Entity Keys as a `jwk-set+jwt`.
///
/// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
/// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HistoricalKeys {
    /// The Entity Identifier of the entity whose keys these are.
    pub iss: crate::EntityId,
    /// When this JWT was issued, as a NumericDate.
    #[serde(deserialize_with = "crate::jwt::numeric_date::deserialize")]
    pub iat: i64,
    /// The historical keys.
    pub keys: Vec<HistoricalKey>,
    /// Other claims, which may be defined and used.
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl HistoricalKeys {
    /// The historical keys `keys` of `iss`, issued at `iat`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
    /// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
    pub fn new(iss: crate::EntityId, iat: i64, keys: Vec<HistoricalKey>) -> Self {
        Self {
            iss,
            iat,
            keys,
            additional: HashMap::new(),
        }
    }

    /// Checks that the keys can be published: as for [`JwkSet::validate`], every key has a
    /// non-empty `kid`, no two keys share one, and no key carries private or symmetric key
    /// material. Neither does an `additional` map of a key or of its revocation repeat a member
    /// the key or revocation serializes, which would publish that member twice (RFC 7517
    /// Section 4). Every key parses back as published, so an `additional` member such as `iat`
    /// that is not a NumericDate is refused.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidMetadata`] when an `additional` map repeats a member or a key
    /// would not parse, and the errors of [`JwkSet::validate`].
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
    /// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
    pub fn validate(&self) -> FederationResult<()> {
        for historical in &self.keys {
            let kid = &historical.key.kid;
            let set = [
                ("exp", true),
                ("iat", historical.iat.is_some()),
                ("nbf", historical.nbf.is_some()),
                ("revoked", historical.revoked.is_some()),
            ];
            if let Some(name) = repeated_member(&historical.key.additional, &set) {
                return Err(FederationError::InvalidMetadata(format!(
                    "historical key {kid:?} repeats the {name} member in its additional members"
                )));
            }
            if let Some(revocation) = &historical.revoked {
                let set = [("revoked_at", true), ("reason", revocation.reason.is_some())];
                if let Some(name) = repeated_member(&revocation.additional, &set) {
                    return Err(FederationError::InvalidMetadata(format!(
                        "the revocation of historical key {kid:?} repeats the {name} member in its additional members"
                    )));
                }
            }
            // An `additional` member a verifier reads as a typed one, such as an `iat` that is
            // not a NumericDate, would make the whole set fail to parse.
            serde_json::to_value(historical)
                .and_then(serde_json::from_value::<HistoricalKey>)
                .map_err(|err| {
                    FederationError::InvalidMetadata(format!("historical key {kid:?} would not parse: {err}"))
                })?;
        }
        JwkSet {
            keys: self.keys.iter().map(|historical| historical.key.clone()).collect(),
        }
        .validate()
    }

    /// Signs the historical keys with `signer`, one of the entity's current Federation Entity
    /// Keys, as a `jwk-set+jwt` that names the key in `kid`, after [`validate`](Self::validate)
    /// and after checking that every key has usable key material.
    ///
    /// # Errors
    ///
    /// The errors of [`validate`](Self::validate), of [`Jwk::to_decoding_key`] and of
    /// [`sign_federation_jwt`](crate::sign_federation_jwt).
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
    /// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
    pub async fn sign(&self, signer: &dyn crate::Signer) -> FederationResult<String> {
        self.validate()?;
        // A producer rule: a key without usable key material is no use to a verifier.
        for historical in &self.keys {
            historical.key.to_decoding_key()?;
        }
        crate::sign_federation_jwt(self, crate::JwtArtifactType::SignedJwkSet, signer).await
    }

    /// Decodes and authenticates a historical keys JWT published by `issuer`: it must be typed
    /// `jwk-set+jwt`, be signed with a key from `issuer_jwks`, the issuer's current keys, under
    /// the `kid` it names, and have `iss` equal to `issuer`.
    ///
    /// # Errors
    ///
    /// [`FederationError::InvalidSubordinateStatement`] when `iss` is another entity, the errors
    /// of verifying the JWT, and those of [`validate`](Self::validate).
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
    /// <https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>
    pub fn from_verified_jwt(jwt: &str, issuer: &crate::EntityId, issuer_jwks: &JwkSet) -> FederationResult<Self> {
        // A historical keys JWT has no `exp`; its keys carry their own.
        let mut validation = jsonwebtoken::Validation::default();
        validation.required_spec_claims.clear();
        validation.leeway = 60;
        let keys: Self = crate::JwtProcessor::with_validation(validation).verify_jwt_with_jwks(
            jwt,
            issuer_jwks,
            crate::JwtArtifactType::SignedJwkSet,
        )?;
        keys.validate()?;
        if keys.iss != *issuer {
            return Err(FederationError::InvalidSubordinateStatement(format!(
                "historical keys of {} were issued by {}",
                issuer, keys.iss
            )));
        }
        Ok(keys)
    }
}

/// The first member in `members` that is serialized, as its flag says, and also in `additional`.
fn repeated_member<'a>(
    additional: &HashMap<String, serde_json::Value>,
    members: &[(&'a str, bool)],
) -> Option<&'a str> {
    members
        .iter()
        .find(|(name, serialized)| *serialized && additional.contains_key(*name))
        .map(|(name, _)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// RFC 7638 Section 3.1: the example RSA key and its SHA-256 JWK Thumbprint.
    const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    fn jwk(value: serde_json::Value) -> Jwk {
        serde_json::from_value(value).expect("test JWK parses")
    }

    fn set(keys: Vec<Jwk>) -> JwkSet {
        JwkSet { keys }
    }

    fn rsa_public(kid: &str) -> Jwk {
        jwk(json!({ "kty": "RSA", "kid": kid, "n": RFC7638_N, "e": "AQAB" }))
    }

    /// One private key of each asymmetric type. The private members only have to be present:
    /// `validate` and `to_public` look at which members a key has, not at their values.
    fn private_keys() -> Vec<Jwk> {
        vec![
            jwk(json!({
                "kty": "RSA", "kid": "rsa", "n": RFC7638_N, "e": "AQAB",
                "d": "ZA", "p": "cA", "q": "cQ", "dp": "ZHA", "dq": "ZHE", "qi": "cWk",
                "oth": [{ "r": "cg", "d": "ZA", "t": "dA" }]
            })),
            // RFC 7517 Appendix A.2, the EC P-256 private key.
            jwk(json!({
                "kty": "EC", "kid": "ec", "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
            })),
            // RFC 8037 Appendix A.1, the Ed25519 private key.
            jwk(json!({
                "kty": "OKP", "kid": "okp", "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
            })),
        ]
    }

    #[test]
    fn thumbprint_matches_rfc7638_example() {
        let key = jwk(json!({ "kty": "RSA", "n": RFC7638_N, "e": "AQAB", "alg": "RS256", "kid": "2011-04-29" }));
        assert_eq!(key.thumbprint().unwrap(), RFC7638_THUMBPRINT);
    }

    #[test]
    fn thumbprint_matches_rfc8037_example() {
        // RFC 8037 Appendix A.3.
        let key = jwk(json!({ "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }));
        assert_eq!(key.thumbprint().unwrap(), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    #[test]
    fn thumbprint_ignores_private_and_optional_members() {
        for private in private_keys() {
            assert_eq!(private.thumbprint().unwrap(), private.to_public().thumbprint().unwrap());
        }
        let mut key = rsa_public("another-kid");
        key.use_ = Some("sig".to_string());
        key.additional.insert("iat".to_string(), json!(1_700_000_000));
        assert_eq!(key.thumbprint().unwrap(), RFC7638_THUMBPRINT);
    }

    #[test]
    fn thumbprint_of_symmetric_or_incomplete_key_fails() {
        assert!(jwk(json!({ "kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg" }))
            .thumbprint()
            .is_err());
        assert!(jwk(json!({ "kty": "RSA", "e": "AQAB" })).thumbprint().is_err());
        assert!(jwk(json!({ "kty": "EC", "crv": "P-256", "x": "AA" }))
            .thumbprint()
            .is_err());
    }

    #[test]
    fn validate_accepts_public_keys_with_unique_kids() {
        let keys = private_keys().iter().map(Jwk::to_public).collect();
        set(keys).validate().unwrap();
        set(vec![rsa_public("a"), rsa_public("b")]).validate().unwrap();
    }

    #[test]
    fn validate_rejects_missing_or_empty_kid() {
        let mut key = rsa_public("a");
        key.kid = None;
        assert!(set(vec![key.clone()]).validate().is_err());
        key.kid = Some(String::new());
        assert!(set(vec![key]).validate().is_err());
    }

    #[test]
    fn validate_rejects_duplicate_kid() {
        let error = set(vec![rsa_public("a"), rsa_public("a")]).validate().unwrap_err();
        assert!(error.to_string().contains("more than once"), "{error}");
    }

    #[test]
    fn validate_rejects_each_private_key() {
        for private in private_keys() {
            let error = set(vec![private.clone()]).validate().unwrap_err();
            assert!(error.to_string().contains("private key material"), "{error}");
        }
    }

    #[test]
    fn validate_rejects_rsa_key_with_only_d() {
        let mut key = rsa_public("a");
        key.d = Some("ZA".to_string());
        let error = set(vec![key]).validate().unwrap_err();
        assert!(error.to_string().contains("(d)"), "{error}");
    }

    #[test]
    fn validate_rejects_symmetric_key() {
        let key = jwk(json!({ "kty": "oct", "kid": "hmac", "k": "GawgguFyGrWKav7AX4VKUg" }));
        assert!(set(vec![key.clone()]).validate().is_err());
        assert!(set(vec![key.to_public()]).validate().is_err());
    }

    /// A private member placed in `additional` by hand, which deserialization never does.
    fn with_additional_private_member(member: &str) -> Jwk {
        let mut key = rsa_public("a");
        key.additional.insert(member.to_string(), json!("c2VjcmV0"));
        key
    }

    #[test]
    fn validate_rejects_private_member_in_additional() {
        for member in PRIVATE_MEMBERS {
            let error = set(vec![with_additional_private_member(member)])
                .validate()
                .unwrap_err();
            assert!(error.to_string().contains("private key material"), "{member}: {error}");
        }
    }

    #[test]
    fn validate_rejects_named_member_repeated_in_additional() {
        let mut key = rsa_public("a");
        key.additional.insert("kid".to_string(), json!("b"));
        let error = set(vec![key]).validate().unwrap_err();
        assert!(error.to_string().contains("repeats the kid member"), "{error}");
    }

    #[test]
    fn to_public_drops_every_private_member() {
        let mut keys = private_keys();
        keys.extend(PRIVATE_MEMBERS.map(with_additional_private_member));
        for private in keys {
            let public = private.to_public();
            assert!(public.private_members().is_empty(), "{public:?}");
            let serialized = serde_json::to_value(&public).unwrap();
            for member in PRIVATE_MEMBERS {
                assert!(serialized.get(member).is_none(), "{member} in {serialized}");
            }
            assert_eq!(public.kid, private.kid);
            assert_eq!(public.x, private.x);
            assert_eq!(public.n, private.n);
        }
    }

    #[test]
    fn unknown_members_round_trip() {
        let value = json!({
            "kty": "EC", "kid": "1", "use": "sig", "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "iat": 1_700_000_000, "exp": 1_800_000_000, "ext": { "nested": [1, "two"] }
        });
        let key = jwk(value.clone());
        assert_eq!(key.use_.as_deref(), Some("sig"));
        assert_eq!(key.additional["iat"], json!(1_700_000_000));
        assert_eq!(serde_json::to_value(&key).unwrap(), value);
    }
}
