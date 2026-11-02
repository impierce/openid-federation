//! An entity's Federation Entity Keys across rollover: which keys it publishes in `jwks`, which
//! one it signs with, and which it has retired (OpenID Federation 1.0, Sections 11.1 and 11.2).
//!
//! # Rolling over a Trust Anchor's keys
//!
//! [`FederationKeys`] follows the four steps of Section 11.2. The application decides when to
//! take each step, typically from the `exp` of the Entity Configuration, since participants
//! re-fetch the configuration, and with it the keys, when it expires (Section 11.1):
//!
//! 1. [`add_next`](FederationKeys::add_next) the new key. It is published in
//!    [`jwks`](FederationKeys::jwks) from the next signed Entity Configuration on, but not used.
//! 2. Keep signing with the old key until every Subordinate has fetched a configuration that
//!    lists the new one: at least one configuration lifetime, so that every cached configuration
//!    has expired.
//! 3. [`activate`](FederationKeys::activate) the new key. It signs from now on; the old key
//!    becomes [`KeyState::Previous`], still published so that statements it signed keep
//!    verifying until they expire.
//! 4. After a period the Trust Anchor's security profile decides, at least the lifetime of the
//!    last statement the old key signed, [`retire`](FederationKeys::retire) it. It leaves
//!    `jwks` and is kept as [`KeyState::Retired`] with the time it was retired, for the
//!    historical keys endpoint.
//!
//! Exactly one key is [`KeyState::Active`] at any time. A [`KeyStore`] persists the key records
//! between restarts; the private keys stay behind the application's [`Signer`]s.

use crate::{FederationError, FederationResult, Jwk, JwkSet, Signer, StoreError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

/// Where a Federation Entity Key is in its rollover.
///
/// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
/// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KeyState {
    /// Published in `jwks`, not yet used to sign (step 1).
    Next,
    /// Published in `jwks` and used to sign (step 3).
    Active,
    /// Published in `jwks`, no longer used to sign, so that what it signed keeps verifying
    /// (between steps 3 and 4).
    Previous,
    /// Removed from `jwks` (step 4), kept for the historical keys endpoint.
    Retired,
}

/// A Federation Entity Key as a [`KeyStore`] persists it: the public key, its rollover state and,
/// once retired, when.
///
/// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
/// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KeyRecord {
    /// The public key, with the `kid` its signer signs under.
    pub public_key: Jwk,
    /// Where the key is in its rollover.
    pub state: KeyState,
    /// When the key was retired, as a NumericDate; `None` until it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<i64>,
}

impl KeyRecord {
    /// The key's `kid`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 3.1.1
    /// <https://openid.net/specs/openid-federation-1_0.html#section-3.1.1>
    pub fn kid(&self) -> &str {
        self.public_key.kid.as_deref().unwrap_or_default()
    }
}

/// An entity's Federation Entity Keys: the [`KeyRecord`]s, and the [`Signer`] of each key that
/// signs now or will: the [`KeyState::Active`] key and every [`KeyState::Next`] key.
///
/// The set always has exactly one active key, every `kid` appears once, and every published key
/// passes [`JwkSet::validate`], so [`jwks`](Self::jwks) can be published as is. A signer whose
/// key does not match its public key is caught when it signs:
/// [`EntityConfiguration::sign`](crate::EntityConfiguration::sign) verifies its own result.
///
/// See the [module documentation](self) for the rollover procedure.
///
/// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
/// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
#[derive(Clone)]
pub struct FederationKeys {
    records: Vec<KeyRecord>,
    signers: HashMap<String, Arc<dyn Signer>>,
}

impl FederationKeys {
    /// A key set with one key, active: `signer` signs under the `kid` of `public_key`.
    ///
    /// # Errors
    ///
    /// The errors of [`add_next`](Self::add_next).
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn new(signer: Arc<dyn Signer>, public_key: Jwk) -> FederationResult<Self> {
        let mut keys = Self {
            records: Vec::new(),
            signers: HashMap::new(),
        };
        keys.insert(signer, public_key, KeyState::Active)?;
        Ok(keys)
    }

    /// The key set that `records` describe, as a [`KeyStore`] loaded them, with the signers of
    /// its active and next keys. Signers of other keys are ignored.
    ///
    /// # Errors
    ///
    /// [`FederationError::Configuration`] when the records do not have exactly one active key,
    /// repeat a `kid`, publish a key that fails [`JwkSet::validate`], or when the active key or a
    /// next key has no signer in `signers`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn from_records(
        records: Vec<KeyRecord>,
        signers: impl IntoIterator<Item = Arc<dyn Signer>>,
    ) -> FederationResult<Self> {
        let mut signers: HashMap<String, Arc<dyn Signer>> = signers
            .into_iter()
            .map(|signer| (signer.kid().to_string(), signer))
            .collect();
        let mut kids = HashSet::new();
        for record in &records {
            if !kids.insert(record.kid()) {
                return Err(key_error(format!("kid {:?} appears more than once", record.kid())));
            }
        }
        let active = records.iter().filter(|record| record.state == KeyState::Active).count();
        if active != 1 {
            return Err(key_error(format!(
                "a key set has exactly one active key, but these records have {active}"
            )));
        }
        let signing: HashSet<&str> = records
            .iter()
            .filter(|record| matches!(record.state, KeyState::Active | KeyState::Next))
            .map(KeyRecord::kid)
            .collect();
        if let Some(kid) = signing.iter().find(|kid| !signers.contains_key(**kid)) {
            return Err(key_error(format!(
                "no signer for the key {kid:?}, which is active or next"
            )));
        }
        signers.retain(|kid, _| signing.contains(kid.as_str()));
        let keys = Self { records, signers };
        keys.jwks().validate()?;
        Ok(keys)
    }

    /// Step 1 of Section 11.2: publishes `public_key` as a [`KeyState::Next`] key, which `signer`
    /// signs for once it is [`activate`](Self::activate)d.
    ///
    /// # Errors
    ///
    /// [`FederationError::Configuration`] when the `kid` of `public_key` is missing, differs from
    /// the signer's, or is already in the set, and the errors of [`JwkSet::validate`] for a key
    /// that cannot be published, such as one with private members.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn add_next(&mut self, signer: Arc<dyn Signer>, public_key: Jwk) -> FederationResult<()> {
        self.insert(signer, public_key, KeyState::Next)
    }

    fn insert(&mut self, signer: Arc<dyn Signer>, public_key: Jwk, state: KeyState) -> FederationResult<()> {
        let kid = signer.kid().to_string();
        if public_key.kid.as_deref() != Some(kid.as_str()) {
            return Err(key_error(format!(
                "the public key's kid {:?} differs from the signer's kid {kid:?}",
                public_key.kid
            )));
        }
        if self.records.iter().any(|record| record.kid() == kid) {
            return Err(key_error(format!("kid {kid:?} is already in the key set")));
        }
        let mut published = JwkSet::new();
        published.add_key(public_key.clone());
        published.validate()?;
        self.records.push(KeyRecord {
            public_key,
            state,
            retired_at: None,
        });
        self.signers.insert(kid, signer);
        Ok(())
    }

    /// Step 3 of Section 11.2: the [`KeyState::Next`] key `kid` signs from now on, and the
    /// active key becomes [`KeyState::Previous`].
    ///
    /// # Errors
    ///
    /// [`FederationError::Configuration`] when `kid` is not a next key.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn activate(&mut self, kid: &str) -> FederationResult<()> {
        self.require_state(kid, &[KeyState::Next], "activated")?;
        for record in &mut self.records {
            if record.state == KeyState::Active {
                record.state = KeyState::Previous;
                self.signers
                    .remove(record.public_key.kid.as_deref().unwrap_or_default());
            }
        }
        self.record_mut(kid).state = KeyState::Active;
        Ok(())
    }

    /// Step 4 of Section 11.2: removes the key `kid` from [`jwks`](Self::jwks) and keeps it as
    /// [`KeyState::Retired`], retired at `retired_at`, a NumericDate. A [`KeyState::Next`] key
    /// can be retired too, to abandon a rollover.
    ///
    /// # Errors
    ///
    /// [`FederationError::Configuration`] when `kid` is not a previous or next key: the active
    /// key is replaced with [`activate`](Self::activate), never retired, and a retired key stays
    /// retired.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn retire(&mut self, kid: &str, retired_at: i64) -> FederationResult<()> {
        self.require_state(kid, &[KeyState::Previous, KeyState::Next], "retired")?;
        let record = self.record_mut(kid);
        record.state = KeyState::Retired;
        record.retired_at = Some(retired_at);
        self.signers.remove(kid);
        Ok(())
    }

    fn require_state(&self, kid: &str, allowed: &[KeyState], action: &str) -> FederationResult<()> {
        match self.records.iter().find(|record| record.kid() == kid) {
            None => Err(key_error(format!("no key {kid:?} in the key set"))),
            Some(record) if !allowed.contains(&record.state) => Err(key_error(format!(
                "the key {kid:?} is {:?} and cannot be {action}",
                record.state
            ))),
            Some(_) => Ok(()),
        }
    }

    fn record_mut(&mut self, kid: &str) -> &mut KeyRecord {
        self.records
            .iter_mut()
            .find(|record| record.kid() == kid)
            .expect("the key was found by require_state")
    }

    /// The keys to publish as `jwks` in the Entity Configuration: the next, active and previous
    /// keys, never the retired ones.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.1 Federation Key Rollover
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.1>
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: self
                .records
                .iter()
                .filter(|record| record.state != KeyState::Retired)
                .map(|record| record.public_key.clone())
                .collect(),
        }
    }

    /// The signer of the active key, to sign the Entity Configuration and Subordinate Statements
    /// with.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn active_signer(&self) -> Arc<dyn Signer> {
        let kid = self.active().kid();
        Arc::clone(&self.signers[kid])
    }

    /// The record of the active key.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn active(&self) -> &KeyRecord {
        self.records
            .iter()
            .find(|record| record.state == KeyState::Active)
            .expect("a key set always has an active key")
    }

    /// Every key record, for a [`KeyStore`] to persist.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn records(&self) -> &[KeyRecord] {
        &self.records
    }

    /// The retired keys, with when each was retired.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn retired(&self) -> impl Iterator<Item = &KeyRecord> {
        self.records.iter().filter(|record| record.state == KeyState::Retired)
    }
}

/// Shows the key records and which keys have a signer, never the signers.
impl fmt::Debug for FederationKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederationKeys")
            .field("records", &self.records)
            .field("signers", &self.signers.keys().collect::<Vec<_>>())
            .finish()
    }
}

fn key_error(message: String) -> FederationError {
    FederationError::Configuration(format!("key rollover: {message}"))
}

/// Where an entity keeps the records of its Federation Entity Keys between restarts.
///
/// The application implements it on its own database; [`InMemoryKeyStore`] serves tests,
/// examples and small deployments. Only public keys and states are stored: the private keys stay
/// behind the application's [`Signer`]s, which [`FederationKeys::from_records`] takes back.
///
/// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
/// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// The stored key records, empty if none were saved.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    async fn load(&self) -> Result<Vec<KeyRecord>, StoreError>;

    /// Replaces the stored key records with `records`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    async fn save(&self, records: &[KeyRecord]) -> Result<(), StoreError>;
}

/// A [`KeyStore`] in memory, for tests, examples and small deployments.
///
/// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
/// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
#[derive(Debug, Default)]
pub struct InMemoryKeyStore {
    records: RwLock<Vec<KeyRecord>>,
}

impl InMemoryKeyStore {
    /// An empty store.
    ///
    /// Reference: OpenID Federation 1.0 - Section 11.2 Key Rollover for a Trust Anchor
    /// <https://openid.net/specs/openid-federation-1_0.html#section-11.2>
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyStore for InMemoryKeyStore {
    async fn load(&self) -> Result<Vec<KeyRecord>, StoreError> {
        Ok(self.records.read().unwrap_or_else(PoisonError::into_inner).clone())
    }

    async fn save(&self, records: &[KeyRecord]) -> Result<(), StoreError> {
        *self.records.write().unwrap_or_else(PoisonError::into_inner) = records.to_vec();
        Ok(())
    }
}
