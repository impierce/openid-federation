//! The historical keys endpoint: an entity publishes the Federation Entity Keys it used before,
//! so that statements they signed stay verifiable after a rollover (OpenID Federation 1.0,
//! Section 8.7).

use super::{EndpointResponse, ErrorCode, ErrorResponse, JWK_SET_CONTENT_TYPE};
use crate::{
    EntityId, FederationError, FederationResult, HistoricalKeys, JwkSet, KeyRecord, KeyState, KeyStore, Signer,
};
use chrono::Utc;
use std::fmt;
use std::sync::Arc;

/// Serves an entity's retired and revoked Federation Entity Keys from its [`KeyStore`], as a
/// `jwk-set+jwt` signed with its active key.
///
/// A request is a `GET`, or a `POST` when client authentication is used (Section 8.7.1). It has
/// no parameters, so the handler takes none; authenticating the client is the application's
/// concern. Every request reads the store, so a key retired or revoked through
/// [`FederationKeys`](crate::FederationKeys) and saved is published at once.
///
/// `signer` must sign for the active key in the store: the response is signed with a current
/// Federation Entity Key, which verifiers find in the entity's `jwks`. After a rollover switches
/// the active key, build the endpoint with the new
/// [`active_signer`](crate::FederationKeys::active_signer); until then it answers `server_error`.
///
/// Reference: OpenID Federation 1.0 - Section 8.7 Federation Historical Keys Endpoint
/// (<https://openid.net/specs/openid-federation-1_0.html#section-8.7>)
pub struct HistoricalKeysEndpoint {
    issuer: EntityId,
    keys: Arc<dyn KeyStore>,
    signer: Arc<dyn Signer>,
}

impl HistoricalKeysEndpoint {
    /// An endpoint that publishes the historical keys of `issuer` from `keys`, signed with
    /// `signer`.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7 Federation Historical Keys Endpoint
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.7>)
    pub fn new(issuer: EntityId, keys: Arc<dyn KeyStore>, signer: Arc<dyn Signer>) -> Self {
        Self { issuer, keys, signer }
    }

    /// Answers a historical keys request: `200` with [`JWK_SET_CONTENT_TYPE`] and the signed
    /// historical keys, or `500` with the `server_error` error response when they cannot be
    /// signed.
    ///
    /// The error response does not say why, since the cause, such as an unreachable database or
    /// HSM, is the deployment's business. Call [`try_handle`](Self::try_handle) to learn it.
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>)
    pub async fn handle(&self) -> EndpointResponse {
        self.try_handle().await.unwrap_or_else(|_| {
            ErrorResponse::new(ErrorCode::ServerError, "the historical keys could not be signed").to_endpoint_response()
        })
    }

    /// Like [`handle`](Self::handle), but returns why the historical keys could not be signed
    /// instead of the `server_error` response.
    ///
    /// # Errors
    ///
    /// [`FederationError::Store`] when the store fails, [`FederationError::Configuration`] when
    /// the signer does not sign for the active key in the store, by its `kid` or, checked by
    /// verifying the signed set, by its key, and the errors of [`HistoricalKeys::sign`].
    ///
    /// Reference: OpenID Federation 1.0 - Section 8.7.2 Federation Historical Keys Response
    /// (<https://openid.net/specs/openid-federation-1_0.html#section-8.7.2>)
    pub async fn try_handle(&self) -> FederationResult<EndpointResponse> {
        let records = self.keys.load().await?;
        let active = match records.iter().find(|record| record.state == KeyState::Active) {
            Some(active) if active.kid() == self.signer.kid() => active,
            active => {
                return Err(FederationError::Configuration(format!(
                    "the historical keys signer {:?} is not the active key in the key store ({:?})",
                    self.signer.kid(),
                    active.map(KeyRecord::kid)
                )))
            }
        };
        let keys = records.iter().filter_map(KeyRecord::to_historical_key).collect();
        let jwt = HistoricalKeys::new(self.issuer.clone(), Utc::now().timestamp(), keys)
            .sign(self.signer.as_ref())
            .await?;
        // A signer under the active `kid` but with another key would publish a set that no
        // verifier can check against the entity's `jwks`.
        let active_key = JwkSet {
            keys: vec![active.public_key.clone()],
        };
        HistoricalKeys::from_verified_jwt(&jwt, &self.issuer, &active_key).map_err(|err| {
            FederationError::Configuration(format!(
                "the historical keys signer {:?} does not sign for the active public key: {err}",
                self.signer.kid()
            ))
        })?;
        Ok(EndpointResponse::new(200, JWK_SET_CONTENT_TYPE, jwt))
    }
}

/// Shows the issuer and the signer's `kid`.
impl fmt::Debug for HistoricalKeysEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoricalKeysEndpoint")
            .field("issuer", &self.issuer)
            .field("kid", &self.signer.kid())
            .finish_non_exhaustive()
    }
}
