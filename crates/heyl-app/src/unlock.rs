//! Recovering the seed in a later, separate invocation.
//!
//! This is §3's central path, and the reason M2 self-grants an unlock at login
//! rather than decrypting inside the login process:
//!
//! ```text
//! token ──► Sync ──► SyncUpdate.session_unlock.encrypted_secret
//!                            │
//!        asym_decrypt(session_priv_key, ·) ──► seed (in memory)
//! ```
//!
//! The backend refuses to serve the blob once the unlock lapses, so the
//! re-swipe control is **server-enforced** rather than trusted to this client.
//! A stolen laptop yields a token and a session key; neither opens anything
//! after the window closes.

use heyl_crypto::{SecretSalt, Seed};
use heyl_domain::{Authenticator, AuthenticatorId, AuthenticatorKeys, SyncSnapshot};
use heyl_ports::{SecretKey, StoredSecret};

use crate::{AppError, Ports, login::decode_key};

/// An unlocked session: the seed, and the authenticator keys it derives.
pub struct Unlocked {
    /// The account snapshot the unlock came from.
    pub sync: SyncSnapshot,
    /// Every authenticator, with `secretSalt` — the only source of it.
    pub authenticators: Vec<Authenticator>,
    /// Which authenticator granted the unlock.
    pub authenticator_id: AuthenticatorId,
    /// The seed. Dropped, and zeroized, when this value is.
    pub seed: Seed,
    /// The authenticator-layer keys derived from the seed and `secretSalt`.
    pub keys: AuthenticatorKeys,
}

/// Load the stored token, sync, and recover the seed.
///
/// Handles token rotation on the way: `SyncUpdate.token_refresh_needed` means
/// the access token is due, and without acting on it a stale token fails
/// looking exactly like a broken key hierarchy — the worst possible confusion
/// at the milestone whose job is confirming the hierarchy.
///
/// # Errors
/// [`AppError::UnlockRequired`] if no grant is being served,
/// [`AppError::UnlockUndecryptable`] if our session key does not open it.
pub async fn run(ports: &Ports<'_>) -> Result<Unlocked, AppError> {
    let token = ports
        .store
        .get(&SecretKey::default_slot(StoredSecret::AccessToken))
        .await?;
    let session_key = decode_key(
        &ports
            .store
            .get(&SecretKey::default_slot(StoredSecret::SessionPrivateKey))
            .await?,
    )?;

    ports.api.set_access_token(Some(&token)).await;
    let mut sync = ports.api.sync().await?;

    if sync.token_refresh_needed {
        let refreshed = ports.api.refresh_token().await?;
        ports
            .store
            .set(
                &SecretKey::default_slot(StoredSecret::AccessToken),
                &refreshed,
            )
            .await?;
        ports.api.set_access_token(Some(&refreshed)).await;
        // Re-sync so the rest of this run sees a snapshot fetched with the
        // token we will actually keep using.
        sync = ports.api.sync().await?;
    }

    let grant = sync
        .session_unlock
        .clone()
        .ok_or(AppError::UnlockRequired)?;

    let plaintext = session_key
        .open(&grant.encrypted_secret)
        .map_err(|_| AppError::UnlockUndecryptable)?;
    let seed = Seed::try_from_slice(&plaintext).map_err(|_| AppError::UnlockUndecryptable)?;

    // secretSalt has exactly one source: SyncUpdate carries no authenticator
    // list (its field numbers are reserved). Re-fetched every invocation
    // because this client caches nothing.
    let authenticators = ports.api.list_authenticators().await?;
    let salt = secret_salt(&authenticators, grant.authenticator_id)?;
    let keys = AuthenticatorKeys::derive(grant.authenticator_id, &seed, &salt)?;

    Ok(Unlocked {
        sync,
        authenticators,
        authenticator_id: grant.authenticator_id,
        seed,
        keys,
    })
}

fn secret_salt(
    authenticators: &[Authenticator],
    id: AuthenticatorId,
) -> Result<SecretSalt, AppError> {
    let authenticator = authenticators.iter().find(|a| a.id == id).ok_or(
        AppError::UnknownGrantingAuthenticator {
            authenticator_id: id,
        },
    )?;
    authenticator.secret_salt.ok_or(AppError::NoSecretSalt {
        authenticator_id: id,
    })
}
