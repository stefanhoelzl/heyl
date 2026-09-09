//! The backend, as a driven port.
//!
//! **One method per RPC, domain types in and out.** "Use-case-shaped" means no
//! `prost` type crosses this boundary — not that the methods are coarse.
//! Coarser methods would move the login sequence into the adapter, which is
//! precisely what the port exists to prevent: `heyl-app` orchestrates,
//! `heyl-grpc` maps (DESIGN.md §4).
//!
//! Six methods carry M2. The set grows to roughly twelve by M5.

use heyl_domain::{
    Authenticator, AuthenticatorId, Challenge, SyncSnapshot, Timestamp, Tokens, VaultCommits,
    VaultId,
};

use crate::error::ApiError;

/// The self-granted unlock attached to `CreateTokens`.
///
/// Sending this at login is what lets a *later, separate* invocation decrypt:
/// the backend stores the blob, and the next process recovers the seed from
/// `Sync` with its session private key. `single_use` is false because a
/// single-use grant would be consumed by the first `Sync` (§6).
#[derive(Debug, Clone)]
pub struct SessionUnlockGrant {
    /// `asymEncrypt(our session encPubKey, seed)`.
    pub encrypted_secret: Vec<u8>,
    /// The hard cap we request. The backend may clamp it, so the effective
    /// value is read back from `SyncUpdate.Session.unlocked_until`.
    pub expires_at: Timestamp,
}

/// heylogin, reduced to what this client calls.
#[async_trait::async_trait]
pub trait HeylApi: Send + Sync {
    /// Adopt a bearer token for subsequent calls, or clear it.
    ///
    /// The port is stateful about authentication because the backend is: a
    /// token is rotated by `RefreshToken` mid-run, and every later call has to
    /// pick up the new value. Threading it through each method signature would
    /// put the same parameter on all of them and still not express that the
    /// old token is now dead.
    async fn set_access_token(&self, token: Option<&str>);

    /// `CredentialService.CreateChallenge` — the challenge and the account's
    /// authenticators, before any credential is presented.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn create_challenge(&self, email: &str) -> Result<Challenge, ApiError>;

    /// `CredentialService.CreateTokens` — answer the challenge, and in the same
    /// call self-grant an unlock.
    ///
    /// # Errors
    /// [`ApiError::PermissionDenied`] if the signature is refused.
    async fn create_tokens(
        &self,
        authenticator_id: AuthenticatorId,
        challenge: &str,
        response: &[u8],
        unlock: Option<SessionUnlockGrant>,
    ) -> Result<Tokens, ApiError>;

    /// `CredentialService.RefreshToken` — a new access token for this session.
    ///
    /// Called when `SyncUpdate.token_refresh_needed` is set. Without it, a
    /// stale token fails looking exactly like a broken key hierarchy, which is
    /// the worst possible confusion at the milestone that confirms the
    /// hierarchy.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn refresh_token(&self) -> Result<String, ApiError>;

    /// `SyncService.Sync` — the account snapshot, including the unlock grant.
    ///
    /// # Errors
    /// [`ApiError::Unauthenticated`] if no token was presented,
    /// [`ApiError::PermissionDenied`] if it was rejected.
    async fn sync(&self) -> Result<SyncSnapshot, ApiError>;

    /// `AuthenticatorService.List` — every authenticator, with `secretSalt`.
    ///
    /// The only source of `secretSalt`: `SyncUpdate` carries no authenticator
    /// list (its field numbers are reserved). Re-fetched every invocation
    /// rather than cached, because this client persists nothing.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn list_authenticators(&self) -> Result<Vec<Authenticator>, ApiError>;

    /// `VaultService.ListCommits` — a vault's commits and our lock on it.
    ///
    /// Always called with `force_locks`, because nothing is cached and a lock
    /// the backend omits as "you already have it" would read as a failure.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn list_commits(&self, vault: VaultId) -> Result<VaultCommits, ApiError>;
}
