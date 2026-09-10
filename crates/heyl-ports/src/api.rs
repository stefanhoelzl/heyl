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
    Authenticator, AuthenticatorId, Challenge, CommitId, SessionId, SessionType, SyncSnapshot,
    Timestamp, Tokens, VaultCommits, VaultId,
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

/// What a phone answered a pairing channel with.
///
/// The reply to `CreateLongPollChannelChallenge`: the seed, sealed to the
/// public key we put in the QR, plus the challenge to answer with it.
#[derive(Debug, Clone)]
pub struct LongPollChallenge {
    /// Whose account the phone belongs to.
    pub user_id: String,
    /// The challenge `CreateTokens` expects a signature over.
    pub challenge: String,
    /// Which authenticator answered — the phone's.
    pub authenticator_id: AuthenticatorId,
    /// `asymEncrypt(the QR's public key, seed)`.
    pub encrypted_secret: Vec<u8>,
    /// Set when the reply enrolled a new authenticator rather than unlocking
    /// an existing one; heylogin's own client omits the self-grant then.
    pub registration: bool,
}

/// What `UpdateSession` is being asked to change.
///
/// Every field is optional because the wire's are: an absent one is left
/// alone. None of this needs an unlock — it is session state behind the
/// bearer token, not vault content.
#[derive(Debug, Clone, Default)]
pub struct SessionUpdate {
    /// `unlock_time_limit_minutes`, the server-enforced auto-lock.
    pub unlock_time_limit_minutes: Option<u32>,
    /// The per-session `client_settings` string, where heyl's own flags ride.
    pub client_settings: Option<String>,
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
        session_type: SessionType,
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

    /// `CredentialService.CreateLongPollChannelChallenge` — the pairing
    /// channel behind the QR code.
    ///
    /// **Long-polls**: it does not return until a phone scans the code and
    /// answers, or the backend gives up. The caller is expected to have shown
    /// the code first.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn create_long_poll_channel_challenge(
        &self,
        public_key_hash: &str,
    ) -> Result<LongPollChallenge, ApiError>;

    /// `SessionService.Update` — change a session's own settings.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn update_session(
        &self,
        session: SessionId,
        update: SessionUpdate,
    ) -> Result<(), ApiError>;

    /// `SessionService.RequestSessionUnlock` — ask the account's other devices
    /// to unlock us.
    ///
    /// The phone will only answer for a session whose signed `encPubKey` it can
    /// verify, i.e. one with a `SessionMetadata` entry. Asking without one
    /// produces a notification with nothing behind it, so callers check first.
    ///
    /// `source` is telemetry — heylogin logs it to chase exactly those ghost
    /// notifications, and never shows it to the user.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn request_session_unlock(&self, source: &str) -> Result<(), ApiError>;

    /// `SessionService.DeleteSessionUnlock` — drop a session's unlock now,
    /// and cancel any request pending on it.
    ///
    /// Works on any session of the account, not only our own.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn delete_session_unlock(&self, session: SessionId) -> Result<(), ApiError>;

    /// `SessionService.DeleteSession` — end a session for good.
    ///
    /// Note this does **not** rotate the seed: a client that kept one from an
    /// earlier unlock still holds it. Real revocation is deleting the
    /// authenticator (`HEYLOGIN_SPEC.md` §6).
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn delete_session(&self, session: SessionId) -> Result<(), ApiError>;

    /// `VaultService.CreateCommit` — write a vault's next full state.
    ///
    /// Guarded by `latest_commit_id`: if another client committed in the
    /// meantime the backend refuses, and the caller re-reads rather than
    /// merging (DESIGN.md §3).
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure, including a rejected
    /// guard.
    async fn create_commit(
        &self,
        vault: VaultId,
        latest_commit: CommitId,
        blob: Vec<u8>,
        update_time: Timestamp,
    ) -> Result<CommitId, ApiError>;

    /// `VaultService.ListCommits` — a vault's commits and our lock on it.
    ///
    /// Always called with `force_locks`, because nothing is cached and a lock
    /// the backend omits as "you already have it" would read as a failure.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    async fn list_commits(&self, vault: VaultId) -> Result<VaultCommits, ApiError>;
}
