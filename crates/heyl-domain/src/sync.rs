//! The backend's view of the account, in domain terms.
//!
//! These are what `HeylApi` returns; no `prost` type ever crosses that port
//! (DESIGN.md §4). Fields we do not use are dropped at the boundary rather
//! than carried, so what appears here is exactly what the client acts on.

use heyl_crypto::{EncryptionPublicKey, Signature, VerifyingKey};

use crate::{
    ids::{AuthenticatorId, CommitId, KeyGenerationId, ProfileId, SessionId, VaultId},
    locks::{ProfileAuthenticatorLock, VaultProfileLock},
    time::Timestamp,
    vault::VaultType,
};

/// One `SyncService.Sync` response, reduced to what v1 reads.
#[derive(Debug, Clone, Default)]
pub struct SyncSnapshot {
    /// The backend's clock, for diagnosing expiry disagreements.
    pub server_time: Option<Timestamp>,
    /// The access token is due for rotation via `RefreshToken`.
    pub token_refresh_needed: bool,
    /// The backend says this client build is too old.
    pub client_outdated: bool,
    /// The seed, encrypted to our session key — absent once the unlock lapses.
    pub session_unlock: Option<SessionUnlock>,
    /// Our own sessions.
    pub sessions: Vec<Session>,
    /// Every vault we can see.
    pub vaults: Vec<VaultSummary>,
    /// Every profile we can unlock from.
    pub profiles: Vec<Profile>,
}

impl SyncSnapshot {
    /// The profile with this id, if the backend sent it.
    #[must_use]
    pub fn profile(&self, id: ProfileId) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    /// The session with this id, if the backend sent it.
    #[must_use]
    pub fn session(&self, id: SessionId) -> Option<&Session> {
        self.sessions.iter().find(|s| s.id == id)
    }
}

/// A stored unlock grant: `asymEncrypt(sessionEncPubKey, seed)` (§6).
///
/// The backend stops serving this once the unlock expires, which is what makes
/// heylogin's re-swipe control server-enforced rather than cooperative
/// (DESIGN.md §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUnlock {
    /// The seed, sealed to our session encryption key.
    pub encrypted_secret: Vec<u8>,
    /// Which authenticator granted it — so we know whose `secretSalt` to use.
    pub authenticator_id: AuthenticatorId,
}

/// One of our sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Which session.
    pub id: SessionId,
    /// When the current unlock lapses. The **effective** value, which is what
    /// the backend decided rather than what we asked for.
    pub unlocked_until: Option<Timestamp>,
}

/// A vault, as `SyncUpdate` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSummary {
    /// Which vault.
    pub id: VaultId,
    /// Which content schema it carries.
    pub vault_type: VaultType,
    /// The vault's current key generation.
    pub generation_id: KeyGenerationId,
    /// Its newest commit, if it has one.
    pub commit_id: Option<CommitId>,
    /// The profiles that can open it.
    pub profile_ids: Vec<ProfileId>,
}

/// A profile and the keys the backend publishes for it.
#[derive(Debug, Clone)]
pub struct Profile {
    /// Which profile.
    pub id: ProfileId,
    /// Its current key generation — checked against every lock before any
    /// decryption is attempted.
    pub key_generation_id: KeyGenerationId,
    /// One lock per authenticator, so any authenticator opens every profile.
    pub authenticator_locks: Vec<ProfileAuthenticatorLock>,
    /// The public halves, for `doctor`'s derived-vs-published comparison.
    pub public_keys: ProfilePublicKeys,
}

impl Profile {
    /// The lock addressed to `authenticator`, if this profile carries one.
    #[must_use]
    pub fn lock_for(&self, authenticator: AuthenticatorId) -> Option<&ProfileAuthenticatorLock> {
        self.authenticator_locks
            .iter()
            .find(|l| l.authenticator_id == authenticator)
    }
}

/// The public halves the backend publishes for a profile.
///
/// Each corresponds to one link of the hierarchy, which is what lets `doctor`
/// name a broken context salt by byte comparison instead of inferring it from a
/// failed decryption three links downstream (DESIGN.md §6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfilePublicKeys {
    /// Identity signing key, high-security tier.
    pub high_security_identity_sig: Option<VerifyingKey>,
    /// Identity signing key, storable tier.
    pub storable_sig: Option<VerifyingKey>,
    /// Unwraps `protectedSecret`.
    pub high_security_vault_key_enc: Option<EncryptionPublicKey>,
    /// Unwraps `vaultSecret`.
    pub storable_vault_key_enc: Option<EncryptionPublicKey>,
    /// Receives a downstream profile's high-security seed.
    pub high_security_profile_seed_enc: Option<EncryptionPublicKey>,
    /// Receives a downstream profile's storable seed.
    pub storable_profile_seed_enc: Option<EncryptionPublicKey>,
    /// Signature over `high_security_vault_key_enc`.
    pub high_security_vault_key_enc_signature: Option<Signature>,
    /// Signature over `storable_vault_key_enc`.
    pub storable_vault_key_enc_signature: Option<Signature>,
    /// Signature over `high_security_profile_seed_enc`.
    pub high_security_profile_seed_enc_signature: Option<Signature>,
    /// Signature over `storable_profile_seed_enc`.
    pub storable_profile_seed_enc_signature: Option<Signature>,
    /// Signature over `storable_sig`.
    pub storable_sig_signature: Option<Signature>,
}

/// What `CredentialService.CreateChallenge` returns.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// The account the challenge is for.
    pub user_id: String,
    /// The challenge to sign, exactly as the backend spelled it.
    pub challenge: String,
    /// Which authenticators may answer it.
    pub authenticators: Vec<crate::authenticator::Authenticator>,
}

/// What `CredentialService.CreateTokens` returns.
#[derive(Debug, Clone)]
pub struct Tokens {
    /// The bearer token.
    pub access_token: String,
    /// When it expires.
    pub expires_at: Option<Timestamp>,
    /// The session the token belongs to.
    pub session_id: SessionId,
    /// Login already carries a full sync, so the first read needs no `Sync`.
    pub sync: SyncSnapshot,
}

/// What `VaultService.ListCommits` returns.
#[derive(Debug, Clone)]
pub struct VaultCommits {
    /// The vault's current generation, as the commit endpoint sees it.
    pub current_generation_id: KeyGenerationId,
    /// Commits newer than the one we asked from — all of them, here.
    pub commits: Vec<Commit>,
    /// Our lock on this vault. Requested with `force_locks`, because this
    /// client caches nothing and an omitted lock would read as a failure.
    pub profile_lock: Option<VaultProfileLock>,
}

/// One commit: the full serialized vault state, encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// Which commit.
    pub id: CommitId,
    /// `symEncrypt(vaultSecret, serialize(state))`.
    pub blob: Vec<u8>,
}
