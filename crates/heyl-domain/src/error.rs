//! Errors raised while walking the unlock chain.

use crate::ids::{AuthenticatorId, KeyGenerationId, ProfileId};

/// Anything that can go wrong in `heyl-domain`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DomainError {
    /// A cryptographic step failed. Carries no key or plaintext material.
    #[error(transparent)]
    Crypto(#[from] heyl_crypto::CryptoError),

    /// The profile carries no lock for the authenticator we hold.
    #[error("profile has no lock for authenticator {authenticator_id}")]
    NoLockForAuthenticator {
        /// The authenticator we tried to unlock with.
        authenticator_id: AuthenticatorId,
    },

    /// An authenticator's `secretInfo` could not be read.
    ///
    /// Carries only which field was wrong, never the payload — a `DUMMY`
    /// authenticator's `secretInfo` is a plaintext seed (§4).
    #[error("malformed secretInfo: {what}")]
    MalformedSecretInfo {
        /// Which part was unreadable.
        what: &'static str,
    },

    /// The profile has been re-keyed since the lock was written.
    ///
    /// Distinct from a decryption failure on purpose: the fix is to re-sync,
    /// not to re-authenticate.
    #[error(
        "profile {profile_id} is at key generation {profile}, but the lock was written at {lock}"
    )]
    KeyGenerationMismatch {
        /// The profile whose generation disagreed.
        profile_id: ProfileId,
        /// The profile's current generation.
        profile: KeyGenerationId,
        /// The generation recorded in the lock.
        lock: KeyGenerationId,
    },
}
