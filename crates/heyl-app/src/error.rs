//! The error taxonomy, and the exit codes it maps onto.
//!
//! `heyl-app` owns the taxonomy; `heyl-cli` maps it to §5's exit codes. Codes
//! **2** (not found) and **3** (ambiguous selector) have no caller at M2 —
//! selectors arrive with the read path at M3 — so they are reserved rather
//! than invented here.
//!
//! No variant carries key, plaintext or ciphertext bytes. Decrypt failures
//! *are* distinguished from one another, because the padding-oracle argument
//! for opacity does not apply to a client decrypting data it fetched, and M2
//! is exactly where a failed decryption has to be diagnosable (DESIGN.md §4).

use heyl_domain::{AuthenticatorId, VaultId};

/// What a `heyl` command can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AppError {
    /// The typed recovery code did not match the account's checksum.
    ///
    /// Caught locally, before `CreateTokens` — though *not* before any network
    /// call, since the checksum and Argon2 parameters only arrive with
    /// `CreateChallenge`.
    #[error("that recovery code is not correct for this account")]
    WrongRecoveryCode,

    /// The account has no `BACKUP_CODE` authenticator to log in with.
    #[error("this account has no recovery code configured; use another method")]
    NoRecoveryAuthenticator,

    /// A recovery would have disconnected something and the user did not agree.
    ///
    /// Also raised when there is something to lose and the command is running
    /// without a terminal to ask at: a destructive operation must not proceed
    /// silently because nobody was there to object.
    #[error("cancelled: nothing was changed. Pass --confirm to proceed without being asked")]
    NotConfirmed,

    /// The backend refused our challenge signature.
    ///
    /// At M2 this is the signal that [`heyl_domain::ChallengeEncoding`] is
    /// wrong, not that the code is — the checksum already passed.
    #[error("the backend rejected our login signature")]
    SignatureRejected,

    /// No unlock grant is being served: it expired, or there never was one.
    ///
    /// The backend stops serving the blob after `expiresAt`, which is what
    /// makes the re-swipe control server-enforced (DESIGN.md §3).
    #[error("this session is locked; run `heyl login` again")]
    UnlockRequired,

    /// The unlock grant was served but our session key did not open it.
    #[error("the unlock grant did not open with our session key")]
    UnlockUndecryptable,

    /// The unlock grant names an authenticator the backend did not list.
    #[error(
        "the unlock grant names authenticator {authenticator_id}, which the account does not list"
    )]
    UnknownGrantingAuthenticator {
        /// The authenticator the grant referred to.
        authenticator_id: AuthenticatorId,
    },

    /// The backend has not revealed `secretSalt` for the granting
    /// authenticator, so no authenticator key can be derived.
    #[error("the backend did not reveal secretSalt for authenticator {authenticator_id}")]
    NoSecretSalt {
        /// Which authenticator.
        authenticator_id: AuthenticatorId,
    },

    /// No profile carries a lock for the authenticator we hold.
    #[error("no profile is unlockable with authenticator {authenticator_id}")]
    NoUnlockableProfile {
        /// Which authenticator.
        authenticator_id: AuthenticatorId,
    },

    /// A vault could not be opened. Names the vault and the link that broke.
    #[error("vault {vault}: {source}")]
    Vault {
        /// Which vault.
        vault: VaultId,
        /// Which link failed.
        source: heyl_domain::DomainError,
    },

    /// A vault's blob decrypted but its contents did not hold up.
    #[error("vault {vault}: {source}")]
    VaultContent {
        /// Which vault.
        vault: VaultId,
        /// What was wrong with the document.
        source: heyl_vault::VaultError,
    },

    /// The chain itself failed outside a specific vault.
    #[error(transparent)]
    Domain(#[from] heyl_domain::DomainError),

    /// A cryptographic step failed.
    #[error(transparent)]
    Crypto(#[from] heyl_crypto::CryptoError),

    /// The backend, or the network.
    #[error(transparent)]
    Api(#[from] heyl_ports::ApiError),

    /// The keychain, terminal or OS.
    #[error(transparent)]
    Port(#[from] heyl_ports::PortError),
}

/// §5's exit codes.
///
/// 2 and 3 are absent on purpose — nothing at M2 can produce them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Generic failure.
    Failure = 1,
    /// Unlock required or expired.
    UnlockRequired = 4,
    /// Network or backend error.
    Backend = 5,
}

impl AppError {
    /// Which exit code this failure means.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::UnlockRequired => ExitCode::UnlockRequired,
            Self::Api(_) => ExitCode::Backend,
            _ => ExitCode::Failure,
        }
    }
}
