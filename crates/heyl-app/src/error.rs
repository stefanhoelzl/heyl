//! The error taxonomy, and the exit codes it maps onto.
//!
//! `heyl-app` owns the taxonomy; `heyl-cli` maps it to §5's exit codes. There
//! is one code per *class a caller acts on differently*, not one per variant:
//! a script that can tell "that name does not exist" from "that value is not
//! allowed" can do something about each, while twenty numbers would only be a
//! second vocabulary to keep stable. **3** (ambiguous selector) is still
//! reserved — selectors arrive with the read path.
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

    /// A slot already has credentials.
    #[error("session slot {slot:?} already exists; `heyl session remove {slot}` first")]
    SlotExists {
        /// The slot in question.
        slot: String,
    },

    /// A slot's stored values are not what they should be.
    #[error("session slot {slot:?} is unusable: {what}")]
    MalformedSlot {
        /// The slot in question.
        slot: String,
        /// What was wrong with it.
        what: &'static str,
    },

    /// This session has no `SessionMetadata` entry, so no phone will unlock it.
    #[error(
        "session {slot:?} is not registered as a device, so the phone cannot show it; \
         run `heyl session create` again"
    )]
    NotRegistered {
        /// The slot in question.
        slot: String,
    },

    /// The backend no longer knows this session.
    #[error("this session no longer exists; run `heyl session create` again")]
    SessionGone,

    /// A settings key that does not exist.
    #[error("unknown setting {key:?}")]
    UnknownSetting {
        /// What the user typed.
        key: String,
    },

    /// A settings value the key cannot take.
    #[error("{key} cannot be {value:?}; expected {expected}")]
    BadSettingValue {
        /// Which key.
        key: &'static str,
        /// What the user typed.
        value: String,
        /// What would have been accepted.
        expected: &'static str,
    },

    /// A timeout under the backend's floor.
    #[error("the backend refuses an unlock timeout under {minimum} minute(s)")]
    TimeoutTooShort {
        /// The smallest value the backend accepts.
        minimum: u32,
    },

    /// The account has no META vault at all.
    #[error("this account has no META vault, so there is nowhere to register a device")]
    NoMetaVault,

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
/// 3 is absent on purpose: an ambiguous selector needs selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Generic failure: crypto, a vault, local state that makes no sense.
    Failure = 1,
    /// A name that does not exist — a slot, a setting.
    NotFound = 2,
    /// Unlock required or expired.
    UnlockRequired = 4,
    /// Network or backend error.
    Backend = 5,
    /// Something is already there.
    Conflict = 6,
    /// A value the command cannot take.
    Invalid = 7,
}

impl AppError {
    /// Which exit code this failure means.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            // A locked session and an unapproved request are the same exit:
            // heyl cannot tell a phone-lock from an idle timeout, and says so
            // rather than guessing (decision 16).
            Self::UnlockRequired | Self::NotRegistered { .. } => ExitCode::UnlockRequired,
            // A rejected token is the one case that is *not* "locked": the
            // session is gone, and swiping again will not bring it back.
            Self::SessionGone | Self::Api(_) => ExitCode::Backend,

            // A name nobody has. The keychain's own "not found" is how an
            // unknown *slot* arrives here: every session verb reads the slot's
            // token first.
            Self::UnknownSetting { .. } | Self::Port(heyl_ports::PortError::NotFound { .. }) => {
                ExitCode::NotFound
            }

            // The caller asked to make something that is already there. The
            // action — pick another name, or remove that one — is different
            // enough from every other failure to be worth its own number.
            Self::SlotExists { .. } => ExitCode::Conflict,

            // The command understood the request and will not take that value.
            // `NotConfirmed` belongs here: the answer was "no", which is a
            // value the command cannot act on rather than a fault.
            Self::BadSettingValue { .. }
            | Self::TimeoutTooShort { .. }
            | Self::MalformedSlot { .. }
            | Self::NotConfirmed => ExitCode::Invalid,

            _ => ExitCode::Failure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One code per class a caller acts on differently.
    ///
    /// The scenario suite asserts these numbers from the outside — a step
    /// states the exit it expects — so what they *mean* has to be pinned
    /// somewhere a reader of the taxonomy will find it.
    #[test]
    fn each_class_of_failure_has_its_own_code() {
        let cases: [(AppError, ExitCode); 7] = [
            (
                AppError::SlotExists {
                    slot: "ci".to_owned(),
                },
                ExitCode::Conflict,
            ),
            (
                AppError::UnknownSetting {
                    key: "displayname".to_owned(),
                },
                ExitCode::NotFound,
            ),
            (
                AppError::Port(heyl_ports::PortError::NotFound { what: "token" }),
                ExitCode::NotFound,
            ),
            (AppError::TimeoutTooShort { minimum: 1 }, ExitCode::Invalid),
            (
                AppError::BadSettingValue {
                    key: "strict",
                    value: "maybe".to_owned(),
                    expected: "on or off",
                },
                ExitCode::Invalid,
            ),
            (AppError::UnlockRequired, ExitCode::UnlockRequired),
            (AppError::SessionGone, ExitCode::Backend),
        ];

        for (error, expected) in cases {
            assert_eq!(error.exit_code(), expected, "{error}");
        }
    }

    /// A keychain that cannot be reached is not a name that does not exist.
    /// Only `NotFound` means "no such thing"; anything else the port reports is
    /// a failure of the machine.
    #[test]
    fn only_a_missing_item_reads_as_not_found() {
        let broken = AppError::Port(heyl_ports::PortError::Unavailable {
            operation: "open the keychain",
            reason: "no Secret Service".to_owned(),
        });
        assert_eq!(broken.exit_code(), ExitCode::Failure);
    }
}
