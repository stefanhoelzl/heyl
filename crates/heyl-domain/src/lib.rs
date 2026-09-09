//! heylogin's domain vocabulary and key hierarchy.
//!
//! Pure and I/O-free: it depends on `heyl-crypto` and leaf utilities, on no
//! runtime and no transport, so the whole unlock chain is exercisable against
//! fixtures with no network and no account.
//!
//! What lives here: identifiers and enums, the lock structures, the
//! heymerge-compatible [`Timestamp`], and the authenticator → profile → vault
//! key chain. What does not: traits for other crates to implement (those are
//! `heyl-ports`), orchestration (`heyl-app`), wire types (`heyl-grpc`), and
//! the serialize/heymerge codec (`heyl-vault`).

pub mod authenticator;
pub mod error;
pub mod ids;
pub mod keys;
pub mod locks;
pub mod sync;
pub mod time;
pub mod vault;

pub use authenticator::{
    Authenticator, AuthenticatorPublicKeys, AuthenticatorSecret, RecoverySecret,
};
pub use error::DomainError;
pub use ids::{AuthenticatorId, CommitId, KeyGenerationId, ProfileId, SessionId, VaultId};
pub use keys::{
    AuthenticatorKeys, HighSecurity, ProfileSeed, ProtectedSecret, Storable, VaultSecret,
    login_signing_key,
};
pub use locks::{ProfileAuthenticatorLock, VaultProfileLock};
pub use sync::{
    Challenge, Commit, Profile, ProfilePublicKeys, Session, SessionUnlock, SyncSnapshot, Tokens,
    VaultCommits, VaultSummary,
};
pub use time::Timestamp;
pub use vault::{AuthenticatorType, VaultType};
