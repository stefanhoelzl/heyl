//! The use cases — **the core**.
//!
//! This crate depends on the port traits and on nothing that implements them.
//! It cannot name `heyl-platform`, `heyl-grpc` or `heyl-proto`, and does not
//! depend on `tokio`: it is physically incapable of calling an OS API or
//! constructing a request. Composition happens once, in `heyl-cli`
//! (DESIGN.md §4).
//!
//! Two use cases carry M2:
//!
//! * [`recovery`] — `CreateChallenge` → confirm → recovery code → Argon2id →
//!   sign → `CreateTokens`, self-granting an unlock on the way through so that
//!   a *later, separate* invocation can decrypt. It is a **recovery**, not a
//!   sign-in: heylogin deletes the push authenticator as a side effect.
//! * [`doctor`] — `Sync` → recover the seed from that grant → walk the whole
//!   key hierarchy, comparing every derived public key against the one the
//!   backend publishes, then decrypt every vault.

pub mod doctor;
pub mod error;
pub mod recovery;
pub mod unlock;

pub use error::{AppError, ExitCode};

/// The ports a use case needs, gathered once.
///
/// Passed by reference so `heyl-cli` owns the adapters and the core borrows
/// them. `dyn` rather than generics: see `heyl-ports`' crate docs.
pub struct Ports<'a> {
    /// heylogin.
    pub api: &'a dyn heyl_ports::HeylApi,
    /// The keychain.
    pub store: &'a dyn heyl_ports::SecretStore,
    /// The terminal.
    pub terminal: &'a dyn heyl_ports::Terminal,
    /// Wall-clock time.
    pub clock: &'a dyn heyl_ports::Clock,
    /// Randomness.
    pub random: &'a dyn heyl_ports::RandomSource,
}
