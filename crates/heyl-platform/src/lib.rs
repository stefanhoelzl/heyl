//! OS adapters for the ports.
//!
//! Two of the five platform ports contain **no OS-specific code of our own** —
//! `keyring` and `directories` do the delegating. The ports stay because they
//! are what let `HeadlessSecretStore` be bound in CI and fakes be bound under
//! test, but they are thin (DESIGN.md §4).
//!
//! `Paths` is deliberately absent. M2 writes no file: `SyncUpdate.SessionUnlock`
//! carries the granting authenticator, `AuthenticatorService.List` is
//! re-fetched every invocation, `SyncRequest` has no cursor, and email is
//! needed only by `CreateChallenge` at login time. Nothing through M5 has a use
//! for a state directory, so the five platform ports may turn out to be four.

pub mod clock;
pub mod headless;
pub mod keychain;
pub mod process;
pub mod random;
pub mod terminal;

pub use clock::SystemClock;
pub use headless::HeadlessSecretStore;
pub use keychain::KeyringStore;
pub use process::{HardeningError, harden_process};
pub use random::OsRandom;
pub use terminal::SystemTerminal;
