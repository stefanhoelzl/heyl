//! Port traits — **definitions only**.
//!
//! No adapter and no platform code lives here (DESIGN.md §4). `heyl-app`
//! depends on this crate and on nothing that implements it, which is what makes
//! the core physically incapable of reaching an OS API or constructing a
//! request. Composition happens once, in `heyl-cli`.
//!
//! Two of these are ports for reasons that have nothing to do with the OS.
//! [`Clock`] and [`RandomSource`] isolate what the core cannot control — time
//! and randomness — so that every generated key and every timestamp is
//! deterministic under test. [`HeylApi`] is a driven port like any other, so
//! `heyl-app` cannot tell gRPC from a fake.
//!
//! # Why `#[async_trait]`
//!
//! Rust 1.91 has native `async fn` in traits, but a natively-async trait is not
//! `dyn`-compatible, so every use case would grow a type parameter per port —
//! four of them, for anything that touches the backend, the keychain, the clock
//! and randomness at once. A boxed future is noise next to a network round
//! trip, so the ports box and `heyl-app` holds `&dyn`.

pub mod api;
pub mod clock;
pub mod error;
pub mod random;
pub mod secret_store;
pub mod terminal;

pub use api::HeylApi;
pub use clock::Clock;
pub use error::{ApiError, PortError};
pub use random::RandomSource;
pub use secret_store::{SecretKey, SecretStore, StoredSecret};
pub use terminal::Terminal;
