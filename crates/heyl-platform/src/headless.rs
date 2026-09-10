//! The keychain, for a box that has none.
//!
//! This is what makes CI work on a Linux runner with no Secret Service, and it
//! is a **port implementation** rather than a special case threaded through the
//! code (DESIGN.md §5).
//!
//! It is read-only by nature: there is nowhere to persist to. A `login` under
//! this adapter reports the values it would have stored, on stderr, so a CI job
//! can capture them — rather than failing after a successful login.

use std::env;

use heyl_ports::{PortError, SecretKey, SecretStore, StoredSecret};
use zeroize::Zeroizing;

/// Reads `HEYL_TOKEN` / `HEYL_SESSION_KEY` / `HEYL_SESSION_ID` from the
/// environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeadlessSecretStore;

impl HeadlessSecretStore {
    /// Which variable holds this item.
    #[must_use]
    pub const fn variable(secret: StoredSecret) -> &'static str {
        match secret {
            StoredSecret::AccessToken => "HEYL_TOKEN",
            StoredSecret::SessionPrivateKey => "HEYL_SESSION_KEY",
            StoredSecret::SessionId => "HEYL_SESSION_ID",
            StoredSecret::SlotIndex => "HEYL_SLOTS",
        }
    }

    /// Whether the environment is set up for headless operation at all.
    #[must_use]
    pub fn is_configured() -> bool {
        StoredSecret::ALL
            .iter()
            .any(|s| env::var_os(Self::variable(*s)).is_some())
    }
}

#[async_trait::async_trait]
impl SecretStore for HeadlessSecretStore {
    async fn get(&self, key: &SecretKey) -> Result<Zeroizing<String>, PortError> {
        env::var(Self::variable(key.secret))
            .map(Zeroizing::new)
            .map_err(|_| PortError::NotFound {
                what: Self::variable(key.secret),
            })
    }

    async fn set(&self, key: &SecretKey, _value: &str) -> Result<(), PortError> {
        Err(PortError::Unavailable {
            operation: "write to the environment",
            reason: format!(
                "headless mode cannot persist; set {} yourself",
                Self::variable(key.secret)
            ),
        })
    }

    async fn delete(&self, _key: &SecretKey) -> Result<(), PortError> {
        // Nothing was stored, so nothing needs removing.
        Ok(())
    }
}
