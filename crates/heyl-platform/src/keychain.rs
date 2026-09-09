//! The OS keychain, via `keyring`.
//!
//! macOS Keychain, Windows Credential Manager, Linux Secret Service and
//! keyutils behind one API, so this adapter has no OS-specific code of its own.
//!
//! Exactly two items are stored, under the service name
//! [`heyl_ports::SecretKey::service`] renders — `heyl` for the default slot.
//! Both are visible to the user in seahorse or Keychain Access, which is what
//! makes README's "the keychain holds only a session token and a session
//! private key" a claim they can check rather than one they must take on trust.

use heyl_ports::{PortError, SecretKey, SecretStore};
use zeroize::Zeroizing;

/// The real keychain.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringStore;

impl KeyringStore {
    fn entry(key: &SecretKey) -> Result<keyring::Entry, PortError> {
        keyring::Entry::new(&key.service(), key.secret.name()).map_err(|e| PortError::Unavailable {
            operation: "open the keychain entry",
            reason: e.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl SecretStore for KeyringStore {
    async fn get(&self, key: &SecretKey) -> Result<Zeroizing<String>, PortError> {
        match Self::entry(key)?.get_password() {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(keyring::Error::NoEntry) => Err(PortError::NotFound {
                what: key.secret.name(),
            }),
            Err(e) => Err(PortError::Unavailable {
                operation: "read from the keychain",
                reason: e.to_string(),
            }),
        }
    }

    async fn set(&self, key: &SecretKey, value: &str) -> Result<(), PortError> {
        Self::entry(key)?
            .set_password(value)
            .map_err(|e| PortError::Unavailable {
                operation: "write to the keychain",
                reason: e.to_string(),
            })
    }

    async fn delete(&self, key: &SecretKey) -> Result<(), PortError> {
        match Self::entry(key)?.delete_credential() {
            // Deleting something that is not there is what the caller wanted.
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(PortError::Unavailable {
                operation: "delete from the keychain",
                reason: e.to_string(),
            }),
        }
    }
}
