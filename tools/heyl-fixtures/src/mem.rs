//! In-memory ports, so a recording runs the real use case without touching the
//! operator's keychain or expecting a terminal.

use std::sync::Mutex;

use heyl_ports::{PortError, SecretKey, SecretStore, Terminal};
use zeroize::Zeroizing;

/// A keychain that exists only for the length of the run.
#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<std::collections::HashMap<String, String>>,
}

#[async_trait::async_trait]
impl SecretStore for MemoryStore {
    async fn get(&self, key: &SecretKey) -> Result<Zeroizing<String>, PortError> {
        self.items
            .lock()
            .expect("not poisoned")
            .get(key.secret.name())
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or(PortError::NotFound {
                what: key.secret.name(),
            })
    }
    async fn set(&self, key: &SecretKey, value: &str) -> Result<(), PortError> {
        self.items
            .lock()
            .expect("not poisoned")
            .insert(key.secret.name().to_owned(), value.to_owned());
        Ok(())
    }
    async fn delete(&self, key: &SecretKey) -> Result<(), PortError> {
        self.items
            .lock()
            .expect("not poisoned")
            .remove(key.secret.name());
        Ok(())
    }
}

/// A terminal that answers the confirmation and nothing else.
pub struct AnsweringTerminal {
    interactive: bool,
}

impl AnsweringTerminal {
    /// `confirmed` mirrors whether `--confirm` was passed: when it was, the
    /// prompt is never reached, so this terminal reports itself as
    /// non-interactive and cannot be asked anything by accident.
    pub const fn new(confirmed: bool) -> Self {
        Self {
            interactive: !confirmed,
        }
    }
}

impl Terminal for AnsweringTerminal {
    fn is_interactive(&self) -> bool {
        self.interactive
    }
    fn prompt_line(&self, prompt: &str) -> Result<String, PortError> {
        heyl_platform::SystemTerminal.prompt_line(prompt)
    }
    fn prompt_hidden(&self, prompt: &str) -> Result<Zeroizing<String>, PortError> {
        heyl_platform::SystemTerminal.prompt_hidden(prompt)
    }
    fn read_line(&self) -> Result<Zeroizing<String>, PortError> {
        heyl_platform::SystemTerminal.read_line()
    }
    fn note(&self, message: &str) {
        heyl_platform::SystemTerminal.note(message);
    }
}
