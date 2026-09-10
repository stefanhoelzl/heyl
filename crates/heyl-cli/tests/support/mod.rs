//! Fake ports, so the core is exercised with no network, no keychain and no
//! terminal (DESIGN.md §6).
//!
//! These are the ports the corpus does *not* cover. `HeylApi` is answered from
//! recorded heylogin data through `DomainApi<RecordedApi>`; the keychain, the
//! terminal, the clock and randomness have no backend to record, so they stay
//! fakes. There is no fake *account* any more — that was the thing the corpus
//! replaced.

use std::sync::Mutex;

use heyl_domain::Timestamp;
use heyl_ports::{Clock, PortError, QrStyle, RandomSource, SecretKey, SecretStore, Terminal};
use zeroize::Zeroizing;

/// A keychain in memory.
#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<std::collections::HashMap<String, String>>,
}

impl MemoryStore {
    fn slot(key: &SecretKey) -> String {
        format!("{}/{}", key.service(), key.secret.name())
    }

    /// Seed a value, as a prior `login` would have.
    pub fn put(&self, key: &SecretKey, value: &str) {
        self.items
            .lock()
            .expect("not poisoned")
            .insert(Self::slot(key), value.to_owned());
    }
}

#[async_trait::async_trait]
impl SecretStore for MemoryStore {
    async fn get(&self, key: &SecretKey) -> Result<Zeroizing<String>, PortError> {
        self.items
            .lock()
            .expect("not poisoned")
            .get(&Self::slot(key))
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or(PortError::NotFound {
                what: key.secret.name(),
            })
    }

    async fn set(&self, key: &SecretKey, value: &str) -> Result<(), PortError> {
        self.put(key, value);
        Ok(())
    }

    async fn delete(&self, key: &SecretKey) -> Result<(), PortError> {
        self.items
            .lock()
            .expect("not poisoned")
            .remove(&Self::slot(key));
        Ok(())
    }
}

/// A terminal that answers from a script.
pub struct ScriptedTerminal {
    interactive: bool,
    answers: Mutex<Vec<String>>,
}

impl ScriptedTerminal {
    /// A terminal that is not a TTY, and so cannot be asked anything.
    pub fn non_interactive() -> Self {
        Self {
            interactive: false,
            answers: Mutex::new(Vec::new()),
        }
    }

    /// Answer these, in order.
    pub fn with(answers: &[&str]) -> Self {
        Self {
            interactive: true,
            answers: Mutex::new(answers.iter().rev().map(|s| (*s).to_owned()).collect()),
        }
    }

    fn pop(&self) -> Result<String, PortError> {
        self.answers
            .lock()
            .expect("not poisoned")
            .pop()
            .ok_or(PortError::Unavailable {
                operation: "read from the scripted terminal",
                reason: "the script ran out of answers".to_owned(),
            })
    }
}

impl Terminal for ScriptedTerminal {
    fn is_interactive(&self) -> bool {
        self.interactive
    }
    fn prompt_line(&self, _prompt: &str) -> Result<String, PortError> {
        self.pop()
    }
    fn prompt_hidden(&self, _prompt: &str) -> Result<Zeroizing<String>, PortError> {
        self.pop().map(Zeroizing::new)
    }
    fn read_line(&self) -> Result<Zeroizing<String>, PortError> {
        self.pop().map(Zeroizing::new)
    }
    fn note(&self, _message: &str) {}

    /// Nothing to draw on under test; the URL is what a caller would use.
    fn render_qr(&self, _payload: &str, _style: QrStyle) -> bool {
        false
    }
}

/// A clock frozen at a chosen instant.
pub struct FixedClock {
    /// What `now` reports.
    pub now: Timestamp,
    /// What `next_unlock_deadline` reports.
    pub deadline: Timestamp,
}

#[async_trait::async_trait]
impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.now
    }
    fn next_unlock_deadline(&self) -> Timestamp {
        self.deadline
    }

    /// Returns immediately: a test that waits for an approval should spend its
    /// time on the assertion, not on the clock.
    async fn sleep_millis(&self, _millis: u64) {}
}

/// Yields the corpus's session seed first, then counts.
///
/// `recovery` derives its session key from the first draw, and the recorded
/// unlock blob was sealed to exactly that key. Everything after it is a nonce
/// or an ephemeral key, where any value does — which is only true because
/// `heyl-crypto` takes randomness as explicit bytes rather than drawing it
/// inside a primitive.
pub struct CorpusRandom {
    session_seed: [u8; 32],
    drawn: Mutex<u8>,
}

impl CorpusRandom {
    /// Draw this seed first.
    pub fn new(session_seed: [u8; 32]) -> Self {
        Self {
            session_seed,
            drawn: Mutex::new(0),
        }
    }
}

impl RandomSource for CorpusRandom {
    fn fill(&self, out: &mut [u8]) {
        let mut n = self.drawn.lock().expect("not poisoned");
        *n = n.wrapping_add(1);
        if *n == 1 && out.len() == 32 {
            out.copy_from_slice(&self.session_seed);
        } else {
            out.fill(*n);
        }
    }
}
