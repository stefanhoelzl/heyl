//! The two ports a scenario has to control, in one file.
//!
//! A scenario is several `heyl` processes in a row, so anything that must
//! outlive one of them has nowhere else to go. Two things do:
//!
//! * **the keychain** — `recovery` stores a token and a session key that
//!   `doctor` reads back. `KeyringStore` would write them into the user's real
//!   login keyring under the same service name their own session uses, and CI
//!   has no Secret Service at all; `HeadlessSecretStore` cannot write. keyring
//!   4 ships both a file store and a mock, and `Cargo.toml` bans them: an
//!   on-disk credential store is at odds with DESIGN.md §3. This honours that
//!   ban by being unreachable in a build anyone gets — it exists only under
//!   `test-ports`, which is off by default.
//!
//! * **the draw counter** — a recorded unlock grant is sealed to the session
//!   key the *recording* derived, so a replay has to draw the same bytes. The
//!   sequence is stated by the scenario (`meta.session_seed` first, then
//!   counter bytes), and it has to continue across process boundaries: if each
//!   step restarted at draw zero, two steps would derive the same session key
//!   and `rekey` would need a notion of steps to re-seal against. Persisting
//!   the counter beside the secrets means a four-step scenario draws exactly
//!   what one process would have drawn.
//!
//! Neither is a fake of anything: the store really stores and the draws really
//! continue. What they are not is *secure* — which is why this file cannot be
//! reached from a release build.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use heyl_ports::{PortError, RandomSource, SecretKey, SecretStore};
use zeroize::Zeroizing;

/// What is on disk between two steps of a scenario.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct State {
    /// Slot name → value, as `SecretStore` sees them.
    #[serde(default)]
    secrets: BTreeMap<String, String>,
    /// How many times `fill` has been called, across every step so far.
    #[serde(default)]
    draws: u8,
}

/// The keychain and the random source, for one scenario run.
///
/// Bound only when `HEYL_STORE` is set in a build made with `test-ports`.
#[derive(Debug)]
pub struct TestState {
    path: PathBuf,
    /// The first 32-byte draw, when a scenario stated one.
    ///
    /// Absent while *recording*: a recording draws from the OS, and `rekey`
    /// substitutes the synthetic material afterwards. Binding the scenario's
    /// sequence then would put predictable key material on a live account.
    seed: Option<[u8; 32]>,
    /// Serialises the read-modify-write; a step is one process, but a use case
    /// may still draw from two tasks.
    lock: Mutex<()>,
}

impl TestState {
    /// The variable naming the state file.
    pub const STORE_ENV: &'static str = "HEYL_STORE";
    /// The variable carrying the scenario's `meta.session_seed`, base64.
    pub const SEED_ENV: &'static str = "HEYL_SEED";

    /// Build one from the environment, if a scenario put it there.
    ///
    /// Returns [`None`] when `HEYL_STORE` is unset — which is every ordinary
    /// invocation, including every one a user ever makes. `HEYL_SEED` beside it
    /// additionally binds the draw sequence; without it the OS random source
    /// stays, which is what a *recording* wants.
    ///
    /// # Errors
    /// A message, if the seed is set but malformed. Failing loudly matters: a
    /// replay that silently fell back to `OsRandom` would fail later, deep in a
    /// decryption, for a reason that looks nothing like the cause.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(path) = std::env::var_os(Self::STORE_ENV) else {
            return Ok(None);
        };
        let seed = std::env::var(Self::SEED_ENV).ok();
        Ok(Some(Self::new(Path::new(&path), seed.as_deref())?))
    }

    /// Build one explicitly.
    ///
    /// # Errors
    /// A message, if the seed is given and is not 32 base64-encoded bytes.
    pub fn new(path: &Path, seed_base64: Option<&str>) -> Result<Self, String> {
        use base64::Engine as _;
        let seed = seed_base64
            .map(|raw| {
                base64::engine::general_purpose::STANDARD
                    .decode(raw)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or_else(|| format!("{} is not 32 base64 bytes", Self::SEED_ENV))
            })
            .transpose()?;
        Ok(Self {
            path: path.to_owned(),
            seed,
            lock: Mutex::new(()),
        })
    }

    /// Whether this state also states the draw sequence.
    ///
    /// A recording binds the store but not the randomness.
    #[must_use]
    pub const fn drives_randomness(&self) -> bool {
        self.seed.is_some()
    }

    fn read(&self) -> State {
        // A missing file is the first step of a scenario, not an error.
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    fn save(&self, state: &State) -> Result<(), PortError> {
        let unavailable =
            |operation: &'static str, reason: String| PortError::Unavailable { operation, reason };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| unavailable("create the test state directory", e.to_string()))?;
        }
        let body = serde_json::to_string_pretty(state)
            .map_err(|e| unavailable("render the test state", e.to_string()))?;
        std::fs::write(&self.path, body)
            .map_err(|e| unavailable("write the test state", e.to_string()))?;

        // The file holds a session key. Nothing here is a secret worth
        // protecting — every byte is synthetic — but a fixture that models
        // careless handling is a fixture someone copies.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn slot(key: &SecretKey) -> String {
        format!("{}/{}", key.service(), key.secret.name())
    }
}

#[async_trait::async_trait]
impl SecretStore for TestState {
    async fn get(&self, key: &SecretKey) -> Result<Zeroizing<String>, PortError> {
        let _guard = self.lock.lock().expect("not poisoned");
        self.read()
            .secrets
            .get(&Self::slot(key))
            .map(|value| Zeroizing::new(value.clone()))
            .ok_or(PortError::NotFound {
                what: key.secret.name(),
            })
    }

    async fn set(&self, key: &SecretKey, value: &str) -> Result<(), PortError> {
        let _guard = self.lock.lock().expect("not poisoned");
        let mut state = self.read();
        state.secrets.insert(Self::slot(key), value.to_owned());
        self.save(&state)
    }

    async fn delete(&self, key: &SecretKey) -> Result<(), PortError> {
        let _guard = self.lock.lock().expect("not poisoned");
        let mut state = self.read();
        state.secrets.remove(&Self::slot(key));
        self.save(&state)
    }
}

impl RandomSource for TestState {
    /// The scenario's stated sequence: its seed first, then counter bytes.
    ///
    /// The seed goes to the first 32-byte draw because that is the one a
    /// recovery turns into the session encryption key; everything after it is
    /// a nonce or an ephemeral key, which only has to be *reproducible*, and
    /// `rekey` re-seals the corpus against exactly these values.
    fn fill(&self, out: &mut [u8]) {
        let Some(seed) = self.seed else {
            // Bound as a store only, which is what a recording does.
            return crate::OsRandom.fill(out);
        };
        let _guard = self.lock.lock().expect("not poisoned");
        let mut state = self.read();
        state.draws = state.draws.wrapping_add(1);
        if state.draws == 1 && out.len() == 32 {
            out.copy_from_slice(&seed);
        } else {
            out.fill(state.draws);
        }
        // A failure here would silently desynchronise the sequence from what
        // the corpus was sealed against, so it is worth being loud about.
        self.save(&state)
            .expect("the test state file must be writable");
    }
}
