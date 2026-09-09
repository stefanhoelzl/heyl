//! Fake ports, so the core is exercised with no network, no keychain and no
//! terminal (DESIGN.md §6).

pub mod account;

use std::sync::Mutex;

use heyl_domain::{
    Authenticator, AuthenticatorId, Challenge, SyncSnapshot, Timestamp, Tokens, VaultCommits,
    VaultId,
};
use heyl_ports::{
    ApiError, Clock, HeylApi, PortError, RandomSource, SecretKey, SecretStore, Terminal,
    api::SessionUnlockGrant,
};
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
}

/// A clock frozen at a chosen instant.
pub struct FixedClock {
    /// What `now` reports.
    pub now: Timestamp,
    /// What `next_unlock_deadline` reports.
    pub deadline: Timestamp,
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.now
    }
    fn next_unlock_deadline(&self) -> Timestamp {
        self.deadline
    }
}

/// Counter-based "randomness", so every generated key is reproducible.
///
/// `heyl-crypto` is strictly deterministic precisely so this works: nonces and
/// ephemeral keys arrive as explicit bytes rather than being drawn inside a
/// primitive, which is what makes a sealed blob pinnable at all.
#[derive(Default)]
pub struct CountingRandom {
    next: Mutex<u8>,
}

impl RandomSource for CountingRandom {
    fn fill(&self, out: &mut [u8]) {
        let mut next = self.next.lock().expect("not poisoned");
        *next = next.wrapping_add(1);
        out.fill(*next);
    }
}

/// A fake heylogin.
pub struct FakeBackend {
    /// What `CreateChallenge` answers.
    pub challenge: Challenge,
    /// What `CreateTokens` answers once the signature verifies.
    pub tokens: Tokens,
    /// What `Sync` answers.
    pub sync: Mutex<SyncSnapshot>,
    /// What `AuthenticatorService.List` answers.
    pub authenticators: Vec<Authenticator>,
    /// What `ListCommits` answers, per vault.
    pub commits: std::collections::HashMap<VaultId, VaultCommits>,
    /// Verifies the login signature, so the fake pins the signing input rather
    /// than accepting anything — otherwise a regression there would pass every
    /// offline test.
    pub login_verifier: heyl_crypto::VerifyingKey,
    /// Which encoding the signature is expected under.
    pub encoding: heyl_domain::ChallengeEncoding,
    /// Which session type the backend accepts.
    pub session_type: heyl_domain::SessionType,
    calls: Mutex<Vec<&'static str>>,
    token: Mutex<Option<String>>,
    /// When set, `create_tokens` fails with this instead of answering.
    pub refuse_with: Mutex<Option<ApiError>>,
}

impl FakeBackend {
    /// Build one.
    pub fn new(
        challenge: Challenge,
        tokens: Tokens,
        sync: SyncSnapshot,
        authenticators: Vec<Authenticator>,
        commits: std::collections::HashMap<VaultId, VaultCommits>,
        login_verifier: heyl_crypto::VerifyingKey,
    ) -> Self {
        Self {
            challenge,
            tokens,
            sync: Mutex::new(sync),
            authenticators,
            commits,
            login_verifier,
            encoding: heyl_domain::ChallengeEncoding::Utf8,
            session_type: heyl_domain::SessionType::BackupCode,
            calls: Mutex::new(Vec::new()),
            token: Mutex::new(None),
            refuse_with: Mutex::new(None),
        }
    }

    fn record(&self, call: &'static str) {
        self.calls.lock().expect("not poisoned").push(call);
    }

    /// Which calls were made, in order.
    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("not poisoned").clone()
    }

    /// The token the client is currently presenting.
    pub fn presented_token(&self) -> Option<String> {
        self.token.lock().expect("not poisoned").clone()
    }

    /// Make the next `Sync` ask for a token refresh, then stop asking.
    pub fn demand_token_refresh(&self) {
        self.sync.lock().expect("not poisoned").token_refresh_needed = true;
    }
}

#[async_trait::async_trait]
impl HeylApi for FakeBackend {
    async fn set_access_token(&self, token: Option<&str>) {
        *self.token.lock().expect("not poisoned") = token.map(str::to_owned);
    }

    async fn create_challenge(&self, _email: &str) -> Result<Challenge, ApiError> {
        self.record("create_challenge");
        Ok(self.challenge.clone())
    }

    async fn create_tokens(
        &self,
        _authenticator_id: AuthenticatorId,
        challenge: &str,
        response: &[u8],
        session_type: heyl_domain::SessionType,
        unlock: Option<SessionUnlockGrant>,
    ) -> Result<Tokens, ApiError> {
        self.record("create_tokens");

        if let Some(refusal) = self.refuse_with.lock().expect("not poisoned").take() {
            return Err(refusal);
        }

        assert_eq!(
            session_type, self.session_type,
            "login must send the session type the backend accepts"
        );

        let signature = heyl_crypto::Signature::try_from_slice(response)
            .map_err(|_| ApiError::PermissionDenied { domain_code: None })?;
        let signed = self
            .encoding
            .bytes_to_sign(challenge)
            .map_err(|_| ApiError::PermissionDenied { domain_code: None })?;
        if !self.login_verifier.verify_unprefixed(&signed, &signature) {
            return Err(ApiError::PermissionDenied {
                domain_code: Some(30420),
            });
        }

        assert!(
            unlock.is_some(),
            "M2 must self-grant an unlock at login, or a later invocation cannot decrypt"
        );
        Ok(self.tokens.clone())
    }

    async fn refresh_token(&self) -> Result<String, ApiError> {
        self.record("refresh_token");
        // Stop demanding it, so the caller's re-sync terminates.
        self.sync.lock().expect("not poisoned").token_refresh_needed = false;
        Ok("refreshed-token".to_owned())
    }

    async fn sync(&self) -> Result<SyncSnapshot, ApiError> {
        self.record("sync");
        Ok(self.sync.lock().expect("not poisoned").clone())
    }

    async fn list_authenticators(&self) -> Result<Vec<Authenticator>, ApiError> {
        self.record("list_authenticators");
        Ok(self.authenticators.clone())
    }

    async fn list_commits(&self, vault: VaultId) -> Result<VaultCommits, ApiError> {
        self.record("list_commits");
        self.commits
            .get(&vault)
            .cloned()
            .ok_or_else(|| ApiError::MalformedResponse {
                what: format!("no commits for {vault}"),
            })
    }
}
