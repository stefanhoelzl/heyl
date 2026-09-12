//! Sessions: the devices this machine has on the account.
//!
//! A **slot** is a local name for one session — its keychain entries, and the
//! identity a caller runs under. `HEYL_SESSION` or `--session` picks one;
//! `default` is the one you get when you say nothing. Slots exist so that a
//! human and an agent can hold opposite policies on the same account at the
//! same time: your own slot caches its unlock for the day, an agent's re-asks,
//! and your phone can tell them apart because each publishes its own name.
//!
//! # What lives where, and what it costs
//!
//! | State | Where | Cost to change |
//! |---|---|---|
//! | token, session key, session id | this machine's keychain | nothing |
//! | timeout, `strict`, `auto-extend` | the session record, behind the token | nothing |
//! | display name, icon | the **META vault**, E2EE | an unlock |
//!
//! That last row is why [`set`] may ask for a swipe and the rest never do: the
//! description is vault content, so writing it needs the seed. It is also the
//! only string the phone shows when it asks you to approve an unlock, which is
//! what makes naming slots worth doing at all.
//!
//! # The seed
//!
//! Never persisted, in any flow here. It exists in memory for the length of one
//! invocation — pair, register, zeroize — exactly as [`crate::recovery`] does.
//! The keychain gains a session id, which identifies but does not decrypt.

use heyl_domain::{
    ICON_CLI, SessionId, SessionMetadata, SessionPolicy, SessionType, Timestamp, sign_challenge,
};
use heyl_ports::{QrStyle, SecretKey, SessionUnlockGrant, SessionUpdate, StoredSecret};

use crate::{AppError, Ports, unlock::Unlocked};

mod lifecycle;
mod settings;

pub use lifecycle::{Created, Removed, create, finish, lock, remove, unlock_and_wait};
pub use settings::{Setting, SettingValue, SlotStatus, get, list, parse_timeout, set};

/// The default slot's name, when the user names none.
pub const DEFAULT_SLOT: &str = "default";

/// What the default slot calls itself on your phone.
///
/// Named slots default to their own name; only this one gets a friendlier
/// label, because "default" says nothing useful on an approval screen.
pub const DEFAULT_DISPLAY: &str = "heyl CLI";

/// One local session identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    name: Option<String>,
}

impl Slot {
    /// The slot a caller named, or the default one.
    #[must_use]
    pub fn new(name: Option<&str>) -> Self {
        Self {
            name: name
                .filter(|n| !n.is_empty() && *n != DEFAULT_SLOT)
                .map(str::to_owned),
        }
    }

    /// What to call this slot in output.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or(DEFAULT_SLOT)
    }

    /// The display name to publish when the user gave none.
    #[must_use]
    pub fn default_display(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| DEFAULT_DISPLAY.to_owned())
    }

    /// One of this slot's keychain items.
    #[must_use]
    pub fn key(&self, secret: StoredSecret) -> SecretKey {
        self.name.as_ref().map_or_else(
            || SecretKey::default_slot(secret),
            |name| SecretKey::in_slot(name.clone(), secret),
        )
    }
}

/// Every slot this machine knows about, default first.
///
/// The index is a plain JSON array in the keychain, kept because no keychain
/// offers a portable way to enumerate itself. It is advisory: a slot missing
/// from it still works when named, it just will not be listed.
///
/// # Errors
/// Never for a missing or unparseable index — that reads as "no slots", since
/// refusing to list because the index is odd would be worse than listing
/// nothing.
pub async fn slots(ports: &Ports<'_>) -> Vec<String> {
    let raw = ports
        .store
        .get(&SecretKey::default_slot(StoredSecret::SlotIndex))
        .await
        .ok();
    raw.and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .unwrap_or_default()
}

/// Record a slot in the index, if it is not there already.
async fn index_add(ports: &Ports<'_>, slot: &Slot) -> Result<(), AppError> {
    let mut names = slots(ports).await;
    let name = slot.name().to_owned();
    if !names.contains(&name) {
        names.push(name);
        write_index(ports, &names).await?;
    }
    Ok(())
}

/// Drop a slot from the index.
async fn index_remove(ports: &Ports<'_>, slot: &Slot) -> Result<(), AppError> {
    let mut names = slots(ports).await;
    names.retain(|n| n != slot.name());
    write_index(ports, &names).await
}

async fn write_index(ports: &Ports<'_>, names: &[String]) -> Result<(), AppError> {
    let json = serde_json::to_string(names).map_err(|_| AppError::MalformedSlot {
        slot: "index".to_owned(),
        what: "slot index does not serialize",
    })?;
    ports
        .store
        .set(&SecretKey::default_slot(StoredSecret::SlotIndex), &json)
        .await
        .map_err(AppError::Port)
}

/// A slot's stored credentials, adopted for this invocation.
pub struct Adopted {
    /// Which session these belong to.
    pub session_id: SessionId,
    /// The session's X25519 private key, which opens an unlock grant.
    pub session_key: heyl_crypto::EncryptionPrivateKey,
}

/// Load a slot's credentials and point the API at them.
///
/// # Errors
/// [`AppError::Port`] if the slot has no keychain entries — which is what
/// "this slot does not exist" looks like from here.
pub async fn adopt(ports: &Ports<'_>, slot: &Slot) -> Result<Adopted, AppError> {
    let token = ports
        .store
        .get(&slot.key(StoredSecret::AccessToken))
        .await?;
    let session_id = ports.store.get(&slot.key(StoredSecret::SessionId)).await?;
    let session_key = crate::recovery::decode_key(
        &ports
            .store
            .get(&slot.key(StoredSecret::SessionPrivateKey))
            .await?,
    )?;

    ports.api.set_access_token(Some(&token)).await;

    Ok(Adopted {
        session_id: SessionId::parse(&session_id).map_err(|_| AppError::MalformedSlot {
            slot: slot.name().to_owned(),
            what: "session_id is not a UUID",
        })?,
        session_key,
    })
}

/// Whether a slot has credentials at all.
pub async fn exists(ports: &Ports<'_>, slot: &Slot) -> bool {
    ports
        .store
        .get(&slot.key(StoredSecret::AccessToken))
        .await
        .is_ok()
}

/// Forget a slot's keychain entries.
///
/// # Errors
/// [`AppError::Port`] if the keychain refuses a delete.
pub async fn forget(ports: &Ports<'_>, slot: &Slot) -> Result<(), AppError> {
    for secret in StoredSecret::ALL {
        ports.store.delete(&slot.key(secret)).await?;
    }
    Ok(())
}

/// Build the entry this session publishes about itself.
///
/// `encPubKeySignature` is made with the authenticator's **identity** key, so
/// this is only possible while unlocked — it can never happen during an
/// ordinary read (DESIGN.md §3). Without it the phone refuses to unlock us,
/// and the unlock request becomes a notification with nothing behind it.
fn metadata(
    session: &Unlocked,
    session_key: &heyl_crypto::EncryptionPrivateKey,
    description: String,
    now: Timestamp,
) -> SessionMetadata {
    use base64::Engine as _;

    let public = session_key.public_key();
    let signature = session.keys.identity_signing_key().sign(
        heyl_crypto::context::SESSION_ENCRYPTION_SIGNATURE,
        public.as_bytes(),
    );
    let b64 = base64::engine::general_purpose::STANDARD;

    SessionMetadata {
        description: Some(description),
        icon_type: Some(ICON_CLI.to_owned()),
        // False, always: heyl is unlocked by the phone, never by itself.
        is_self_unlocking: false,
        enc_pub_key: b64.encode(public.as_bytes()),
        enc_pub_key_signature: b64.encode(signature.as_bytes()),
        signing_auth_id: session.authenticator_id,
        creation_time: now,
        edit_time: now,
        is_deleted: false,
        update_time: now,
    }
}

/// Push a slot's policy to the session record.
///
/// Both fields ride on `SessionService.Update`, which needs only the token —
/// no unlock, and it works on a locked session.
async fn write_policy(
    ports: &Ports<'_>,
    session_id: SessionId,
    policy: SessionPolicy,
    existing_client_settings: &str,
) -> Result<(), AppError> {
    let client_settings = policy
        .to_client_settings(existing_client_settings)
        .map_err(|_| AppError::MalformedSlot {
            slot: session_id.to_string(),
            what: "policy does not serialize",
        })?;

    ports
        .api
        .update_session(
            session_id,
            SessionUpdate {
                unlock_time_limit_minutes: Some(policy.timeout_minutes),
                client_settings: Some(client_settings),
            },
        )
        .await
        .map_err(AppError::Api)
}

/// The self-grant attached to `CreateTokens` when `--unlock` was asked for.
///
/// heylogin's own `finishChallenge` always sends this; heyl only does when the
/// user asks, because a session that starts with a window nobody approved for
/// it contradicts the point of a strict slot.
fn self_grant(
    ports: &Ports<'_>,
    session_key: &heyl_crypto::EncryptionPrivateKey,
    seed: &heyl_crypto::Seed,
) -> SessionUnlockGrant {
    SessionUnlockGrant {
        encrypted_secret: session_key.public_key().seal(
            &ports.random.ephemeral_key(),
            &ports.random.nonce(),
            seed.expose_secret(),
        ),
        expires_at: ports.clock.next_unlock_deadline(),
    }
}

/// The session type every heyl session is: a connected device, as a paired
/// browser is. Not `SELF_UNLOCKING_PRIMARY`, which is the phone's own.
const SESSION_TYPE: SessionType = SessionType::Connected;

/// Sign a pairing challenge with the seed the phone just handed over.
fn respond(seed: &heyl_crypto::Seed, challenge: &str) -> Result<heyl_crypto::Signature, AppError> {
    sign_challenge(seed, challenge, heyl_domain::ChallengeEncoding::Utf8).map_err(AppError::Domain)
}

/// Where the phone points when it scans our code.
///
/// `heylogin.app/qr/#<base64url(pubKey)>` — the trailing slash and the padding
/// stripped from the fragment are both load-bearing: `parseQrUri` matches the
/// path exactly and `decodeBase64Urlsafe` re-pads what it is given.
fn pair_url(public: &heyl_crypto::EncryptionPublicKey) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes());
    format!("https://heylogin.app/qr/#{encoded}")
}

/// Show the pairing code, and always print the URL under it.
///
/// The URL is the difference between a recoverable and an unrecoverable
/// attempt: a code can fail to scan for reasons nobody can see — polarity,
/// cell aspect, a font that substitutes the block glyphs (DESIGN.md §5).
fn show_pairing(ports: &Ports<'_>, url: &str, style: QrStyle) {
    ports.terminal.note("scan this with the heylogin app:");
    let drawn = ports.terminal.render_qr(url, style);
    if !drawn {
        ports.terminal.note("(no terminal to draw on)");
    }
    ports.terminal.note(url);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use heyl_ports::{PortError, SecretStore};
    use zeroize::Zeroizing;

    use super::*;

    /// A keychain in memory. The keychain is one of the ports the corpus does
    /// not cover — there is no backend to record — so it stays a fake.
    #[derive(Default)]
    struct MemoryStore {
        items: Mutex<HashMap<String, String>>,
    }

    impl MemoryStore {
        fn slot_of(key: &SecretKey) -> String {
            format!("{}/{}", key.service(), key.secret.name())
        }
    }

    #[async_trait::async_trait]
    impl SecretStore for MemoryStore {
        async fn get(&self, key: &SecretKey) -> Result<Zeroizing<String>, PortError> {
            self.items
                .lock()
                .expect("not poisoned")
                .get(&Self::slot_of(key))
                .map(|v| Zeroizing::new(v.clone()))
                .ok_or(PortError::NotFound {
                    what: key.secret.name(),
                })
        }

        async fn set(&self, key: &SecretKey, value: &str) -> Result<(), PortError> {
            self.items
                .lock()
                .expect("not poisoned")
                .insert(Self::slot_of(key), value.to_owned());
            Ok(())
        }

        async fn delete(&self, key: &SecretKey) -> Result<(), PortError> {
            self.items
                .lock()
                .expect("not poisoned")
                .remove(&Self::slot_of(key));
            Ok(())
        }
    }

    #[test]
    fn the_default_slot_has_several_spellings() {
        for spelling in [None, Some(""), Some(DEFAULT_SLOT)] {
            let slot = Slot::new(spelling);
            assert_eq!(slot.name(), DEFAULT_SLOT, "{spelling:?}");
            assert_eq!(slot.default_display(), DEFAULT_DISPLAY);
            assert_eq!(
                slot.key(StoredSecret::AccessToken),
                SecretKey::default_slot(StoredSecret::AccessToken),
                "{spelling:?} must reach the unnamed keychain service"
            );
        }
    }

    /// A named slot displays as its own name: "default" would say nothing
    /// useful on an approval screen, but "claude-code" says everything.
    #[test]
    fn a_named_slot_names_itself_on_the_phone() {
        let slot = Slot::new(Some("claude-code"));
        assert_eq!(slot.name(), "claude-code");
        assert_eq!(slot.default_display(), "claude-code");
    }

    #[test]
    fn slots_do_not_share_keychain_entries() {
        let mine = Slot::new(Some("claude-code")).key(StoredSecret::AccessToken);
        let theirs = Slot::new(Some("ci")).key(StoredSecret::AccessToken);
        let default = Slot::new(None).key(StoredSecret::AccessToken);
        assert_ne!(mine.service(), theirs.service());
        assert_ne!(mine.service(), default.service());
    }

    /// The index is what `session list` enumerates; a keychain cannot be
    /// listed portably, so losing this loses the listing.
    #[tokio::test]
    async fn the_index_round_trips_and_deduplicates() {
        let store = MemoryStore::default();
        let ports = ports(&store);

        index_add(&ports, &Slot::new(None)).await.expect("adds");
        index_add(&ports, &Slot::new(Some("claude-code")))
            .await
            .expect("adds");
        index_add(&ports, &Slot::new(Some("claude-code")))
            .await
            .expect("adds again");

        assert_eq!(slots(&ports).await, vec!["default", "claude-code"]);

        index_remove(&ports, &Slot::new(Some("claude-code")))
            .await
            .expect("removes");
        assert_eq!(slots(&ports).await, vec!["default"]);
    }

    /// A machine with no index has no slots — not an error.
    #[tokio::test]
    async fn an_absent_index_reads_as_empty() {
        let store = MemoryStore::default();
        assert!(slots(&ports(&store)).await.is_empty());
    }

    /// Removing one slot must not take the others' entry with it, which is
    /// why `SlotIndex` is not in `StoredSecret::ALL`.
    #[tokio::test]
    async fn forgetting_a_slot_leaves_the_index_alone() {
        let store = MemoryStore::default();
        let ports = ports(&store);
        let slot = Slot::new(Some("claude-code"));

        index_add(&ports, &slot).await.expect("adds");
        store
            .set(&slot.key(StoredSecret::AccessToken), "token")
            .await
            .expect("stores");

        forget(&ports, &slot).await.expect("forgets");

        assert!(!exists(&ports, &slot).await, "credentials are gone");
        assert_eq!(slots(&ports).await, vec!["claude-code"], "index survives");
    }

    fn ports(store: &MemoryStore) -> Ports<'_> {
        Ports {
            api: &NoApi,
            store,
            terminal: &NoTerminal,
            clock: &NoClock,
            random: &NoRandom,
        }
    }

    // The other ports are unreachable in these tests; a call would be a bug.
    struct NoApi;
    struct NoTerminal;
    struct NoClock;
    struct NoRandom;

    macro_rules! unreachable_port {
        ($($tt:tt)*) => {
            unreachable!("these tests touch only the keychain")
        };
    }

    #[async_trait::async_trait]
    impl heyl_ports::HeylApi for NoApi {
        async fn set_access_token(&self, _token: Option<&str>) {}
        async fn create_challenge(
            &self,
            _email: &str,
        ) -> Result<heyl_domain::Challenge, heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn create_tokens(
            &self,
            _a: heyl_domain::AuthenticatorId,
            _c: &str,
            _r: &[u8],
            _t: SessionType,
            _u: Option<SessionUnlockGrant>,
        ) -> Result<heyl_domain::Tokens, heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn refresh_token(&self) -> Result<String, heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn sync(&self) -> Result<heyl_domain::SyncSnapshot, heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn list_authenticators(
            &self,
        ) -> Result<Vec<heyl_domain::Authenticator>, heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn create_long_poll_channel_challenge(
            &self,
            _hash: &str,
        ) -> Result<heyl_ports::LongPollChallenge, heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn update_session(
            &self,
            _s: SessionId,
            _u: SessionUpdate,
        ) -> Result<(), heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn request_session_unlock(&self, _source: &str) -> Result<(), heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn delete_session_unlock(&self, _s: SessionId) -> Result<(), heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn delete_session(&self, _s: SessionId) -> Result<(), heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn create_commit(
            &self,
            _v: heyl_domain::VaultId,
            _l: heyl_domain::CommitId,
            _b: Vec<u8>,
            _t: Timestamp,
        ) -> Result<heyl_domain::CommitId, heyl_ports::ApiError> {
            unreachable_port!()
        }
        async fn list_commits(
            &self,
            _v: heyl_domain::VaultId,
        ) -> Result<heyl_domain::VaultCommits, heyl_ports::ApiError> {
            unreachable_port!()
        }
    }

    impl heyl_ports::Terminal for NoTerminal {
        fn is_interactive(&self) -> bool {
            false
        }
        fn prompt_line(&self, _p: &str) -> Result<String, heyl_ports::PortError> {
            unreachable_port!()
        }
        fn prompt_hidden(
            &self,
            _p: &str,
        ) -> Result<zeroize::Zeroizing<String>, heyl_ports::PortError> {
            unreachable_port!()
        }
        fn read_line(&self) -> Result<zeroize::Zeroizing<String>, heyl_ports::PortError> {
            unreachable_port!()
        }
        fn note(&self, _m: &str) {}
        fn render_qr(&self, _p: &str, _s: QrStyle) -> bool {
            false
        }
    }

    #[async_trait::async_trait]
    impl heyl_ports::Clock for NoClock {
        fn now(&self) -> Timestamp {
            unreachable_port!()
        }
        fn next_unlock_deadline(&self) -> Timestamp {
            unreachable_port!()
        }
        async fn sleep_millis(&self, _millis: u64) {}
    }

    impl heyl_ports::RandomSource for NoRandom {
        fn fill(&self, _out: &mut [u8]) {
            unreachable_port!()
        }
    }
}
