//! The keychain: exactly two items, neither of which decrypts anything.

use zeroize::Zeroizing;

use crate::error::PortError;

/// Which of the two stored items.
///
/// The seed is **never** here. A stolen laptop yields a token and a session
/// key; once the unlock window has closed, neither opens a vault. That is the
/// central security property of the design (DESIGN.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoredSecret {
    /// The bearer token for the backend.
    AccessToken,
    /// This session's X25519 private key, which opens the unlock grant.
    SessionPrivateKey,
    /// The names of every slot this machine has, as a JSON array.
    ///
    /// **Not a secret, and not per-session**: it lives once, in the default
    /// slot's service, because a keychain offers no portable way to enumerate
    /// what is in it. Without it `heyl session list` could only ever describe
    /// the slot it was told about.
    SlotIndex,
    /// This session's id.
    ///
    /// **Not a secret**: it identifies, it does not decrypt, so §3's claim
    /// that the keychain holds nothing which opens a vault is unchanged. It is
    /// stored because a later invocation cannot derive it — the access token's
    /// JWT carries the *user* id and a token id, and `SyncUpdate` names every
    /// session of the account without saying which one is us. Locking
    /// ourselves, setting our timeout and writing our own `SessionMetadata`
    /// entry all address the session by id.
    SessionId,
}

impl StoredSecret {
    /// Every item, for `logout` and for `doctor`'s report.
    /// The three items a *session* owns.
    ///
    /// [`Self::SlotIndex`] is deliberately not here: it belongs to the machine
    /// rather than to any one session, and removing a slot must not delete the
    /// list of the others.
    pub const ALL: [Self; 3] = [Self::AccessToken, Self::SessionPrivateKey, Self::SessionId];

    /// The name this item is stored under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::SessionPrivateKey => "session_priv_key",
            Self::SessionId => "session_id",
            Self::SlotIndex => "slots",
        }
    }
}

/// A stored item, scoped to an account slot.
///
/// The slot is a **user-chosen label**, not the heylogin `userId`: a later
/// invocation has to *read* the token before it knows anything about the
/// account, and this client persists nothing to disk to look it up
/// (DESIGN.md §3). M2 only ever constructs [`SecretKey::default_slot`]; the
/// label exists so multi-account is later a CLI change with no migration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretKey {
    /// `None` is the unnamed default slot.
    pub account: Option<String>,
    /// Which item.
    pub secret: StoredSecret,
}

impl SecretKey {
    /// An item in the default, unnamed slot.
    #[must_use]
    pub const fn default_slot(secret: StoredSecret) -> Self {
        Self {
            account: None,
            secret,
        }
    }

    /// An item in a named slot.
    #[must_use]
    pub fn in_slot(account: impl Into<String>, secret: StoredSecret) -> Self {
        Self {
            account: Some(account.into()),
            secret,
        }
    }

    /// The keyring *service* name: `heyl`, or `heyl:<label>`.
    ///
    /// Rendered here rather than in the adapter so every implementation —
    /// including the headless one and the fakes — agrees on the naming.
    #[must_use]
    pub fn service(&self) -> String {
        self.account
            .as_ref()
            .map_or_else(|| "heyl".to_owned(), |account| format!("heyl:{account}"))
    }
}

/// Where the two items live.
///
/// Bound to the OS keychain normally, to `HEYL_TOKEN` / `HEYL_SESSION_KEY` on a
/// headless box, and to an in-memory fake under test — an adapter swap, not a
/// special case threaded through the code (DESIGN.md §5).
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    /// Fetch an item.
    ///
    /// # Errors
    /// [`PortError::NotFound`] if absent; [`PortError::Unavailable`] if the
    /// backing store could not be reached.
    async fn get(&self, key: &SecretKey) -> Result<Zeroizing<String>, PortError>;

    /// Store an item, replacing any current value.
    ///
    /// # Errors
    /// [`PortError::Unavailable`] if the backing store refused.
    async fn set(&self, key: &SecretKey, value: &str) -> Result<(), PortError>;

    /// Remove an item. Removing an absent item succeeds.
    ///
    /// # Errors
    /// [`PortError::Unavailable`] if the backing store refused.
    async fn delete(&self, key: &SecretKey) -> Result<(), PortError>;
}
