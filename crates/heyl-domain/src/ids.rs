//! Newtyped identifiers.
//!
//! Distinct types so a `ProfileId` cannot be passed where a `VaultId` belongs,
//! with parsing constructors that reject anything that is not a UUID — which
//! is what makes the newtypes worth more than type aliases.

use core::fmt;

use uuid::Uuid;

/// A value that was supposed to be a UUID and was not.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not a valid UUID: {value:?}")]
pub struct ParseIdError {
    /// The rejected input. Identifiers are not secret.
    pub value: String,
}

macro_rules! uuid_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Parse from its canonical string form.
            ///
            /// # Errors
            /// [`ParseIdError`] if `s` is not a UUID.
            pub fn parse(s: &str) -> Result<Self, ParseIdError> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|_| ParseIdError { value: s.to_owned() })
            }

            /// Wrap a UUID directly.
            #[must_use]
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

uuid_id!(
    /// Identifies an authenticator (§4).
    AuthenticatorId
);
uuid_id!(
    /// Identifies a profile (§7).
    ProfileId
);
uuid_id!(
    /// Identifies a vault (§7).
    VaultId
);
uuid_id!(
    /// Identifies a commit in a vault's history (§7).
    CommitId
);
uuid_id!(
    /// Identifies a session (§6).
    SessionId
);
uuid_id!(
    /// Identifies a login within a vault's `logins` list (§7).
    LoginId
);
uuid_id!(
    /// Identifies a custom field on a login.
    ///
    /// Not every custom field has one: entries written by importers after the
    /// heymerge migration can arrive without an `id`, and heylogin invents a
    /// random one on each parse (`CustomField.ts`). heyl never invents one, so
    /// such a field is reachable by name but not by this id (DESIGN.md §5).
    FieldId
);

/// A profile's key generation.
///
/// Every lock records the generation of the profile that created it, and an
/// unlock is **refused** rather than attempted when they disagree — see
/// [`crate::locks`].
///
/// **Opaque on purpose.** Every wire field is a `string`
/// (`ProfileData.key_generation_id`, `VaultProfileLock
/// .locking_profile_key_generation_id`, `SyncUpdate.Vault.generation_id`), and
/// nothing in this client ever interprets one — the only operation is equality.
/// Parsing it into a UUID or a counter would invent a format we do not need and
/// would fail on values that are perfectly usable.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct KeyGenerationId(String);

impl KeyGenerationId {
    /// Adopt the server's value verbatim.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value as the server sent it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyGenerationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
