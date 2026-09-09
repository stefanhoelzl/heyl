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

/// A profile's key generation.
///
/// Every lock records the generation of the profile that created it, and an
/// unlock is **refused** rather than attempted when they disagree — see
/// [`crate::locks`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct KeyGenerationId(pub u64);

impl fmt::Display for KeyGenerationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
