//! Vault and authenticator kinds.

/// The ten vault types, mapping onto five content schemas (DESIGN.md §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum VaultType {
    /// Session registry and account settings.
    Meta,
    /// The user's own logins.
    Private,
    /// A team's shared logins.
    Team,
    /// A team's names and membership.
    TeamMeta,
    /// Logins in transit to the user.
    Inbox,
    /// The inbox's metadata.
    InboxMeta,
    /// An organisation-managed personal vault.
    OrganizationPersonal,
    /// Organisation admin surface. Out of scope for v1 (DESIGN.md §2).
    OrganizationAdmin,
    /// Organisation login summary. Out of scope for v1.
    OrganizationLoginSummary,
}

impl VaultType {
    /// Whether v1 can read this vault.
    ///
    /// The two organisation-side types need schemas we deliberately do not
    /// implement, so they are reported rather than guessed at.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        !matches!(
            self,
            Self::OrganizationAdmin | Self::OrganizationLoginSummary
        )
    }

    /// Whether this vault's content is a `LoginVaultContentV2`.
    ///
    /// Every credential in the system lives in that schema, so team logins
    /// parse with exactly the same code as personal ones.
    #[must_use]
    pub const fn holds_logins(self) -> bool {
        matches!(
            self,
            Self::Private | Self::Team | Self::Inbox | Self::OrganizationPersonal
        )
    }
}

/// How an authenticator's seed is obtained (§4).
///
/// Values match `domain.AuthenticatorType` on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum AuthenticatorType {
    /// Phone secure element, delivered by a swipe.
    Push,
    /// `Argon2id` over a recovery code.
    BackupCode,
    /// OS-backed backup of the seed.
    BackupOs,
    /// Seed stored in plaintext in `secretInfo`. **Test-only** — see
    /// DESIGN.md §6; never a user-facing auth method.
    Dummy,
    /// A session's time-limited unlock grant (§6).
    SessionUnlock,
    /// A FIDO2 key's PRF output (M9).
    Webauthn,
    /// An organisation admin-created service profile. Out of scope for v1.
    OrganizationService,
}

impl AuthenticatorType {
    /// Whether v1 can log in with this authenticator.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Push | Self::BackupCode)
    }
}
