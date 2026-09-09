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

/// What kind of session `CreateTokens` is asked to mint (§5, §6).
///
/// Values match `domain.SessionType` on the wire.
///
/// **Which one the recovery path needs is unsettled.** `HEYLOGIN_SPEC` §5 says
/// `SESSION_TYPE_BACKUP_CODE`, but the backend answers `grpc-status 3 —
/// invalid session type` to it from a `CLIENT_TYPE_CLI` client, so the spec
/// and the backend disagree and the spec was written from client source. This
/// is enumerated by `heyl-fixtures probe-signing` the same way the challenge
/// encoding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionType {
    /// The proto3 zero value, indistinguishable on the wire from not setting
    /// the field at all — so "omit it and let the backend decide" is a
    /// candidate the probe has to try.
    Unspecified,
    /// A session that carries its own unlock grant, as the primary device.
    SelfUnlockingPrimary,
    /// The same, as an additional device.
    SelfUnlockingSecondary,
    /// An OS-backed backup session.
    BackupOs,
    /// A session established with a recovery code.
    BackupCode,
    /// A session connected to an already-unlocked one.
    Connected,
}

impl SessionType {
    /// Every value, in wire order — the set the probe sweeps.
    pub const ALL: [Self; 6] = [
        Self::Unspecified,
        Self::SelfUnlockingPrimary,
        Self::SelfUnlockingSecondary,
        Self::BackupOs,
        Self::BackupCode,
        Self::Connected,
    ];

    /// How this prints in a probe report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::SelfUnlockingPrimary => "self-unlocking-primary",
            Self::SelfUnlockingSecondary => "self-unlocking-secondary",
            Self::BackupOs => "backup-os",
            Self::BackupCode => "backup-code",
            Self::Connected => "connected",
        }
    }
}
