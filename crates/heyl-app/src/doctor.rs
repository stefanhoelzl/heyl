//! `heyl doctor` — the hierarchy, checked link by link.
//!
//! This is what confirms M1's reverse engineering against the backend, and it
//! does it two ways at once.
//!
//! **By comparison.** The backend publishes the public half of every key we
//! derive — profile keys in `SyncUpdate.profiles`, authenticator keys via
//! `AuthenticatorService.List`. Deriving each and comparing bytes names a wrong
//! context salt *directly*, instead of letting it surface three links
//! downstream as an opaque authentication failure. That is the difference
//! between "crypto is broken" and "link 4 is broken".
//!
//! **By decryption.** Every vault, both tiers: unwrap `vaultSecret` and
//! `protectedSecret` — both asym opens authenticate, which proves links 3, 4,
//! 7 and 8 — then `symDecrypt` the newest commit blob and decode its framing.
//!
//! The walk **never aborts**. Reporting eight links and stopping at the third
//! would turn an eight-link diagnostic into a one-link one, and the whole
//! value of this command is seeing every failure at once.

use heyl_domain::{HighSecurity, Profile, ProfileSeed, Storable, VaultId, VaultSummary, VaultType};

use crate::{AppError, Ports, unlock};

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Derived and published agree, or the vault opened.
    Pass,
    /// They disagree, or it did not open.
    Fail,
    /// Nothing to compare against, or not something v1 reads.
    Skip,
}

impl Outcome {
    /// How this prints.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

/// One line of the report.
#[derive(Debug, Clone)]
pub struct Check {
    /// What was checked, e.g. `link 3 · profile storable vault-key encryption`.
    pub name: String,
    /// How it came out.
    pub outcome: Outcome,
    /// Why, when that is not obvious. Never contains key material.
    pub detail: Option<String>,
}

impl Check {
    fn new(name: impl Into<String>, outcome: Outcome) -> Self {
        Self {
            name: name.into(),
            outcome,
            detail: None,
        }
    }

    fn with(name: impl Into<String>, outcome: Outcome, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome,
            detail: Some(detail.into()),
        }
    }

    /// Compare a derived public key against the published one.
    ///
    /// A key the backend does not publish is [`Outcome::Skip`], not a failure:
    /// absence is normal for some tiers and proves nothing either way.
    fn compare<T: PartialEq>(name: impl Into<String>, derived: &T, published: Option<&T>) -> Self {
        match published {
            None => Self::with(
                name,
                Outcome::Skip,
                "the backend publishes no key to compare",
            ),
            Some(published) if published == derived => Self::new(name, Outcome::Pass),
            Some(_) => Self::with(
                name,
                Outcome::Fail,
                "derived key does not match the published one — the context salt for this link is wrong",
            ),
        }
    }
}

/// The whole report.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Every check, in the order they were run.
    pub checks: Vec<Check>,
}

impl Report {
    fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    /// Whether anything failed.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.outcome == Outcome::Fail)
    }

    /// How many checks came out each way.
    #[must_use]
    pub fn tally(&self) -> (usize, usize, usize) {
        let count = |o| self.checks.iter().filter(|c| c.outcome == o).count();
        (
            count(Outcome::Pass),
            count(Outcome::Fail),
            count(Outcome::Skip),
        )
    }
}

/// Walk the chain and report.
///
/// # Errors
/// Only for failures that make the walk impossible at all — no unlock, no
/// profile. Anything narrower is a [`Check`] with [`Outcome::Fail`], because a
/// report that stops at the first problem is not a diagnostic.
pub async fn run(ports: &Ports<'_>) -> Result<Report, AppError> {
    let session = unlock::run(ports).await?;
    run_with(ports, session).await
}

/// The same, on a session the caller already unlocked.
///
/// Split out so an ordinary command can do the unlocking — which may mean
/// asking the phone and waiting — before the report starts.
///
/// # Errors
/// As [`run`].
pub async fn run_with(ports: &Ports<'_>, session: unlock::Unlocked) -> Result<Report, AppError> {
    let mut report = Report::default();

    report.push(Check::with(
        "session · unlock grant",
        Outcome::Pass,
        format!(
            "seed recovered from authenticator {}",
            session.authenticator_id
        ),
    ));

    check_authenticator_keys(&mut report, &session);

    let profile_ids = check_profiles(&mut report, &session)?;

    for vault in &session.sync.vaults {
        check_vault(ports, &mut report, &session, vault, &profile_ids).await;
    }

    Ok(report)
}

/// Links 1 and 2, plus the profile-seed encryption keys.
fn check_authenticator_keys(report: &mut Report, session: &unlock::Unlocked) {
    let Some(authenticator) = session
        .authenticators
        .iter()
        .find(|a| a.id == session.authenticator_id)
    else {
        report.push(Check::new(
            "link 1 · authenticator login signing",
            Outcome::Skip,
        ));
        return;
    };
    let published = &authenticator.public_keys;

    // Link 1 is the one key derived with a null secondary seed, which is what
    // lets login happen before secretSalt is revealed (§4). CreateTokens
    // accepting our signature already proved it; this proves it again offline.
    match heyl_domain::login_signing_key(&session.seed) {
        Ok(key) => report.push(Check::compare(
            "link 1 · authenticator login signing",
            &key.verifying_key(),
            published.login_sig.as_ref(),
        )),
        Err(e) => report.push(Check::with(
            "link 1 · authenticator login signing",
            Outcome::Fail,
            e.to_string(),
        )),
    }

    // Link 2. heylogin declares the storable and high-security constants with
    // identical values, so one derived key is compared against both published
    // slots -- and if they ever diverge, this is where it shows.
    let identity = session.keys.identity_signing_key().verifying_key();
    report.push(Check::compare(
        "link 2 · authenticator identity signing (high-security)",
        &identity,
        published.high_security_identity_sig.as_ref(),
    ));
    report.push(Check::compare(
        "link 2 · authenticator identity signing (storable)",
        &identity,
        published.storable_sig.as_ref(),
    ));
}

/// Links 3 through 8, for every profile we can unlock.
fn check_profiles(
    report: &mut Report,
    session: &unlock::Unlocked,
) -> Result<Vec<heyl_domain::ProfileId>, AppError> {
    let mut unlockable = Vec::new();

    for profile in &session.sync.profiles {
        let Some(lock) = profile.lock_for(session.authenticator_id) else {
            report.push(Check::with(
                format!("profile {} · authenticator lock", profile.id),
                Outcome::Skip,
                "no lock for the authenticator that granted our unlock",
            ));
            continue;
        };

        let storable = session
            .keys
            .unlock_storable_profile_seed(lock, &profile.key_generation_id);
        let high = session
            .keys
            .unlock_high_security_profile_seed(lock, &profile.key_generation_id);

        match (storable, high) {
            (Ok(storable), Ok(high)) => {
                report.push(Check::new(
                    format!("profile {} · both seeds unwrapped", profile.id),
                    Outcome::Pass,
                ));
                check_profile_keys(report, profile, &storable, &high);
                unlockable.push(profile.id);
            }
            (storable, high) => {
                let reason = storable
                    .err()
                    .map(|e| e.to_string())
                    .or_else(|| high.err().map(|e| e.to_string()))
                    .unwrap_or_default();
                report.push(Check::with(
                    format!("profile {} · seed unwrap", profile.id),
                    Outcome::Fail,
                    reason,
                ));
            }
        }
    }

    if unlockable.is_empty() {
        return Err(AppError::NoUnlockableProfile {
            authenticator_id: session.authenticator_id,
        });
    }
    Ok(unlockable)
}

/// The six profile-layer links, each against its published key.
fn check_profile_keys(
    report: &mut Report,
    profile: &Profile,
    storable: &ProfileSeed<Storable>,
    high: &ProfileSeed<HighSecurity>,
) {
    let published = &profile.public_keys;
    let id = profile.id;

    compare_derived(
        report,
        format!("link 3 · profile {id} storable vault-key encryption"),
        storable.vault_key_encryption_key().map(|k| k.public_key()),
        published.storable_vault_key_enc.as_ref(),
    );
    compare_derived(
        report,
        format!("link 4 · profile {id} high-security vault-key encryption"),
        high.vault_key_encryption_key().map(|k| k.public_key()),
        published.high_security_vault_key_enc.as_ref(),
    );
    compare_derived(
        report,
        format!("link 5 · profile {id} storable identity signing"),
        storable.identity_signing_key().map(|k| k.verifying_key()),
        published.storable_sig.as_ref(),
    );
    compare_derived(
        report,
        format!("link 6 · profile {id} high-security identity signing"),
        high.identity_signing_key().map(|k| k.verifying_key()),
        published.high_security_identity_sig.as_ref(),
    );
    // Links 7 and 8 are the ProfileProfileLock chain, which v1 does not walk --
    // but the backend publishes the keys, so they cost one comparison each and
    // a wrong context here would otherwise stay invisible until an admin flow.
    compare_derived(
        report,
        format!("link 7 · profile {id} storable profile-key encryption"),
        storable
            .profile_key_encryption_key()
            .map(|k| k.public_key()),
        published.storable_profile_seed_enc.as_ref(),
    );
    compare_derived(
        report,
        format!("link 8 · profile {id} high-security profile-key encryption"),
        high.profile_key_encryption_key().map(|k| k.public_key()),
        published.high_security_profile_seed_enc.as_ref(),
    );
}

fn compare_derived<T: PartialEq>(
    report: &mut Report,
    name: String,
    derived: Result<T, heyl_domain::DomainError>,
    published: Option<&T>,
) {
    match derived {
        Ok(derived) => report.push(Check::compare(name, &derived, published)),
        Err(e) => report.push(Check::with(name, Outcome::Fail, e.to_string())),
    }
}

/// One vault: both tiers unwrapped, newest commit decrypted and framed.
async fn check_vault(
    ports: &Ports<'_>,
    report: &mut Report,
    session: &unlock::Unlocked,
    vault: &VaultSummary,
    unlockable: &[heyl_domain::ProfileId],
) {
    let name = format!("vault {} ({:?})", vault.id, vault.vault_type);

    if !vault.vault_type.is_supported() {
        report.push(Check::with(
            name,
            Outcome::Skip,
            "organisation-side schema, out of scope for v1",
        ));
        return;
    }

    match open_vault(ports, session, vault, unlockable).await {
        Ok(detail) => report.push(Check::with(name, Outcome::Pass, detail)),
        Err(e) => report.push(Check::with(name, Outcome::Fail, e.to_string())),
    }
}

async fn open_vault(
    ports: &Ports<'_>,
    session: &unlock::Unlocked,
    vault: &VaultSummary,
    unlockable: &[heyl_domain::ProfileId],
) -> Result<String, AppError> {
    let commits = ports.api.list_commits(vault.id).await?;
    let lock = commits
        .profile_lock
        .ok_or_else(|| vault_err(vault.id, "the backend returned no profile lock"))?;

    if !unlockable.contains(&lock.locking_profile_id) {
        return Err(vault_err(
            vault.id,
            "locked to a profile we cannot unlock from",
        ));
    }
    let profile = session
        .sync
        .profile(lock.locking_profile_id)
        .ok_or_else(|| vault_err(vault.id, "locking profile is not in the sync snapshot"))?;
    let profile_lock = profile.lock_for(session.authenticator_id).ok_or_else(|| {
        vault_err(
            vault.id,
            "locking profile has no lock for our authenticator",
        )
    })?;

    let storable = session
        .keys
        .unlock_storable_profile_seed(profile_lock, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: vault.id,
            source: e,
        })?;
    let high = session
        .keys
        .unlock_high_security_profile_seed(profile_lock, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: vault.id,
            source: e,
        })?;

    // Both opens authenticate, which is what proves links 3/4 for this vault.
    let vault_secret = storable
        .unlock_vault(&lock, profile.id, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: vault.id,
            source: e,
        })?;
    let _protected_secret = high
        .unlock_vault(&lock, profile.id, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: vault.id,
            source: e,
        })?;

    let Some(commit) = commits.commits.last() else {
        return Ok("both tiers unwrapped; vault has no commits to decrypt".to_owned());
    };

    let plaintext = vault_secret
        .key()
        .decrypt(&commit.blob)
        .map_err(AppError::Crypto)?;
    let document = heyl_vault::decode(&plaintext).map_err(|e| AppError::VaultContent {
        vault: vault.id,
        source: e,
    })?;

    Ok(format!(
        "both tiers unwrapped; commit decrypted ({}, {}, descriptor v{}, {} content keys)",
        document.format.name(),
        document.document_type,
        document.version,
        document.content_keys(),
    ))
}

fn vault_err(vault: VaultId, what: &'static str) -> AppError {
    AppError::VaultContent {
        vault,
        source: heyl_vault::VaultError::NotADocument { what },
    }
}

/// Whether this vault type is one v1 reads at all.
///
/// Re-exported so `heyl-cli` can explain a SKIP without importing the domain.
#[must_use]
pub const fn is_supported(vault_type: VaultType) -> bool {
    vault_type.is_supported()
}
