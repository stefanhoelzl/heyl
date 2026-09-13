//! The META vault, opened for reading and writing.
//!
//! This is the one vault heyl writes to, and the only exception to "read-only
//! by design": a session registers itself as a named, revocable device
//! (DESIGN.md §2). Everything here therefore follows §3's rails —
//! read-modify-write of the folded state (every commit is a delta;
//! [`open`] folds them with `heyl_vault::fold`), guarded by `latest_commit_id`,
//! preserving unknown keys, refusing to write a descriptor version we do not
//! understand.
//!
//! Opening it needs the seed, so every caller here has an [`unlock::Unlocked`]
//! in hand. That is why `heyl session set display-name` may ask for a swipe
//! while `heyl session set timeout` never does.

use heyl_domain::{CommitId, ProfileId, SyncSnapshot, VaultId, VaultType};
use heyl_vault::Document;

use crate::{AppError, Ports, unlock::Unlocked};

/// A decrypted META vault, and what is needed to write it back.
pub struct MetaVault {
    /// Which vault this is.
    pub id: VaultId,
    /// The document as it was read. Edit this, then [`MetaVault::commit`].
    pub document: Document,
    /// The commit this document came from — the optimistic-concurrency guard.
    latest_commit: CommitId,
    /// The vault's storable key, which both opens and seals its content.
    key: heyl_crypto::SymKey,
}

/// Open the account's META vault.
///
/// # Errors
/// [`AppError::NoMetaVault`] if the account has none (which would mean the
/// account is not in a shape any heylogin client produces), or any failure
/// unwrapping the key chain down to it.
pub async fn open(ports: &Ports<'_>, session: &Unlocked) -> Result<MetaVault, AppError> {
    let summary = session
        .sync
        .vaults
        .iter()
        .find(|v| v.vault_type == VaultType::Meta)
        .ok_or(AppError::NoMetaVault)?;

    let commits = ports.api.list_commits(summary.id).await?;
    let lock = commits
        .profile_lock
        .ok_or_else(|| meta_err(summary.id, "the backend returned no profile lock"))?;

    let profile = session
        .sync
        .profile(lock.locking_profile_id)
        .ok_or_else(|| meta_err(summary.id, "locking profile is not in the sync snapshot"))?;
    let profile_lock = profile
        .lock_for(session.authenticator_id)
        .ok_or_else(|| meta_err(summary.id, "no lock for our authenticator"))?;

    let storable = session
        .keys
        .unlock_storable_profile_seed(profile_lock, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: summary.id,
            source: e,
        })?;
    let vault_secret = storable
        .unlock_vault(&lock, profile.id, &profile.key_generation_id)
        .map_err(|e| AppError::Vault {
            vault: summary.id,
            source: e,
        })?;

    let latest_commit = commits
        .commits
        .last()
        .ok_or_else(|| meta_err(summary.id, "the META vault has no commits"))?
        .id;

    // Commits are deltas: the current document is every commit folded, not the
    // last one (DESIGN.md §3, corrected — `heyl_vault::fold`). Reading only the
    // last would show whichever session was written most recently and miss the
    // rest, which is exactly what made `disambiguate` pick a colliding name.
    let mut documents = Vec::with_capacity(commits.commits.len());
    for commit in &commits.commits {
        let plaintext = vault_secret
            .key()
            .decrypt(&commit.blob)
            .map_err(AppError::Crypto)?;
        documents.push(
            heyl_vault::decode(&plaintext).map_err(|e| AppError::VaultContent {
                vault: summary.id,
                source: e,
            })?,
        );
    }
    let document = heyl_vault::fold(&documents).map_err(|e| AppError::VaultContent {
        vault: summary.id,
        source: e,
    })?;

    Ok(MetaVault {
        id: summary.id,
        document,
        latest_commit,
        key: vault_secret.into_key(),
    })
}

impl MetaVault {
    /// Seal the edited document and commit it.
    ///
    /// On a rejected guard the caller re-reads rather than merging: our entry
    /// is a key no other client owns, so there is never anything to merge
    /// (DESIGN.md §3).
    ///
    /// # Errors
    /// [`AppError::VaultContent`] if the document will not encode,
    /// [`AppError::Api`] if the backend refuses the commit.
    pub async fn commit(self, ports: &Ports<'_>) -> Result<CommitId, AppError> {
        let blob = heyl_vault::encode(&self.document).map_err(|e| AppError::VaultContent {
            vault: self.id,
            source: e,
        })?;
        let sealed = self.key.encrypt(&ports.random.nonce(), &blob);
        ports
            .api
            .create_commit(self.id, self.latest_commit, sealed, ports.clock.now())
            .await
            .map_err(AppError::Api)
    }
}

/// Which profiles this authenticator can open, for callers that need to know
/// before they try.
#[must_use]
pub fn unlockable_profiles(sync: &SyncSnapshot, session: &Unlocked) -> Vec<ProfileId> {
    sync.profiles
        .iter()
        .filter(|p| p.lock_for(session.authenticator_id).is_some())
        .map(|p| p.id)
        .collect()
}

fn meta_err(vault: VaultId, what: &'static str) -> AppError {
    AppError::VaultContent {
        vault,
        source: heyl_vault::VaultError::NotADocument { what },
    }
}
