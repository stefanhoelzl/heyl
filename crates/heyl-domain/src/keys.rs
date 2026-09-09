//! The key hierarchy: authenticator → profile → vault (§3, §7).
//!
//! Every step is a pure function of a seed and a lock, so the whole chain is
//! testable with no network and no account — which matters, because this is
//! where the correctness risk concentrates and nothing confirms it against
//! heylogin until M2.
//!
//! The tier is a **phantom type**. The storable and high-security branches are
//! structurally identical and differ only in which context they derive with,
//! so crossing them is exactly the copy-paste a reviewer would miss. Here it
//! does not compile: [`ProfileSeed<Storable>`] yields a [`VaultSecret`] and
//! [`ProfileSeed<HighSecurity>`] yields a [`ProtectedSecret`], and there is no
//! path between them.

use core::{fmt, marker::PhantomData};

use heyl_crypto::{
    EncryptionPrivateKey, SecretBytes, SecretSalt, Seed, SigningKey, SymKey, Tier, context,
};

use crate::{
    error::DomainError,
    ids::{AuthenticatorId, KeyGenerationId, ProfileId},
    locks::{ProfileAuthenticatorLock, VaultProfileLock},
};

// re-exported for callers writing `ProfileSeed<Storable>`
pub use heyl_crypto::{HighSecurity, Storable};

/// The login signing key: the one authenticator key derived with a **null**
/// secondary seed.
///
/// That is not an accident of the design — it is what lets login happen before
/// the server has revealed `secretSalt`, which it only does *after* a
/// successful `CreateTokens` (§4).
///
/// # Errors
/// Propagates [`heyl_crypto::CryptoError`].
pub fn login_signing_key(seed: &Seed) -> Result<SigningKey, DomainError> {
    Ok(SigningKey::derive(
        seed.expose_secret(),
        None,
        context::AUTHENTICATOR_LOGIN_SIGNING,
    )?)
}

/// The authenticator-level keys that need `secretSalt`.
///
/// heylogin declares separate storable and high-security constants for both of
/// these, with **identical values**, so there is one key of each kind at this
/// layer rather than two. The tiers first diverge at the profile layer, and
/// modelling a distinction that does not exist would only invite the belief
/// that the storable key cannot reach high-security material.
#[derive(Debug, Clone)]
pub struct AuthenticatorKeys {
    id: AuthenticatorId,
    identity_signing: SigningKey,
    profile_seed_encryption: EncryptionPrivateKey,
}

impl AuthenticatorKeys {
    /// Derive from the seed and the server-supplied `secretSalt`.
    ///
    /// # Errors
    /// Propagates [`heyl_crypto::CryptoError`].
    pub fn derive(
        id: AuthenticatorId,
        seed: &Seed,
        secret_salt: &SecretSalt,
    ) -> Result<Self, DomainError> {
        let seed = seed.expose_secret();
        let salt = Some(secret_salt.as_bytes());
        Ok(Self {
            id,
            identity_signing: SigningKey::derive(
                seed,
                salt,
                context::AUTHENTICATOR_IDENTITY_SIGNING,
            )?,
            profile_seed_encryption: EncryptionPrivateKey::derive(
                seed,
                salt,
                context::AUTHENTICATOR_PROFILE_SEED_ENCRYPTION,
            )?,
        })
    }

    /// Which authenticator these belong to.
    #[must_use]
    pub const fn id(&self) -> AuthenticatorId {
        self.id
    }

    /// The identity signing key.
    ///
    /// Signs a session's `encPubKey` for `SessionMetadata` (M5) — which is why
    /// registering the CLI as a device is only possible while unlocked, and
    /// can never happen during an ordinary read (DESIGN.md §3).
    #[must_use]
    pub const fn identity_signing_key(&self) -> &SigningKey {
        &self.identity_signing
    }

    /// Unwrap a profile's storable seed from the lock addressed to us.
    ///
    /// # Errors
    /// [`DomainError::NoLockForAuthenticator`] if the lock is for a different
    /// authenticator; [`DomainError::KeyGenerationMismatch`] if the profile has
    /// been re-keyed since the lock was written; [`DomainError::Crypto`] if it
    /// does not open.
    pub fn unlock_storable_profile_seed(
        &self,
        lock: &ProfileAuthenticatorLock,
        generation: &KeyGenerationId,
    ) -> Result<ProfileSeed<Storable>, DomainError> {
        self.check_lock(lock, generation)?;
        ProfileSeed::from_plaintext(
            &self
                .profile_seed_encryption
                .open(&lock.encrypted_storable_profile_seed)?,
        )
    }

    /// Unwrap a profile's high-security seed from the lock addressed to us.
    ///
    /// # Errors
    /// [`DomainError::NoLockForAuthenticator`] if the lock is for a different
    /// authenticator; [`DomainError::KeyGenerationMismatch`] if the profile has
    /// been re-keyed since the lock was written; [`DomainError::Crypto`] if it
    /// does not open.
    pub fn unlock_high_security_profile_seed(
        &self,
        lock: &ProfileAuthenticatorLock,
        generation: &KeyGenerationId,
    ) -> Result<ProfileSeed<HighSecurity>, DomainError> {
        self.check_lock(lock, generation)?;
        ProfileSeed::from_plaintext(
            &self
                .profile_seed_encryption
                .open(&lock.encrypted_high_security_profile_seed)?,
        )
    }

    fn check_lock(
        &self,
        lock: &ProfileAuthenticatorLock,
        generation: &KeyGenerationId,
    ) -> Result<(), DomainError> {
        if lock.authenticator_id != self.id {
            return Err(DomainError::NoLockForAuthenticator {
                authenticator_id: self.id,
            });
        }
        if lock.profile_key_generation_id != *generation {
            return Err(DomainError::KeyGenerationMismatch {
                profile_id: lock.profile_id,
                profile: generation.clone(),
                lock: lock.profile_key_generation_id.clone(),
            });
        }
        Ok(())
    }
}

/// A profile seed, at one tier.
///
/// Profile keys derive from this with a **null** secondary seed — `secretSalt`
/// belongs to the authenticator layer and does not reach here.
pub struct ProfileSeed<T: Tier> {
    bytes: SecretBytes<32>,
    tier: PhantomData<T>,
}

impl<T: Tier> ProfileSeed<T> {
    /// Adopt raw seed bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            bytes: SecretBytes::from_bytes(bytes),
            tier: PhantomData,
        }
    }

    fn from_plaintext(plaintext: &[u8]) -> Result<Self, DomainError> {
        Ok(Self {
            bytes: SecretBytes::try_from_slice(plaintext)?,
            tier: PhantomData,
        })
    }

    /// The raw seed. Secret.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.bytes.expose_secret()
    }

    /// The profile's identity signing key at this tier.
    ///
    /// # Errors
    /// Propagates [`heyl_crypto::CryptoError`].
    pub fn identity_signing_key(&self) -> Result<SigningKey, DomainError> {
        Ok(SigningKey::derive(
            self.expose_secret(),
            None,
            T::PROFILE_SIGNING,
        )?)
    }

    /// The key that unwraps this tier's vault secret.
    ///
    /// # Errors
    /// Propagates [`heyl_crypto::CryptoError`].
    pub fn vault_key_encryption_key(&self) -> Result<EncryptionPrivateKey, DomainError> {
        Ok(EncryptionPrivateKey::derive(
            self.expose_secret(),
            None,
            T::PROFILE_VAULT_KEY_ENCRYPTION,
        )?)
    }

    /// The key that unwraps a downstream profile's seed at this tier.
    ///
    /// Used by the admin-side `ProfileProfileLock` chain, which v1 does not
    /// implement; derived here because it is one line and the context is known.
    ///
    /// # Errors
    /// Propagates [`heyl_crypto::CryptoError`].
    pub fn profile_key_encryption_key(&self) -> Result<EncryptionPrivateKey, DomainError> {
        Ok(EncryptionPrivateKey::derive(
            self.expose_secret(),
            None,
            T::PROFILE_KEY_ENCRYPTION,
        )?)
    }

    fn check_generation(
        lock: &VaultProfileLock,
        profile_id: ProfileId,
        generation: &KeyGenerationId,
    ) -> Result<(), DomainError> {
        if lock.locking_profile_key_generation_id == *generation {
            Ok(())
        } else {
            Err(DomainError::KeyGenerationMismatch {
                profile_id,
                profile: generation.clone(),
                lock: lock.locking_profile_key_generation_id.clone(),
            })
        }
    }
}

impl ProfileSeed<Storable> {
    /// Unwrap a vault's `vaultSecret`, which decrypts its content.
    ///
    /// # Errors
    /// [`DomainError::KeyGenerationMismatch`] if the profile has been re-keyed
    /// since the lock was written; [`DomainError::Crypto`] if it does not open.
    pub fn unlock_vault(
        &self,
        lock: &VaultProfileLock,
        profile_id: ProfileId,
        generation: &KeyGenerationId,
    ) -> Result<VaultSecret, DomainError> {
        Self::check_generation(lock, profile_id, generation)?;
        let key = self.vault_key_encryption_key()?;
        let plaintext = key.open(&lock.encrypted_storable_vault_key)?;
        Ok(VaultSecret(SymKey::try_from_slice(&plaintext)?))
    }
}

impl ProfileSeed<HighSecurity> {
    /// Unwrap a vault's `protectedSecret`, which decrypts its passwords, TOTP
    /// secrets and card numbers.
    ///
    /// # Errors
    /// [`DomainError::KeyGenerationMismatch`] if the profile has been re-keyed
    /// since the lock was written; [`DomainError::Crypto`] if it does not open.
    pub fn unlock_vault(
        &self,
        lock: &VaultProfileLock,
        profile_id: ProfileId,
        generation: &KeyGenerationId,
    ) -> Result<ProtectedSecret, DomainError> {
        Self::check_generation(lock, profile_id, generation)?;
        let key = self.vault_key_encryption_key()?;
        let plaintext = key.open(&lock.encrypted_high_security_vault_key)?;
        Ok(ProtectedSecret(SymKey::try_from_slice(&plaintext)?))
    }
}

impl<T: Tier> fmt::Debug for ProfileSeed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProfileSeed<{}>(<redacted>)", T::NAME)
    }
}

/// A vault's `vaultSecret`: decrypts commit blobs into vault content.
///
/// Storable tier — it reveals titles, usernames and URLs, never a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSecret(SymKey);

impl VaultSecret {
    /// The underlying key.
    #[must_use]
    pub const fn key(&self) -> &SymKey {
        &self.0
    }
}

/// A vault's `protectedSecret`: decrypts the `ProtectedValue`s inside its
/// content — passwords, TOTP secrets, card numbers.
///
/// High-security tier — deriving it requires the seed, so it exists only
/// while the session is unlocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedSecret(SymKey);

impl ProtectedSecret {
    /// The underlying key.
    #[must_use]
    pub const fn key(&self) -> &SymKey {
        &self.0
    }
}
