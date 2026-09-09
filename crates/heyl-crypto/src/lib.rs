//! heylogin's cryptographic primitives and key derivation.
//!
//! This crate is the **leaf** of the workspace: it depends on no other
//! `heyl-*` crate, on no async runtime, and on no transport. It is also
//! **strictly deterministic** — every function is a total function of its
//! arguments, and randomness (nonces, ephemeral keys) arrives as explicit
//! bytes drawn by `heyl-app` from the `RandomSource` port. That is what makes
//! the *wire format* of [`SymKey::encrypt`] and [`EncryptionPublicKey::seal`]
//! fixture-testable: a fresh internal nonce would make the output unpinnable.
//!
//! # Evidence
//!
//! The primitives are checked against authoritative upstream vectors. The
//! heylogin-specific *composition* — which context, concatenated in which
//! order, truncated where — is not verified against heylogin by anything in
//! this crate, and cannot be offline. A mistyped context yields stable,
//! self-consistent, wrong keys. The guard is M2: `CreateTokens` accepting our
//! signature confirms the login limb, and M2's single vault decrypt confirms
//! the profile and vault limbs. See DESIGN.md §6.
//!
//! # Map to the heylogin bundle
//!
//! Names here are idiomatic Rust rather than transcribed, because the newtypes
//! already carry in the type what heylogin's names carry in the identifier
//! (`symEncrypt` on a `SymKey` would say "sym" twice). This table is the
//! cross-reference; each item's own docs name its origin too.
//!
//! | bundle symbol | this crate |
//! |---|---|
//! | `deriveSecretFromSeed` | [`kdf::derive_secret_from_seed`] (internal; reached via the `derive` constructors) |
//! | `deriveSecretFromSeedModern` | [`derive_secret_from_seed_modern`] |
//! | `hashData` | [`hash_data`] |
//! | `deriveSymEncryptionKey` | [`SymKey::derive`] |
//! | `symEncrypt` / `symDecrypt` | [`SymKey::encrypt`] / [`SymKey::decrypt`] |
//! | `deriveEncryptionKeyPair` | [`EncryptionPrivateKey::derive`] |
//! | `asymEncrypt` / `asymDecrypt` | [`EncryptionPublicKey::seal`] / [`EncryptionPrivateKey::open`] |
//! | `deriveSigningKeyPair` | [`SigningKey::derive`] |
//! | `sign` / `verifySignature` | [`SigningKey::sign`] / [`VerifyingKey::verify`] |
//! | `signEncryptionPublicKey` | [`SigningKey::sign`] with a [`SignatureContext`] |
//! | `calculateRecoverySeed` | [`derive_recovery_seed`] |
//! | `SALT_*` / `FIXED_INFO_*` | [`context`] |
//!
//! Domain nouns stay verbatim: `vaultSecret`, `protectedSecret`, `secretSalt`,
//! storable and high-security.

pub mod aead;
pub mod asymmetric;
pub mod context;
pub mod error;
pub mod kdf;
pub mod recovery;
pub mod secret;
pub mod signing;
pub mod symmetric;

pub use aead::AesGcmKey;
pub use asymmetric::{EncryptionPrivateKey, EncryptionPublicKey};
pub use context::{
    EncryptionContext, HighSecurity, SignatureContext, SigningContext, Storable, SymmetricContext,
    Tier,
};
pub use error::CryptoError;
pub use kdf::{SEED_LEN, derive_secret_from_seed_modern, hash_data};
pub use recovery::{RecoveryParams, derive_recovery_seed};
pub use secret::SecretBytes;
pub use signing::{Signature, SigningKey, VerifyingKey};
pub use symmetric::{Nonce, SymKey};

/// A 32-byte authenticator seed — the root of everything (§3).
///
/// Never persisted, never serialised, never logged. The keychain holds only an
/// access token and a session private key, neither of which decrypts anything
/// (DESIGN.md §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed(SecretBytes<SEED_LEN>);

impl Seed {
    /// Adopt raw seed bytes — from a phone swipe, a recovery code, a FIDO PRF
    /// output, or a session unlock grant.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SEED_LEN]) -> Self {
        Self(SecretBytes::from_bytes(bytes))
    }

    /// Adopt raw seed bytes from a slice.
    ///
    /// # Errors
    /// [`CryptoError::BadLength`] if not exactly 32 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(SecretBytes::try_from_slice(slice)?))
    }

    /// The raw seed. Secret.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; SEED_LEN] {
        self.0.expose_secret()
    }

    /// Whether the seed's buffer is `mlock`ed.
    ///
    /// `false` means the OS refused, typically `RLIMIT_MEMLOCK`. `heyl-cli`
    /// treats that as **fatal** at startup: §3 claims the seed never reaches
    /// swap, and continuing would ship a weaker guarantee than advertised.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }
}

/// A server-stored 32-byte `secretSalt`, mixed into every authenticator key
/// **except the login key** — which is what lets login proceed before the
/// server has revealed it (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretSalt([u8; SEED_LEN]);

impl SecretSalt {
    /// Wrap the server-supplied bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SEED_LEN]) -> Self {
        Self(bytes)
    }

    /// Wrap the server-supplied bytes from a slice.
    ///
    /// # Errors
    /// [`CryptoError::BadLength`] if not exactly 32 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; SEED_LEN] = slice.try_into().map_err(|_| CryptoError::BadLength {
            len: slice.len(),
            expected: SEED_LEN,
        })?;
        Ok(Self(bytes))
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}
