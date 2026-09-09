//! AES-256-GCM, for the "newer material" `deriveSecretFromSeedModern` keys.
//!
//! **No v1 path exercises this.** It is implemented because the spec records
//! that heylogin has such material without saying where, and ~20 lines now
//! turns meeting it during M3 into a non-event rather than a surprise.

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroizing;

use crate::{error::CryptoError, secret::SecretBytes};

/// AES-GCM nonce length.
pub const GCM_NONCE_LEN: usize = 12;

/// An AES-256-GCM key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcmKey(SecretBytes<32>);

impl AesGcmKey {
    /// Adopt raw key bytes, e.g. from
    /// [`derive_secret_from_seed_modern`](crate::derive_secret_from_seed_modern).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SecretBytes::from_bytes(bytes))
    }

    /// The raw key bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// Encrypt, returning `nonce ‖ ciphertext‖tag`.
    ///
    /// The nonce is supplied by the caller: this crate is deterministic.
    ///
    /// # Panics
    /// Never in practice: AES-GCM encryption of an in-memory buffer has no
    /// failure mode short of an allocation failure.
    #[must_use]
    pub fn encrypt(&self, nonce: &[u8; GCM_NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(self.expose_secret().into());
        let ct = cipher
            .encrypt(nonce.into(), plaintext)
            .expect("AES-GCM encryption is infallible for in-memory buffers");

        let mut out = Vec::with_capacity(GCM_NONCE_LEN + ct.len());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt `nonce ‖ ciphertext‖tag`.
    ///
    /// # Errors
    /// [`CryptoError::TooShort`] or [`CryptoError::Authentication`].
    ///
    /// # Panics
    /// Never: the length check above guarantees the nonce slice is exactly
    /// [`GCM_NONCE_LEN`] bytes.
    pub fn decrypt(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        const MIN: usize = GCM_NONCE_LEN + 16;
        if blob.len() < MIN {
            return Err(CryptoError::TooShort {
                len: blob.len(),
                min: MIN,
            });
        }
        let (nonce, ct) = blob.split_at(GCM_NONCE_LEN);
        let nonce: &[u8; GCM_NONCE_LEN] = nonce.try_into().expect("split_at guarantees the length");

        let cipher = Aes256Gcm::new(self.expose_secret().into());
        cipher
            .decrypt(nonce.into(), ct)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Authentication)
    }
}
