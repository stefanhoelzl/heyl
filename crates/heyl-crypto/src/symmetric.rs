//! XSalsa20-Poly1305 secretbox.
//!
//! Wire format is heylogin's, not the library's: `nonce(24) ‖ box`.

use crypto_secretbox::{
    XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroizing;

use crate::{
    context::SymmetricContext,
    error::CryptoError,
    kdf::{SEED_LEN, derive_secret_from_seed},
    secret::SecretBytes,
};

/// Secretbox nonce length.
pub const NONCE_LEN: usize = 24;

/// A 24-byte secretbox nonce.
///
/// Supplied by the caller rather than generated internally: `heyl-crypto` is
/// strictly deterministic, so `heyl-app` draws the bytes from the
/// `RandomSource` port. That is what makes ciphertext fixture-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Wrap 24 random bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw nonce. Not secret.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// A symmetric encryption key — `vaultSecret`, `protectedSecret`, or any other
/// 32-byte secretbox key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymKey(SecretBytes<32>);

impl SymKey {
    /// `deriveSymEncryptionKey(seed, secondary, ctx)`.
    ///
    /// # Errors
    /// Propagates [`derive_secret_from_seed`].
    pub fn derive(
        seed: &[u8; SEED_LEN],
        secondary: Option<&[u8; SEED_LEN]>,
        ctx: SymmetricContext,
    ) -> Result<Self, CryptoError> {
        let mut key = SecretBytes::zeroed();
        let mut buf = Zeroizing::new([0u8; 32]);
        derive_secret_from_seed(seed, secondary, &ctx.salt(), buf.as_mut_slice())?;
        key.fill_from(buf.as_slice());
        Ok(Self(key))
    }

    /// Adopt raw key bytes — e.g. a `vaultSecret` just unwrapped from a lock.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SecretBytes::from_bytes(bytes))
    }

    /// Adopt raw key bytes from a slice.
    ///
    /// # Errors
    /// [`CryptoError::BadLength`] if not exactly 32 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(SecretBytes::try_from_slice(slice)?))
    }

    /// The raw key bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// Whether the key's buffer is `mlock`ed.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    /// `symEncrypt` — returns `nonce ‖ box`.
    ///
    /// # Panics
    /// Never in practice: XSalsa20-Poly1305 encryption of an in-memory buffer
    /// has no failure mode short of an allocation failure.
    #[must_use]
    pub fn encrypt(&self, nonce: &Nonce, plaintext: &[u8]) -> Vec<u8> {
        let cipher = XSalsa20Poly1305::new(self.expose_secret().into());
        let box_ = cipher
            .encrypt(nonce.as_bytes().into(), plaintext)
            .expect("XSalsa20Poly1305 encryption is infallible for in-memory buffers");

        let mut out = Vec::with_capacity(NONCE_LEN + box_.len());
        out.extend_from_slice(nonce.as_bytes());
        out.extend_from_slice(&box_);
        out
    }

    /// `symDecrypt` — splits `nonce ‖ box` and opens it.
    ///
    /// # Errors
    /// [`CryptoError::TooShort`] if the blob cannot hold a nonce and a tag,
    /// [`CryptoError::Authentication`] if the tag does not verify.
    pub fn decrypt(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        const MIN: usize = NONCE_LEN + 16;
        if blob.len() < MIN {
            return Err(CryptoError::TooShort {
                len: blob.len(),
                min: MIN,
            });
        }
        let (nonce, box_) = blob.split_at(NONCE_LEN);

        let cipher = XSalsa20Poly1305::new(self.expose_secret().into());
        cipher
            .decrypt(nonce.into(), box_)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Authentication)
    }
}
