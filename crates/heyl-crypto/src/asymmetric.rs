//! X25519 + XSalsa20-Poly1305, wire-compatible with tweetnacl's `nacl.box`.
//!
//! Wire format is `nonce(24) ‖ ephemeralPub(32) ‖ box`. The sender key is
//! ephemeral and its public half travels with the message, so the recipient
//! needs nothing but its own private key.

use crypto_box::{PublicKey, SalsaBox, SecretKey, aead::Aead};
use zeroize::Zeroizing;

use crate::{
    context::EncryptionContext,
    error::CryptoError,
    kdf::{SEED_LEN, derive_secret_from_seed},
    secret::SecretBytes,
    symmetric::{NONCE_LEN, Nonce},
};

/// X25519 key length.
pub const KEY_LEN: usize = 32;

/// An X25519 public key. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionPublicKey([u8; KEY_LEN]);

impl EncryptionPublicKey {
    /// Wrap raw public-key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Wrap raw public-key bytes from a slice.
    ///
    /// # Errors
    /// [`CryptoError::BadLength`] if not exactly 32 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; KEY_LEN] = slice.try_into().map_err(|_| CryptoError::BadLength {
            len: slice.len(),
            expected: KEY_LEN,
        })?;
        Ok(Self(bytes))
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// `asymEncrypt` — seal `plaintext` to this key.
    ///
    /// `ephemeral` and `nonce` are supplied by the caller, because this crate
    /// is deterministic; `heyl-app` draws both from the `RandomSource` port.
    /// **`ephemeral` must be freshly generated for every call** — reusing one
    /// across messages reuses the box key.
    ///
    /// # Panics
    /// Never in practice: sealing an in-memory buffer has no failure mode
    /// short of an allocation failure.
    #[must_use]
    pub fn seal(
        &self,
        ephemeral: &EncryptionPrivateKey,
        nonce: &Nonce,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let cipher = SalsaBox::new(&PublicKey::from(self.0), &ephemeral.to_secret_key());
        let box_ = cipher
            .encrypt(nonce.as_bytes().into(), plaintext)
            .expect("SalsaBox encryption is infallible for in-memory buffers");

        let mut out = Vec::with_capacity(NONCE_LEN + KEY_LEN + box_.len());
        out.extend_from_slice(nonce.as_bytes());
        out.extend_from_slice(ephemeral.public_key().as_bytes());
        out.extend_from_slice(&box_);
        out
    }
}

/// An X25519 private key.
///
/// heylogin stores the derived 32 bytes unclamped and lets the curve
/// implementation clamp on use; `x25519_dalek::StaticSecret` does the same, so
/// the two agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionPrivateKey(SecretBytes<KEY_LEN>);

impl EncryptionPrivateKey {
    /// `deriveEncryptionKeyPair(seed, secondary, ctx)` — the private half.
    ///
    /// # Errors
    /// Propagates [`derive_secret_from_seed`].
    pub fn derive(
        seed: &[u8; SEED_LEN],
        secondary: Option<&[u8; SEED_LEN]>,
        ctx: EncryptionContext,
    ) -> Result<Self, CryptoError> {
        let mut key = SecretBytes::zeroed();
        let mut buf = Zeroizing::new([0u8; KEY_LEN]);
        derive_secret_from_seed(seed, secondary, &ctx.salt(), buf.as_mut_slice())?;
        key.fill_from(buf.as_slice());
        Ok(Self(key))
    }

    /// Adopt raw scalar bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Self(SecretBytes::from_bytes(bytes))
    }

    /// Adopt raw scalar bytes from a slice.
    ///
    /// # Errors
    /// [`CryptoError::BadLength`] if not exactly 32 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(SecretBytes::try_from_slice(slice)?))
    }

    /// The raw scalar. Secret.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }

    /// Whether the key's buffer is `mlock`ed.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    fn to_secret_key(&self) -> SecretKey {
        SecretKey::from(*self.expose_secret())
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> EncryptionPublicKey {
        EncryptionPublicKey(self.to_secret_key().public_key().to_bytes())
    }

    /// `asymDecrypt` — open `nonce ‖ ephemeralPub ‖ box`.
    ///
    /// # Errors
    /// [`CryptoError::TooShort`] if the blob cannot hold its own framing,
    /// [`CryptoError::Authentication`] if the tag does not verify.
    ///
    /// # Panics
    /// Never: the length check above guarantees the ephemeral-key slice is
    /// exactly 32 bytes.
    pub fn open(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        const MIN: usize = NONCE_LEN + KEY_LEN + 16;
        if blob.len() < MIN {
            return Err(CryptoError::TooShort {
                len: blob.len(),
                min: MIN,
            });
        }
        let (nonce, rest) = blob.split_at(NONCE_LEN);
        let (eph_pub, box_) = rest.split_at(KEY_LEN);

        let eph: [u8; KEY_LEN] = eph_pub.try_into().expect("split_at guarantees the length");
        let cipher = SalsaBox::new(&PublicKey::from(eph), &self.to_secret_key());
        cipher
            .decrypt(nonce.into(), box_)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Authentication)
    }
}
