//! Ed25519 signing.
//!
//! `sign(key, data, ctx) = Ed25519.sign(utf8(ctx) ‖ data)` — the context is
//! prefixed to the *message*, not mixed into the key.

use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey as DalekSigningKey, Verifier,
    VerifyingKey as DalekVerifyingKey,
};
use zeroize::Zeroizing;

use crate::{
    context::{SignatureContext, SigningContext},
    error::CryptoError,
    kdf::{SEED_LEN, derive_secret_from_seed},
    secret::SecretBytes,
};

/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Ed25519 public key length.
pub const PUBLIC_KEY_LEN: usize = 32;

/// An Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wrap raw signature bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// Wrap raw signature bytes from a slice.
    ///
    /// # Errors
    /// [`CryptoError::BadLength`] if not exactly 64 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; SIGNATURE_LEN] = slice.try_into().map_err(|_| CryptoError::BadLength {
            len: slice.len(),
            expected: SIGNATURE_LEN,
        })?;
        Ok(Self(bytes))
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

/// An Ed25519 public key. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey([u8; PUBLIC_KEY_LEN]);

impl VerifyingKey {
    /// Wrap raw public-key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Wrap raw public-key bytes from a slice.
    ///
    /// # Errors
    /// [`CryptoError::BadLength`] if not exactly 32 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; PUBLIC_KEY_LEN] = slice.try_into().map_err(|_| CryptoError::BadLength {
            len: slice.len(),
            expected: PUBLIC_KEY_LEN,
        })?;
        Ok(Self(bytes))
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Verify a signature made with a [`SignatureContext`].
    #[must_use]
    pub fn verify(&self, ctx: SignatureContext, data: &[u8], sig: &Signature) -> bool {
        self.verify_raw(Some(&ctx.salt()), data, sig)
    }

    /// Verify a signature over an unprefixed message — the login challenge.
    #[must_use]
    pub fn verify_unprefixed(&self, data: &[u8], sig: &Signature) -> bool {
        self.verify_raw(None, data, sig)
    }

    fn verify_raw(&self, salt: Option<&str>, data: &[u8], sig: &Signature) -> bool {
        let Ok(key) = DalekVerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let message = prefixed(salt, data);
        key.verify(&message, &DalekSignature::from_bytes(&sig.0))
            .is_ok()
    }
}

/// An Ed25519 signing key, held as its 32-byte seed — heylogin's own
/// representation (`loadSigningPrivateKeyFromSeed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKey(SecretBytes<SEED_LEN>);

impl SigningKey {
    /// `deriveSigningKeyPair(seed, secondary, ctx)` — the private half.
    ///
    /// # Errors
    /// Propagates [`derive_secret_from_seed`].
    pub fn derive(
        seed: &[u8; SEED_LEN],
        secondary: Option<&[u8; SEED_LEN]>,
        ctx: SigningContext,
    ) -> Result<Self, CryptoError> {
        let mut key = SecretBytes::zeroed();
        let mut buf = Zeroizing::new([0u8; SEED_LEN]);
        derive_secret_from_seed(seed, secondary, &ctx.salt(), buf.as_mut_slice())?;
        key.fill_from(buf.as_slice());
        Ok(Self(key))
    }

    /// Adopt a raw Ed25519 seed.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SEED_LEN]) -> Self {
        Self(SecretBytes::from_bytes(bytes))
    }

    /// The raw seed. Secret.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; SEED_LEN] {
        self.0.expose_secret()
    }

    /// Whether the key's buffer is `mlock`ed.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(
            DalekSigningKey::from_bytes(self.expose_secret())
                .verifying_key()
                .to_bytes(),
        )
    }

    /// Sign `data` with a context prefixed to the message.
    #[must_use]
    pub fn sign(&self, ctx: SignatureContext, data: &[u8]) -> Signature {
        self.sign_raw(Some(&ctx.salt()), data)
    }

    /// Sign an unprefixed message.
    ///
    /// This is the login challenge response: `CredentialService.CreateTokens`
    /// verifies `Ed25519.sign(challenge)` with no context prefix.
    #[must_use]
    pub fn sign_unprefixed(&self, data: &[u8]) -> Signature {
        self.sign_raw(None, data)
    }

    fn sign_raw(&self, salt: Option<&str>, data: &[u8]) -> Signature {
        let key = DalekSigningKey::from_bytes(self.expose_secret());
        let message = prefixed(salt, data);
        Signature(key.sign(&message).to_bytes())
    }
}

fn prefixed(salt: Option<&str>, data: &[u8]) -> Vec<u8> {
    match salt {
        None => data.to_vec(),
        Some(salt) => {
            let mut m = Vec::with_capacity(salt.len() + data.len());
            m.extend_from_slice(salt.as_bytes());
            m.extend_from_slice(data);
            m
        }
    }
}
