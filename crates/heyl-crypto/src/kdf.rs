//! `deriveSecretFromSeed` and its HMAC variant.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Minimum context length the KDF enforces, from `lib-vault-crypto`.
const MIN_CONTEXT_LEN: usize = 8;

/// Seed length, in bytes. Every seed and secondary seed is exactly this.
pub const SEED_LEN: usize = 32;

/// `deriveSecretFromSeed(seed, secondary, salt, len)`.
///
/// ```text
/// hs  = SHA512(seed)                  # secondary == None
///     = SHA512(seed || secondary)     # else
/// out = SHA512(utf8(salt) || hs)[:len]
/// ```
///
/// `len` must be 32 or 64; the caller's buffer length picks it.
///
/// # Errors
/// [`CryptoError::ContextTooShort`] or [`CryptoError::BadOutputLength`].
pub(crate) fn derive_secret_from_seed(
    seed: &[u8; SEED_LEN],
    secondary: Option<&[u8; SEED_LEN]>,
    salt: &str,
    out: &mut [u8],
) -> Result<(), CryptoError> {
    if salt.len() < MIN_CONTEXT_LEN {
        return Err(CryptoError::ContextTooShort { len: salt.len() });
    }
    if out.len() != 32 && out.len() != 64 {
        return Err(CryptoError::BadOutputLength { len: out.len() });
    }

    let mut first = Sha512::new();
    first.update(seed);
    if let Some(secondary) = secondary {
        first.update(secondary);
    }
    let mut hashed_seed = Zeroizing::new([0u8; 64]);
    hashed_seed.copy_from_slice(&first.finalize());

    let mut second = Sha512::new();
    second.update(salt.as_bytes());
    second.update(hashed_seed.as_slice());
    let mut derived = Zeroizing::new([0u8; 64]);
    derived.copy_from_slice(&second.finalize());

    out.copy_from_slice(&derived[..out.len()]);
    Ok(())
}

/// `deriveSecretFromSeedModern` — `HMAC-SHA256(key = seed[‖secondary], msg = utf8(salt))`.
///
/// heylogin's source is explicit that this is **not** a drop-in replacement for
/// [`derive_secret_from_seed`]: it produces different bytes and exists only for
/// newly derived AES-GCM material. No v1 path exercises it; it is implemented
/// here so that meeting it during M3 is a non-event rather than a surprise.
///
/// Output is fixed at 32 bytes, the native HMAC-SHA256 size.
///
/// # Errors
/// [`CryptoError::ContextTooShort`].
///
/// # Panics
/// Never: HMAC accepts a key of any length.
pub fn derive_secret_from_seed_modern(
    seed: &[u8; SEED_LEN],
    secondary: Option<&[u8; SEED_LEN]>,
    salt: &str,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if salt.len() < MIN_CONTEXT_LEN {
        return Err(CryptoError::ContextTooShort { len: salt.len() });
    }

    // The key is seed‖secondary when a secondary is present.
    let mut key = Zeroizing::new(Vec::with_capacity(SEED_LEN * 2));
    key.extend_from_slice(seed);
    if let Some(secondary) = secondary {
        key.extend_from_slice(secondary);
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_slice())
        .expect("HMAC accepts keys of any length");
    mac.update(salt.as_bytes());

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

/// `hashData` — SHA-512 truncated to 32 bytes.
///
/// heylogin uses this rather than SHA-256 because its crypto was originally
/// libsodium-based, which only exposes SHA-512. Similar to SHA-512/256, but
/// with SHA-512's IV rather than the SHA-512/256 one.
#[must_use]
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    let digest = Sha512::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}
