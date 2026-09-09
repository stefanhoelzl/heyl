//! Randomness, as an explicit dependency.

use heyl_crypto::{EncryptionPrivateKey, Nonce};

/// The source of every random byte the client draws.
///
/// `heyl-crypto` is **strictly deterministic**: nonces and ephemeral keys
/// arrive as explicit bytes rather than being generated inside a primitive.
/// That is what makes the wire format of `symEncrypt` and `asymEncrypt`
/// fixture-testable at all — a fresh internal nonce would make the output
/// unpinnable (DESIGN.md §4).
pub trait RandomSource: Send + Sync {
    /// Fill `out` with cryptographically secure random bytes.
    fn fill(&self, out: &mut [u8]);

    /// A fresh 24-byte nonce.
    fn nonce(&self) -> Nonce {
        let mut bytes = [0u8; heyl_crypto::symmetric::NONCE_LEN];
        self.fill(&mut bytes);
        Nonce::from_bytes(bytes)
    }

    /// A fresh **ephemeral** X25519 private key, for one `asymEncrypt`.
    ///
    /// heylogin's `asymEncrypt` generates a raw X25519 keypair per message
    /// with no KDF, so this is a raw scalar. The *session* key is different —
    /// it is KDF-derived; see [`heyl_domain::session_encryption_key`] and
    /// [`RandomSource::seed`].
    fn ephemeral_key(&self) -> EncryptionPrivateKey {
        let mut bytes = [0u8; heyl_crypto::asymmetric::KEY_LEN];
        self.fill(&mut bytes);
        EncryptionPrivateKey::from_bytes(&bytes)
    }

    /// A fresh 32-byte seed, to be run through a KDF by the caller.
    fn seed(&self) -> zeroize::Zeroizing<[u8; 32]> {
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        self.fill(bytes.as_mut_slice());
        bytes
    }
}
