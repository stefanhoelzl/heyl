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

    /// A fresh X25519 private key — this session's, or an ephemeral sender key.
    fn encryption_private_key(&self) -> EncryptionPrivateKey {
        let mut bytes = [0u8; heyl_crypto::asymmetric::KEY_LEN];
        self.fill(&mut bytes);
        EncryptionPrivateKey::from_bytes(&bytes)
    }
}
