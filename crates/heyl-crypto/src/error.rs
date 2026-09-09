//! Error type for every operation in this crate.

/// Anything that can go wrong in `heyl-crypto`.
///
/// Decryption failures are **distinguished** rather than collapsed into one
/// opaque variant. The usual argument for opacity — denying an attacker a
/// padding oracle — does not apply here: we are a client decrypting data we
/// fetched, with nobody querying us. Meanwhile M2 and M3 are exactly where a
/// failed decryption has to be diagnosable, and until M2 there is no oracle to
/// tell a mistyped context from a mis-sliced nonce.
///
/// No variant ever carries key, plaintext or ciphertext bytes.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A ciphertext was shorter than its own framing requires.
    #[error("ciphertext too short: {len} bytes, need at least {min}")]
    TooShort {
        /// Length that was supplied.
        len: usize,
        /// Smallest length the framing allows.
        min: usize,
    },

    /// A key, nonce or seed had the wrong length.
    #[error("expected {expected} bytes, got {len}")]
    BadLength {
        /// Length that was supplied.
        len: usize,
        /// Length the primitive requires.
        expected: usize,
    },

    /// The Poly1305 tag did not verify: wrong key, or corrupt ciphertext.
    #[error("authentication failed")]
    Authentication,

    /// A context string was shorter than the KDF's 8-character minimum.
    ///
    /// Reachable only by constructing a context by hand; every constant in
    /// [`crate::context`] satisfies it.
    #[error("context string too short: {len} characters, need at least 8")]
    ContextTooShort {
        /// Length that was supplied.
        len: usize,
    },

    /// `deriveSecretFromSeed` accepts only 32- or 64-byte outputs.
    #[error("derived-secret length must be 32 or 64, got {len}")]
    BadOutputLength {
        /// Length that was requested.
        len: usize,
    },

    /// A recovery code was not the canonical form heylogin specifies.
    ///
    /// Distinct from a wrong code on purpose: the fix is to retype it in the
    /// documented shape, not to find a different code. Never carries the
    /// value.
    // The shape is described rather than illustrated: an example would put
    // digits in an error message, and no error here may resemble a code.
    #[error("recovery code must be six dash-separated groups of four digits")]
    MalformedRecoveryCode,

    /// Argon2 rejected the parameters, or they exceeded our own bounds.
    #[error("invalid Argon2 parameters: {reason}")]
    Argon2Params {
        /// Why they were rejected. Never contains the recovery code.
        reason: &'static str,
    },
}
