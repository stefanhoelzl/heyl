//! The lock structures the unlock chain consumes (§7).
//!
//! Plain data: `heyl-grpc` maps protobuf messages onto these, and nothing
//! below `heyl-grpc` ever sees a wire type.

use crate::ids::{AuthenticatorId, KeyGenerationId, ProfileId};

/// A profile's seeds, encrypted to one authenticator's keys.
///
/// Both ciphertexts are `nonce ‖ ephemeralPub ‖ box` (§2). They are encrypted
/// to the *same* public key — heylogin's storable and high-security
/// authenticator key contexts hold identical values — but carry **different
/// seeds**, which is where the two tiers actually diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileAuthenticatorLock {
    /// Which authenticator can open this lock.
    pub authenticator_id: AuthenticatorId,
    /// The profile's storable seed, asym-encrypted.
    pub encrypted_storable_profile_seed: Vec<u8>,
    /// The profile's high-security seed, asym-encrypted.
    pub encrypted_high_security_profile_seed: Vec<u8>,
}

/// A vault's secrets, encrypted to one profile's keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultProfileLock {
    /// Which profile can open this lock.
    pub locking_profile_id: ProfileId,
    /// The generation of that profile's keys when the lock was written.
    ///
    /// Checked before any decryption is attempted: a mismatch means the
    /// profile has been re-keyed and the lock is stale, which is a different
    /// failure from a wrong key and is reported as such.
    pub locking_profile_key_generation_id: KeyGenerationId,
    /// `vaultSecret`, asym-encrypted — decrypts vault content.
    pub encrypted_storable_vault_key: Vec<u8>,
    /// `protectedSecret`, asym-encrypted — decrypts passwords, TOTP, cards.
    pub encrypted_high_security_vault_key: Vec<u8>,
    /// An optional X25519 private key for vault messaging, unwrapped with the
    /// same high-security vault key. Absent for ordinary vaults.
    pub encrypted_vault_message_private_key: Option<Vec<u8>>,
}
