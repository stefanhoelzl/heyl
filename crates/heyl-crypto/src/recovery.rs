//! Recovery-code seed derivation (`BACKUP_CODE`).
//!
//! `seed = Argon2id(password = utf8(code), salt = saltBase64 decoded, ...)`,
//! with parameters supplied by the server in the authenticator's `secretInfo`.
//!
//! Two details that are easy to get wrong:
//!
//! * the code is hashed **including its dashes** — `1234-5678-…`, not the
//!   digits alone;
//! * the parameters come from the server, so they are attacker-influenced if
//!   the backend is hostile. [`RecoveryParams`] bounds them, so a malicious
//!   `memoryCost` cannot be used to exhaust memory or hang the process.
//!
//! The result is verifiable **offline**: `secretInfo.checksum` is
//! `SHA512(seed)[:32]`, so a mistyped code is rejected before any network call.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::{error::CryptoError, kdf::SEED_LEN};

/// Largest `memoryCost` (KiB) we will accept from the server: 4 GiB.
///
/// heylogin's own parameters are far below this; the bound exists so that a
/// hostile or corrupt `secretInfo` cannot turn a login into an OOM.
pub const MAX_MEMORY_COST_KIB: u32 = 4 * 1024 * 1024;

/// Largest `iterations` we will accept from the server.
pub const MAX_ITERATIONS: u32 = 64;

/// Largest `parallelism` we will accept from the server.
pub const MAX_PARALLELISM: u32 = 64;

/// Argon2id parameters from `RecoverySecretInfo.recoveryParameters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryParams {
    /// `memoryCost`, in KiB.
    pub memory_cost_kib: u32,
    /// `iterations` — Argon2's time cost.
    pub iterations: u32,
    /// `parallelism` — Argon2's lanes.
    pub parallelism: u32,
}

impl RecoveryParams {
    /// Check the server-supplied parameters against our bounds.
    ///
    /// # Errors
    /// [`CryptoError::Argon2Params`] if any bound is exceeded.
    pub fn validate(self) -> Result<(), CryptoError> {
        if self.memory_cost_kib > MAX_MEMORY_COST_KIB {
            return Err(CryptoError::Argon2Params {
                reason: "memoryCost above our bound",
            });
        }
        if self.iterations == 0 || self.iterations > MAX_ITERATIONS {
            return Err(CryptoError::Argon2Params {
                reason: "iterations out of range",
            });
        }
        if self.parallelism == 0 || self.parallelism > MAX_PARALLELISM {
            return Err(CryptoError::Argon2Params {
                reason: "parallelism out of range",
            });
        }
        Ok(())
    }
}

/// Normalise a typed recovery code.
///
/// Whitespace and case are forgiven — the code is digits and dashes, so case
/// is meaningless and stray spaces are a paste artefact. **Dashes are kept**:
/// heylogin hashes the code with them.
#[must_use]
pub fn normalize_code(code: &str) -> Zeroizing<String> {
    Zeroizing::new(code.chars().filter(|c| !c.is_whitespace()).collect())
}

/// Derive the 32-byte seed for a `BACKUP_CODE` authenticator.
///
/// `code` is normalised with [`normalize_code`] first.
///
/// # Errors
/// [`CryptoError::Argon2Params`] if the parameters are out of bounds or
/// Argon2 rejects them.
pub fn derive_recovery_seed(
    code: &str,
    salt: &[u8],
    params: RecoveryParams,
) -> Result<Zeroizing<[u8; SEED_LEN]>, CryptoError> {
    params.validate()?;

    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_cost_kib,
            params.iterations,
            params.parallelism,
            Some(SEED_LEN),
        )
        .map_err(|_| CryptoError::Argon2Params {
            reason: "rejected by argon2",
        })?,
    );

    let code = normalize_code(code);
    let mut out = Zeroizing::new([0u8; SEED_LEN]);
    argon
        .hash_password_into(code.as_bytes(), salt, out.as_mut_slice())
        .map_err(|_| CryptoError::Argon2Params {
            reason: "hashing failed; check the salt length",
        })?;
    Ok(out)
}

/// Whether `seed` matches the checksum the server published for it.
///
/// `checksum` is `SHA512(seed)[:32]`, so this rejects a mistyped recovery code
/// locally, before `CreateTokens` is ever called.
#[must_use]
pub fn checksum_matches(seed: &[u8; SEED_LEN], checksum: &[u8]) -> bool {
    let actual = crate::kdf::hash_data(seed);
    if checksum.len() != actual.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(checksum) {
        diff |= a ^ b;
    }
    diff == 0
}
