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

/// How many groups a recovery code has (§4).
const GROUPS: usize = 6;
/// How many digits are in each group.
const GROUP_LEN: usize = 4;

/// Normalise a typed recovery code.
///
/// Surrounding whitespace only — a trailing newline off a pipe or an
/// environment variable is a transport artefact, not part of the code.
///
/// Nothing else is altered. heylogin defines exactly one spelling, so a code
/// that is not already in it is **refused** by [`is_canonical`] rather than
/// reshaped into it. In particular dashes are never removed: heylogin hashes
/// the code *with* them, and stripping them derives a completely different
/// seed.
#[must_use]
pub fn normalize_code(code: &str) -> Zeroizing<String> {
    Zeroizing::new(code.trim().to_owned())
}

/// Whether `code` is the canonical form heylogin specifies: six groups of four
/// digits, dash-separated.
///
/// heylogin defines exactly one spelling, so that is the only one accepted. A
/// code entered with spaces, or with no separators, is **rejected** rather than
/// reshaped: reshaping would accept forms the protocol does not define, and
/// hashing one as typed would derive a wrong seed and report a perfectly good
/// code as incorrect. Refusing says which of the two actually went wrong.
#[must_use]
pub fn is_canonical(code: &str) -> bool {
    let mut groups = 0;
    for group in code.split('-') {
        if group.len() != GROUP_LEN || !group.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        groups += 1;
    }
    groups == GROUPS
}

/// Derive the 32-byte seed for a `BACKUP_CODE` authenticator.
///
/// `code` is normalised with [`normalize_code`] first.
///
/// # Errors
/// [`CryptoError::MalformedRecoveryCode`] if `code` is not the canonical
/// six-groups-of-four form; [`CryptoError::Argon2Params`] if the parameters
/// are out of bounds or Argon2 rejects them.
pub fn derive_recovery_seed(
    code: &str,
    salt: &[u8],
    params: RecoveryParams,
) -> Result<Zeroizing<[u8; SEED_LEN]>, CryptoError> {
    params.validate()?;

    let code = normalize_code(code);
    // Reject a mis-spelled code here rather than hashing it: Argon2id would
    // happily return 32 perfectly good bytes, the checksum would reject them,
    // and the user would be told their code is wrong when the problem was the
    // way they typed it.
    if !is_canonical(&code) {
        return Err(CryptoError::MalformedRecoveryCode);
    }

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
