//! Authenticators, their published public keys, and the `secretInfo` payload.
//!
//! `secretInfo` is a JSON *string* on the wire. It is parsed **here** rather
//! than in `heyl-grpc`, because it is a heylogin domain structure rather than a
//! transport format: parsing it in a pure crate keeps it fixture-testable with
//! no `tonic` in the graph, and means no raw JSON string ever reaches
//! `heyl-app` (DESIGN.md §4).

use heyl_crypto::{
    EncryptionPublicKey, RecoveryParams, SEED_LEN, SecretSalt, Seed, Signature, VerifyingKey,
};
use serde::Deserialize;

use crate::{error::DomainError, ids::AuthenticatorId, vault::AuthenticatorType};

/// One authenticator, as the backend describes it.
///
/// `secret_salt` is [`None`] before login: the backend reveals it only after
/// `CreateTokens` succeeds, which is exactly why the login signing key is the
/// one key derived with a null secondary seed (§4).
#[derive(Debug, Clone)]
pub struct Authenticator {
    /// Which authenticator this is.
    pub id: AuthenticatorId,
    /// How its seed is obtained.
    pub authenticator_type: AuthenticatorType,
    /// Its parsed `secretInfo`.
    pub secret: AuthenticatorSecret,
    /// The server-stored secondary seed, once revealed.
    pub secret_salt: Option<SecretSalt>,
    /// The public keys the backend publishes for it.
    pub public_keys: AuthenticatorPublicKeys,
}

/// The public halves the backend publishes for an authenticator.
///
/// Every field is optional because `CreateChallenge` returns authenticators
/// with none of them — only `AuthenticatorService.List` carries the full set.
/// `doctor` compares each against what our seed derives (DESIGN.md §6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticatorPublicKeys {
    /// Verifies the login challenge response — derived with a **null**
    /// secondary seed.
    pub login_sig: Option<VerifyingKey>,
    /// The identity signing key, high-security tier.
    pub high_security_identity_sig: Option<VerifyingKey>,
    /// The identity signing key, storable tier. heylogin's two context
    /// constants hold identical values, so this equals `high_security_identity_sig`.
    pub storable_sig: Option<VerifyingKey>,
    /// Receives a profile's high-security seed.
    pub high_security_profile_seed_enc: Option<EncryptionPublicKey>,
    /// Receives a profile's storable seed.
    pub storable_profile_seed_enc: Option<EncryptionPublicKey>,
    /// Signature over `high_security_profile_seed_enc`.
    pub high_security_profile_seed_enc_signature: Option<Signature>,
    /// Signature over `storable_profile_seed_enc`.
    pub storable_profile_seed_enc_signature: Option<Signature>,
    /// Signature over `storable_sig`.
    pub storable_sig_signature: Option<Signature>,
}

/// A parsed `secretInfo`.
///
/// Unknown or absent payloads are [`AuthenticatorSecret::Opaque`] rather than
/// an error: `SESSION_UNLOCK` and `ORGANIZATION_SERVICE` authenticators appear
/// in a normal listing and must not fail the parse of the whole response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthenticatorSecret {
    /// `BACKUP_CODE` — Argon2id parameters and an offline checksum (§4).
    Recovery(RecoverySecret),
    /// `DUMMY` — the seed, in plaintext, on the server. Test-only (DESIGN.md §6).
    Dummy(Box<Seed>),
    /// Anything we do not model.
    Opaque,
}

/// `RecoverySecretInfo`: what a `BACKUP_CODE` authenticator publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySecret {
    /// `SHA512(seed)[:32]`, so a mistyped code is caught before `CreateTokens`.
    pub checksum: Vec<u8>,
    /// Argon2id salt, decoded from `saltBase64`.
    pub salt: Vec<u8>,
    /// Argon2id cost parameters, already bounds-checked.
    pub params: RecoveryParams,
}

// The wire shapes. Private: nothing outside this module sees the JSON spelling.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRecoverySecretInfo {
    checksum: String,
    recovery_parameters: RawRecoveryParameters,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRecoveryParameters {
    salt_base64: String,
    iterations: u32,
    memory_cost: u32,
    parallelism: u32,
}

#[derive(Deserialize)]
struct RawDummySecretInfo {
    seed: String,
}

impl AuthenticatorSecret {
    /// Parse a `secretInfo` string for an authenticator of `kind`.
    ///
    /// An empty string is [`AuthenticatorSecret::Opaque`] — that is what
    /// `CreateChallenge` returns for types that publish nothing.
    ///
    /// # Errors
    /// [`DomainError::MalformedSecretInfo`] if the payload is for a type we do
    /// model but cannot read.
    pub fn parse(kind: AuthenticatorType, secret_info: &str) -> Result<Self, DomainError> {
        if secret_info.is_empty() {
            return Ok(Self::Opaque);
        }
        match kind {
            AuthenticatorType::BackupCode => Ok(Self::Recovery(Self::parse_recovery(secret_info)?)),
            AuthenticatorType::Dummy => Ok(Self::Dummy(Box::new(Self::parse_dummy(secret_info)?))),
            _ => Ok(Self::Opaque),
        }
    }

    fn parse_recovery(secret_info: &str) -> Result<RecoverySecret, DomainError> {
        let raw: RawRecoverySecretInfo =
            serde_json::from_str(secret_info).map_err(|_| DomainError::MalformedSecretInfo {
                what: "RecoverySecretInfo is not the expected JSON object",
            })?;

        let params = RecoveryParams {
            memory_cost_kib: raw.recovery_parameters.memory_cost,
            iterations: raw.recovery_parameters.iterations,
            parallelism: raw.recovery_parameters.parallelism,
        };
        // Bound the server-supplied cost here, at the boundary, so a hostile
        // `memoryCost` cannot reach Argon2 at all (heyl-crypto::recovery).
        params.validate()?;

        Ok(RecoverySecret {
            checksum: decode_base64(&raw.checksum, "checksum")?,
            salt: decode_base64(&raw.recovery_parameters.salt_base64, "saltBase64")?,
            params,
        })
    }

    fn parse_dummy(secret_info: &str) -> Result<Seed, DomainError> {
        let raw: RawDummySecretInfo =
            serde_json::from_str(secret_info).map_err(|_| DomainError::MalformedSecretInfo {
                what: "DummySecretInfo is not the expected JSON object",
            })?;
        let bytes = decode_base64(&raw.seed, "seed")?;
        let bytes: [u8; SEED_LEN] =
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| DomainError::MalformedSecretInfo {
                    what: "DUMMY seed is not 32 bytes",
                })?;
        Ok(Seed::from_bytes(&bytes))
    }
}

/// heylogin emits standard-alphabet base64; padding is accepted either way
/// because different call sites in the bundle disagree about it.
fn decode_base64(value: &str, field: &'static str) -> Result<Vec<u8>, DomainError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|_| DomainError::MalformedSecretInfo { what: field })
}
