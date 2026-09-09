//! Answering the login challenge.
//!
//! # The unsettled part
//!
//! `CreateChallengeResponse.challenge` is a proto `string` and
//! `CreateTokensRequest.response` is `bytes`, and the spec does not pin the
//! relationship between them. §5 writes `Ed25519.sign(challenge,
//! loginSigPrivKey)`, but §2 says *every* signing operation is
//! `Ed25519.sign(utf8(salt) ‖ data)` — context-prefixed — and names no context
//! for this one. So the bytes actually signed are ambiguous, and a wrong guess
//! produces a perfectly valid signature over the wrong message: the backend
//! rejects it with no diagnostic pointing at the cause.
//!
//! This is settled empirically rather than guessed at, the same way M0 settled
//! the transport. [`ChallengeEncoding::CANDIDATES`] is the list the probe walks;
//! `tools/heyl-fixtures probe-signing` reports which one `CreateTokens`
//! accepts, and the answer is recorded as a fixture.
//!
//! All candidates are **unprefixed**. If none is accepted, the next hypothesis
//! is a context-prefixed variant — which needs a context string that is not
//! recoverable from the bundles, so it would have to be discovered rather than
//! enumerated.

use heyl_crypto::{Seed, Signature, SigningKey, context};

use crate::error::DomainError;

/// How the challenge string maps onto the bytes that get signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChallengeEncoding {
    /// Sign the challenge's UTF-8 bytes as they arrived.
    ///
    /// M1 assumed this — see `SigningKey::sign_unprefixed`'s doc comment — but
    /// nothing has confirmed it.
    Utf8,
    /// Base64-decode the challenge first (standard alphabet).
    Base64,
    /// Base64-decode the challenge first (URL-safe alphabet).
    Base64Url,
}

impl ChallengeEncoding {
    /// Every candidate, in the order the probe should try them.
    ///
    /// `Utf8` leads because it is what M1 assumed and what §5 reads like at
    /// face value.
    pub const CANDIDATES: [Self; 3] = [Self::Utf8, Self::Base64, Self::Base64Url];

    /// How this candidate prints in the probe's report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Base64 => "base64",
            Self::Base64Url => "base64url",
        }
    }

    /// The bytes this candidate would sign.
    ///
    /// # Errors
    /// [`DomainError::MalformedChallenge`] if the challenge is not valid base64
    /// under a decoding candidate — which is itself evidence, since it rules
    /// that candidate out without a network call.
    pub fn bytes_to_sign(self, challenge: &str) -> Result<Vec<u8>, DomainError> {
        use base64::Engine as _;
        match self {
            Self::Utf8 => Ok(challenge.as_bytes().to_vec()),
            Self::Base64 => base64::engine::general_purpose::STANDARD
                .decode(challenge)
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(challenge))
                .map_err(|_| DomainError::MalformedChallenge {
                    encoding: self.name(),
                }),
            Self::Base64Url => base64::engine::general_purpose::URL_SAFE
                .decode(challenge)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(challenge))
                .map_err(|_| DomainError::MalformedChallenge {
                    encoding: self.name(),
                }),
        }
    }
}

/// The login signing key: the one authenticator key derived with a **null**
/// secondary seed, which is what lets login happen before the server has
/// revealed `secretSalt` (§4).
///
/// # Errors
/// Propagates [`heyl_crypto::CryptoError`].
pub fn login_signing_key(seed: &Seed) -> Result<SigningKey, DomainError> {
    Ok(SigningKey::derive(
        seed.expose_secret(),
        None,
        context::AUTHENTICATOR_LOGIN_SIGNING,
    )?)
}

/// Sign a login challenge under one encoding candidate.
///
/// # Errors
/// Propagates [`ChallengeEncoding::bytes_to_sign`] and the key derivation.
pub fn sign_challenge(
    seed: &Seed,
    challenge: &str,
    encoding: ChallengeEncoding,
) -> Result<Signature, DomainError> {
    let key = login_signing_key(seed)?;
    Ok(key.sign_unprefixed(&encoding.bytes_to_sign(challenge)?))
}
