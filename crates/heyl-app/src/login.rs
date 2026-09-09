//! `heyl login recovery`.
//!
//! The sequence, and why it is in this order:
//!
//! 1. `CreateChallenge` **first**, because the Argon2id parameters and the
//!    verification checksum live in the authenticator's `secretInfo` and
//!    arrive with nothing else. This is also why README's claim that a
//!    mistyped code is rejected "before any network call" is not achievable —
//!    it is rejected before `CreateTokens`, which still saves an Argon2id run
//!    and a round trip, and gives the user "that code is wrong" instead of a
//!    backend error.
//! 2. Read the code — never from argv, in any spelling. §4 makes it a reusable
//!    master credential for every vault, so `ps` output and shell history are
//!    both disqualifying.
//! 3. Argon2id → seed, then verify against the checksum locally.
//! 4. Sign, and **self-grant an unlock in the same call**: `CreateTokens`
//!    carries a `session_unlock`, so the seed is sealed to a session key we
//!    just generated and stored. That is what lets `heyl doctor`, in a
//!    separate process, decrypt anything at all.

use heyl_crypto::{Seed, recovery};
use heyl_domain::{
    Authenticator, AuthenticatorSecret, AuthenticatorType, ChallengeEncoding, RecoverySecret,
};
use heyl_ports::{SecretKey, StoredSecret, api::SessionUnlockGrant};
use zeroize::Zeroizing;

use crate::{AppError, Ports};

/// Where the recovery code may come from.
pub const CODE_ENV: &str = "HEYL_RECOVERY_CODE";

/// What `login` produces.
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    /// The account we logged into.
    pub user_id: String,
    /// The session the token belongs to.
    pub session_id: heyl_domain::SessionId,
    /// When the unlock actually expires, as the backend decided — not what we
    /// asked for.
    pub unlocked_until: Option<heyl_domain::Timestamp>,
}

/// How the recovery code reaches us.
///
/// `heyl-cli` resolves this before calling, so the core never reads an
/// environment variable itself.
pub enum CodeSource<'a> {
    /// Already in hand, e.g. from `HEYL_RECOVERY_CODE`.
    Given(Zeroizing<String>),
    /// Ask the terminal — hidden prompt if interactive, otherwise stdin.
    Ask(&'a str),
}

/// Run the login.
///
/// # Errors
/// [`AppError::NoRecoveryAuthenticator`] if the account has no `BACKUP_CODE`,
/// [`AppError::WrongRecoveryCode`] if the checksum rejects it,
/// [`AppError::SignatureRejected`] if the backend refuses our signature.
pub async fn run(
    ports: &Ports<'_>,
    email: &str,
    code: CodeSource<'_>,
    encoding: ChallengeEncoding,
) -> Result<LoginOutcome, AppError> {
    let challenge = ports.api.create_challenge(email).await?;

    let (authenticator, secret) = recovery_authenticator(&challenge.authenticators)
        .ok_or(AppError::NoRecoveryAuthenticator)?;

    let code = match code {
        CodeSource::Given(code) => code,
        CodeSource::Ask(prompt) => {
            if ports.terminal.is_interactive() {
                ports.terminal.prompt_hidden(prompt)?
            } else {
                ports.terminal.read_line()?
            }
        }
    };

    let seed = derive_and_verify(&code, secret)?;

    // Everything below needs the seed, and the seed is dropped at the end of
    // this function. Nothing persists it -- the keychain gets a token and a
    // session key, neither of which decrypts anything (DESIGN.md §3).
    let signature = heyl_domain::sign_challenge(&seed, &challenge.challenge, encoding)?;

    // Self-grant: seal the seed to a session key we generate now and store, so
    // a later invocation can recover it from Sync.
    let session_key = ports.random.encryption_private_key();
    let grant = SessionUnlockGrant {
        encrypted_secret: session_key.public_key().seal(
            &ports.random.encryption_private_key(),
            &ports.random.nonce(),
            seed.expose_secret(),
        ),
        expires_at: ports.clock.next_unlock_deadline(),
    };

    let tokens = ports
        .api
        .create_tokens(
            authenticator.id,
            &challenge.challenge,
            signature.as_bytes(),
            Some(grant),
        )
        .await
        .map_err(|e| match e {
            heyl_ports::ApiError::PermissionDenied { .. } => AppError::SignatureRejected,
            other => AppError::Api(other),
        })?;

    // Store the session key first: a token without its key is useless, and the
    // reverse order would leave a usable token behind if the second write
    // failed.
    ports
        .store
        .set(
            &SecretKey::default_slot(StoredSecret::SessionPrivateKey),
            &encode_key(&session_key),
        )
        .await?;
    ports
        .store
        .set(
            &SecretKey::default_slot(StoredSecret::AccessToken),
            &tokens.access_token,
        )
        .await?;

    let unlocked_until = tokens
        .sync
        .session(tokens.session_id)
        .and_then(|s| s.unlocked_until);

    Ok(LoginOutcome {
        user_id: challenge.user_id,
        session_id: tokens.session_id,
        unlocked_until,
    })
}

/// The account's `BACKUP_CODE` authenticator, with its parsed secret.
fn recovery_authenticator(
    authenticators: &[Authenticator],
) -> Option<(&Authenticator, &RecoverySecret)> {
    authenticators.iter().find_map(|a| match &a.secret {
        AuthenticatorSecret::Recovery(secret)
            if a.authenticator_type == AuthenticatorType::BackupCode =>
        {
            Some((a, secret))
        }
        _ => None,
    })
}

/// Argon2id, then the offline checksum.
fn derive_and_verify(code: &str, secret: &RecoverySecret) -> Result<Seed, AppError> {
    let derived = recovery::derive_recovery_seed(code, &secret.salt, secret.params)?;
    if !recovery::checksum_matches(&derived, &secret.checksum) {
        return Err(AppError::WrongRecoveryCode);
    }
    Ok(Seed::from_bytes(&derived))
}

/// The session private key, as stored.
///
/// Base64 rather than hex: it is what heylogin's own payloads use, and it is
/// half the length in a keychain entry a human may end up looking at.
#[must_use]
pub fn encode_key(key: &heyl_crypto::EncryptionPrivateKey) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key.expose_secret())
}

/// Recover a stored session private key.
///
/// # Errors
/// [`heyl_ports::PortError::Malformed`] if it is not 32 base64 bytes.
pub fn decode_key(
    encoded: &str,
) -> Result<heyl_crypto::EncryptionPrivateKey, heyl_ports::PortError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| heyl_ports::PortError::Malformed {
            what: "session_priv_key",
        })?;
    let bytes: [u8; 32] =
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| heyl_ports::PortError::Malformed {
                what: "session_priv_key",
            })?;
    Ok(heyl_crypto::EncryptionPrivateKey::from_bytes(&bytes))
}
