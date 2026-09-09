//! `heyl recovery` — an account **recovery**, not a sign-in.
//!
//! heylogin's Security Whitepaper §6.5.4: using a `BACKUP_CODE` authenticator
//! makes the server *delete the push authenticator and all its locks*, and
//! restricts the resulting session to replacing the primary authenticator.
//! That is why this is not called `login` and why it asks first: a command
//! that disconnects the user's phone must not be reachable by someone who
//! believes they are signing in.
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
//! 2. **Confirm** — `CreateChallenge` lists the account's authenticators, so
//!    what is about to be disconnected is known before anything is committed.
//!    When there is nothing to lose, nothing is asked.
//! 3. Read the code — never from argv, in any spelling. §4 makes it a reusable
//!    master credential for every vault, so `ps` output and shell history are
//!    both disqualifying.
//! 4. Argon2id → seed, then verify against the checksum locally.
//! 5. Sign, and **self-grant an unlock in the same call**: `CreateTokens`
//!    carries a `session_unlock`, so the seed is sealed to a session key we
//!    just generated and stored. That is what lets `heyl doctor`, in a
//!    separate process, decrypt anything at all.

use heyl_crypto::{Seed, recovery};
use heyl_domain::{
    Authenticator, AuthenticatorSecret, AuthenticatorType, ChallengeEncoding, RecoverySecret,
    SessionType,
};
use heyl_ports::{SecretKey, StoredSecret, api::SessionUnlockGrant};
use zeroize::Zeroizing;

use crate::{AppError, Ports};

/// Where the recovery code may come from.
pub const CODE_ENV: &str = "HEYL_RECOVERY_CODE";

/// What `recovery` produces.
#[derive(Debug, Clone)]
pub struct RecoveryOutcome {
    /// The account recovered.
    pub user_id: String,
    /// The authenticators heylogin is expected to have disconnected.
    ///
    /// Read from `CreateChallenge` *before* the recovery, since afterwards
    /// they are gone. Empty when there was nothing to disconnect.
    pub disconnected: Vec<Disconnectable>,
    /// The session the token belongs to.
    pub session_id: heyl_domain::SessionId,
    /// When the unlock actually expires, as the backend decided — not what we
    /// asked for.
    pub unlocked_until: Option<heyl_domain::Timestamp>,
}

/// An authenticator a recovery is expected to remove.
///
/// Type and id only: authenticators carry **no name or description anywhere in
/// the schema**. The friendly device names heylogin's app shows are
/// `SessionMetadata.description` — *session* names, held in the encrypted META
/// vault and therefore unreadable until after the recovery has already
/// happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disconnectable {
    /// Which authenticator.
    pub id: heyl_domain::AuthenticatorId,
    /// What kind it is.
    pub kind: AuthenticatorType,
}

/// Whether the user has agreed to lose the authenticators above.
pub enum Confirmation<'a> {
    /// `--confirm` was given: proceed without asking.
    Granted,
    /// Ask, using this prompt, if there is anything to ask about.
    Ask(&'a str),
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

/// Run the recovery.
///
/// # Errors
/// [`AppError::NoRecoveryAuthenticator`] if the account has no `BACKUP_CODE`,
/// [`AppError::NotConfirmed`] if there is something to disconnect and the user
/// did not agree, [`AppError::WrongRecoveryCode`] if the checksum rejects the
/// code, [`AppError::SignatureRejected`] if the backend refuses our signature.
pub async fn run(
    ports: &Ports<'_>,
    email: &str,
    confirmation: Confirmation<'_>,
    code: CodeSource<'_>,
    encoding: ChallengeEncoding,
    session_type: SessionType,
) -> Result<RecoveryOutcome, AppError> {
    let challenge = ports.api.create_challenge(email).await?;

    let (authenticator, secret) = recovery_authenticator(&challenge.authenticators)
        .ok_or(AppError::NoRecoveryAuthenticator)?;

    // What this is about to cost, established before anything is committed.
    let disconnected = disconnectable(&challenge.authenticators, authenticator.id);
    confirm(ports, &confirmation, &disconnected)?;

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
    //
    // The session key is KDF-derived from a random seed, not the random bytes
    // used directly as a scalar — see `heyl_domain::session_encryption_key`.
    // The *ephemeral* sender key inside the seal is raw random, as heylogin's
    // `asymEncrypt` does.
    let session_key = heyl_domain::session_encryption_key(&ports.random.seed())?;
    let grant = SessionUnlockGrant {
        encrypted_secret: session_key.public_key().seal(
            &ports.random.ephemeral_key(),
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
            session_type,
            Some(grant),
        )
        .await
        .map_err(|e| match e {
            heyl_ports::ApiError::PermissionDenied { .. } => AppError::SignatureRejected,
            // Everything else is surfaced as heylogin worded it. We do not
            // rewrite the backend's diagnostics: our reading of them can be
            // wrong, and it goes stale the moment heylogin changes behaviour.
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

    Ok(RecoveryOutcome {
        user_id: challenge.user_id,
        disconnected,
        session_id: tokens.session_id,
        unlocked_until,
    })
}

/// Which authenticators a recovery is expected to remove.
///
/// Everything except the `BACKUP_CODE` authenticator being used. The
/// whitepaper documents removal of the **push** authenticator specifically;
/// whether `WEBAUTHN` or `BACKUP_OS` also go is undocumented and untested, so
/// this errs towards naming anything that might, rather than claiming a
/// precision we do not have.
fn disconnectable(
    authenticators: &[Authenticator],
    in_use: heyl_domain::AuthenticatorId,
) -> Vec<Disconnectable> {
    authenticators
        .iter()
        .filter(|a| a.id != in_use)
        .map(|a| Disconnectable {
            id: a.id,
            kind: a.authenticator_type,
        })
        .collect()
}

/// Gate the recovery on the user having agreed to lose `disconnected`.
///
/// Nothing at stake means nothing is asked — a second recovery, with the phone
/// already gone, has nothing left to destroy and should not train anyone to
/// dismiss a warning.
fn confirm(
    ports: &Ports<'_>,
    confirmation: &Confirmation<'_>,
    disconnected: &[Disconnectable],
) -> Result<(), AppError> {
    if disconnected.is_empty() {
        return Ok(());
    }
    match *confirmation {
        Confirmation::Granted => Ok(()),
        Confirmation::Ask(prompt) => {
            if !ports.terminal.is_interactive() {
                // Never destroy something silently in a script.
                return Err(AppError::NotConfirmed);
            }
            ports
                .terminal
                .note("This will disconnect from your heylogin account:");
            for d in disconnected {
                ports.terminal.note(&format!("  {:?}  {}", d.kind, d.id));
            }
            ports.terminal.note(
                "Pairing a phone again afterwards regenerates every profile, \
                 so anything recorded from this account before that point stops opening.",
            );
            let answer = ports.terminal.prompt_line(prompt)?;
            if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                Ok(())
            } else {
                Err(AppError::NotConfirmed)
            }
        }
    }
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
