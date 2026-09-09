//! Settle the login signing input against the live backend.
//!
//! # What is ambiguous
//!
//! `CreateChallengeResponse.challenge` is a proto `string`;
//! `CreateTokensRequest.response` is `bytes`. §5 writes
//! `Ed25519.sign(challenge, loginSigPrivKey)`, but §2 says *every* signing
//! operation is `Ed25519.sign(utf8(salt) ‖ data)` and names no context for
//! this one. So the bytes signed could be the challenge's UTF-8, or its
//! base64 decoding under either alphabet — and a wrong choice yields a
//! perfectly valid signature over the wrong message, which the backend rejects
//! with no diagnostic pointing at the cause.
//!
//! M0 settled the transport by probing rather than reasoning. This does the
//! same for the signature.
//!
//! # What a run tells you
//!
//! * exactly one candidate accepted → that is the answer; record it.
//! * a candidate rejected before the network → it cannot decode the challenge,
//!   which rules it out for free.
//! * **none** accepted → the hypothesis set is wrong, and the next one is a
//!   context-prefixed variant. That needs a context string which is not
//!   recoverable from the published bundles, so it has to be discovered rather
//!   than enumerated.

use std::time::Duration;

use heyl_crypto::{Seed, recovery};
use heyl_domain::{
    AuthenticatorSecret, AuthenticatorType, ChallengeEncoding, RecoverySecret, SessionType,
};
use heyl_grpc::{GrpcClient, GrpcConfig};
use heyl_platform::{OsRandom, SystemClock};
use heyl_ports::{Clock as _, HeylApi, RandomSource as _, api::SessionUnlockGrant};

/// Dump what `CreateChallenge` says about this account.
///
/// One unauthenticated request. It also verifies the recovery code against the
/// published checksum, which confirms Argon2id, the salt, the parameters and
/// the code itself — offline, and without spending a login attempt.
pub async fn describe(endpoint: &str) -> Result<(), String> {
    let email = std::env::var("HEYL_EMAIL")
        .map_err(|_| "set HEYL_EMAIL (try running under `secrets-env`)".to_owned())?;
    let code = std::env::var("HEYL_RECOVERY_CODE")
        .map_err(|_| "set HEYL_RECOVERY_CODE (try running under `secrets-env`)".to_owned())?;

    let api = GrpcClient::new(GrpcConfig {
        endpoint: endpoint.to_owned(),
        ..GrpcConfig::default()
    })
    .map_err(|e| e.to_string())?;

    let challenge = api
        .create_challenge(&email)
        .await
        .map_err(|e| format!("CreateChallenge failed: {e}"))?;

    println!("user_id:   {}", challenge.user_id);
    println!("challenge: {} chars", challenge.challenge.len());
    println!(
        "           charset: {}",
        describe_charset(&challenge.challenge)
    );
    // The challenge looks like a JWT. Its claims are the backend's own
    // description of what it issued, and are not secret -- it is useless
    // without a signature from the seed.
    if let Some(claims) = jwt_claims(&challenge.challenge) {
        println!("           claims: {claims}");
    }
    println!("authenticators: {}", challenge.authenticators.len());

    for a in &challenge.authenticators {
        println!("  - {} {:?}", a.id, a.authenticator_type);
        match &a.secret {
            AuthenticatorSecret::Recovery(secret) => {
                println!(
                    "    recovery: argon2id m={} t={} p={}, salt {} bytes, checksum {} bytes",
                    secret.params.memory_cost_kib,
                    secret.params.iterations,
                    secret.params.parallelism,
                    secret.salt.len(),
                    secret.checksum.len()
                );
                match derive(&code, secret) {
                    Ok(_) => println!("    checksum: MATCHES the code in HEYL_RECOVERY_CODE"),
                    Err(e) => println!("    checksum: {e}"),
                }
            }
            AuthenticatorSecret::Dummy(_) => println!("    dummy: seed present (redacted)"),
            _ => println!("    secretInfo: none or unmodelled"),
        }
    }
    Ok(())
}

/// Decode a JWT's payload segment, if the challenge is one.
fn jwt_claims(challenge: &str) -> Option<String> {
    use base64::Engine as _;
    let payload = challenge.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    serde_json::to_string_pretty(&value).ok()
}

fn describe_charset(s: &str) -> String {
    let mut kinds = Vec::new();
    if s.chars().any(|c| c.is_ascii_lowercase()) {
        kinds.push("a-z");
    }
    if s.chars().any(|c| c.is_ascii_uppercase()) {
        kinds.push("A-Z");
    }
    if s.chars().any(|c| c.is_ascii_digit()) {
        kinds.push("0-9");
    }
    let symbols: String = s
        .chars()
        .filter(|c| !c.is_ascii_alphanumeric())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !symbols.is_empty() {
        kinds.push(Box::leak(format!("symbols {symbols:?}").into_boxed_str()));
    }
    kinds.join(", ")
}

/// Run the probe.
pub async fn run(
    endpoint: &str,
    client_type: &str,
    authenticator_override: Option<&str>,
    only: Option<&str>,
    delay_secs: u64,
) -> Result<(), String> {
    let email = std::env::var("HEYL_EMAIL")
        .map_err(|_| "set HEYL_EMAIL (try running under `secrets-env`)".to_owned())?;
    let code = std::env::var("HEYL_RECOVERY_CODE")
        .map_err(|_| "set HEYL_RECOVERY_CODE (try running under `secrets-env`)".to_owned())?;

    let api = GrpcClient::new(GrpcConfig {
        endpoint: endpoint.to_owned(),
        client_type: client_type.to_owned(),
        ..GrpcConfig::default()
    })
    .map_err(|e| e.to_string())?;

    eprintln!(
        "Probing {endpoint} (client-type {client_type}) for the session type and signing input."
    );
    eprintln!("Each attempt submits a signature; wrong ones are rejected.\n");
    eprintln!("  {:<24} {:<10} result", "session type", "encoding");

    // Two unknowns, swept together.
    //
    // The encoding is the one this probe was written for. The session type
    // joined it on the first live run: §5 says the recovery path sends
    // SESSION_TYPE_BACKUP_CODE, and the backend answers `grpc-status 3 —
    // invalid session type`. That is request validation, which happens before
    // the signature is looked at, so a wrong session type masks the answer to
    // the question this probe exists to ask.
    //
    // Candidates whose encoding cannot even decode the challenge are skipped
    // without a network call, which is why this is not 15 requests.
    let mut accepted = Vec::new();
    let mut sent = 0usize;

    let candidates: Vec<SessionType> = match only {
        None => SessionType::ALL.to_vec(),
        Some(name) => {
            let chosen: Vec<_> = SessionType::ALL
                .into_iter()
                .filter(|s| s.name() == name)
                .collect();
            if chosen.is_empty() {
                let known: Vec<_> = SessionType::ALL.iter().map(|s| s.name()).collect();
                return Err(format!("unknown session type {name:?}; known: {known:?}"));
            }
            chosen
        }
    };

    for session_type in candidates {
        for encoding in ChallengeEncoding::CANDIDATES {
            let challenge = api
                .create_challenge(&email)
                .await
                .map_err(|e| format!("CreateChallenge failed: {e}"))?;

            let (mut authenticator_id, secret) = recovery_authenticator(&challenge)
                .ok_or_else(|| "this account has no BACKUP_CODE authenticator".to_owned())?;
            let seed = derive(&code, secret)?;

            if let Some(id) = authenticator_override {
                authenticator_id = heyl_domain::AuthenticatorId::parse(id)
                    .map_err(|e| format!("--authenticator: {e}"))?;
            }

            let Ok(signature) = heyl_domain::sign_challenge(&seed, &challenge.challenge, encoding)
            else {
                // Ruled out for free: report it once, against the first
                // session type, and do not spend a request on it.
                if session_type == SessionType::ALL[0] {
                    eprintln!(
                        "  {:<24} {:<10} ruled out without a network call: the challenge is not \
                         valid {}",
                        "(any)",
                        encoding.name(),
                        encoding.name()
                    );
                }
                continue;
            };

            if sent > 0 {
                tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            }
            sent += 1;

            let outcome = match api
                .create_tokens(
                    authenticator_id,
                    &challenge.challenge,
                    signature.as_bytes(),
                    session_type,
                    // The same request shape `heyl login` sends. Omitting the
                    // grant would vary two things at once.
                    Some(unlock_grant(&seed)),
                )
                .await
            {
                Ok(_) => {
                    accepted.push((session_type, encoding));
                    "ACCEPTED".to_owned()
                }
                Err(e) => format!("rejected: {e}"),
            };

            eprintln!(
                "  {:<24} {:<10} {outcome}",
                session_type.name(),
                encoding.name()
            );
        }
    }

    eprintln!("\n{sent} request(s) sent.");
    verdict(&accepted)
}

/// Turn the sweep's outcome into an answer, or into the next hypothesis.
fn verdict(accepted: &[(SessionType, ChallengeEncoding)]) -> Result<(), String> {
    match accepted {
        [(session_type, encoding)] => {
            eprintln!(
                "\nThe backend accepts session type `{}` with encoding `{}`.",
                session_type.name(),
                encoding.name()
            );
            eprintln!(
                "Record both: make them heyl-cli's defaults, pin the encoding in the offline \
                 suite's fake, and correct HEYLOGIN_SPEC §5 if the session type is not the one \
                 it names."
            );
            Ok(())
        }
        [] => Err("nothing was accepted.\n\n\
                   If every row says `invalid session type`, the session type is still wrong and \
                   the signature was never reached. If a row gets past that and is refused on \
                   credentials, the session type is right and the *encoding* hypothesis set is \
                   wrong -- the next one is a context-prefixed signature, whose context string is \
                   not recoverable from the published bundles and must be discovered."
            .to_owned()),
        many => Err(format!(
            "{} combinations were accepted, which should be impossible.",
            many.len()
        )),
    }
}

/// The self-granted unlock that accompanies a real login (§6).
fn unlock_grant(seed: &Seed) -> SessionUnlockGrant {
    let random = OsRandom;
    let session_key = heyl_domain::session_encryption_key(&random.seed()).expect("derives");
    SessionUnlockGrant {
        encrypted_secret: session_key.public_key().seal(
            &random.ephemeral_key(),
            &random.nonce(),
            seed.expose_secret(),
        ),
        expires_at: SystemClock.next_unlock_deadline(),
    }
}

fn recovery_authenticator(
    challenge: &heyl_domain::Challenge,
) -> Option<(heyl_domain::AuthenticatorId, &RecoverySecret)> {
    challenge
        .authenticators
        .iter()
        .find_map(|a| match &a.secret {
            AuthenticatorSecret::Recovery(secret)
                if a.authenticator_type == AuthenticatorType::BackupCode =>
            {
                Some((a.id, secret))
            }
            _ => None,
        })
}

fn derive(code: &str, secret: &RecoverySecret) -> Result<Seed, String> {
    let derived = recovery::derive_recovery_seed(code, &secret.salt, secret.params)
        .map_err(|e| e.to_string())?;
    if !recovery::checksum_matches(&derived, &secret.checksum) {
        return Err(
            "that recovery code does not match this account's checksum — fix the \
                    credential before probing, or every candidate will be rejected for the \
                    wrong reason"
                .to_owned(),
        );
    }
    Ok(Seed::from_bytes(&derived))
}
