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

use std::{fmt::Write as _, time::Duration};

use heyl_crypto::{Seed, recovery};
use heyl_domain::{AuthenticatorSecret, AuthenticatorType, ChallengeEncoding, RecoverySecret};
use heyl_grpc::{GrpcClient, GrpcConfig};
use heyl_ports::HeylApi;

/// Run the probe.
pub async fn run(endpoint: &str, delay_secs: u64) -> Result<(), String> {
    let email = std::env::var("HEYL_EMAIL")
        .map_err(|_| "set HEYL_EMAIL (try running under `secrets-env`)".to_owned())?;
    let code = std::env::var("HEYL_RECOVERY_CODE")
        .map_err(|_| "set HEYL_RECOVERY_CODE (try running under `secrets-env`)".to_owned())?;

    let api = GrpcClient::new(GrpcConfig {
        endpoint: endpoint.to_owned(),
        ..GrpcConfig::default()
    })
    .map_err(|e| e.to_string())?;

    eprintln!("Probing {endpoint} for the login signing input.");
    eprintln!("Each attempt submits a signature; wrong ones are rejected.\n");

    let mut accepted = Vec::new();
    let mut report = String::new();

    for (index, encoding) in ChallengeEncoding::CANDIDATES.iter().enumerate() {
        if index > 0 {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        }

        // A fresh challenge per attempt: a challenge is very likely
        // single-use, and reusing one would confuse "rejected signature" with
        // "stale challenge".
        let challenge = api
            .create_challenge(&email)
            .await
            .map_err(|e| format!("CreateChallenge failed: {e}"))?;

        let (authenticator_id, secret) = recovery_authenticator(&challenge)
            .ok_or_else(|| "this account has no BACKUP_CODE authenticator".to_owned())?;
        let seed = derive(&code, secret)?;

        let outcome = match heyl_domain::sign_challenge(&seed, &challenge.challenge, *encoding) {
            Err(e) => format!("ruled out without a network call: {e}"),
            Ok(signature) => {
                match api
                    .create_tokens(
                        authenticator_id,
                        &challenge.challenge,
                        signature.as_bytes(),
                        // No unlock: this is a probe, and it should not leave
                        // grants lying around on the account.
                        None,
                    )
                    .await
                {
                    Ok(_) => {
                        accepted.push(*encoding);
                        "ACCEPTED".to_owned()
                    }
                    Err(e) => format!("rejected: {e}"),
                }
            }
        };

        eprintln!("  {:<10} {outcome}", encoding.name());
        let _ = writeln!(report, "{:<10} {outcome}", encoding.name());
    }

    eprintln!();
    match accepted.as_slice() {
        [one] => {
            eprintln!("The backend accepts `{}`.", one.name());
            eprintln!(
                "Record it: make it heyl-cli's default and pin it in the offline suite's fake."
            );
            Ok(())
        }
        [] => Err(
            "no candidate was accepted. The hypothesis set is wrong: the next one is a \
                   context-prefixed signature, whose context string is not recoverable from the \
                   published bundles and must be discovered rather than enumerated."
                .to_owned(),
        ),
        many => Err(format!(
            "{} candidates were accepted, which should be impossible and means the probe is \
             measuring something other than the signature.",
            many.len()
        )),
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
