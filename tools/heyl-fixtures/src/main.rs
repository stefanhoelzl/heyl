//! Development tooling. Not published, not shipped, not on any user's machine.
//!
//! Two jobs, both of which need a real account and therefore cannot live in
//! the test suite:
//!
//! * `probe-signing` — settle what `CreateTokens` actually verifies
//!   (DESIGN.md §6; the ambiguity is described in `heyl_domain::login`).
//! * `rekey` — turn a real recorded exchange into a committed fixture whose
//!   key material is entirely synthetic, so the throwaway account's seed and
//!   recovery code never enter the repository.

mod probe;
mod rekey;

use clap::{Parser, Subcommand};

/// Fixture tooling for heyl.
#[derive(Debug, Parser)]
#[command(name = "heyl-fixtures", about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Backend endpoint.
    #[arg(long, env = "HEYL_ENDPOINT", default_value = heyl_grpc::DEFAULT_ENDPOINT)]
    endpoint: String,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Find which challenge encoding `CreateTokens` accepts.
    ///
    /// Reads the account from `HEYL_EMAIL` and the code from
    /// `HEYL_RECOVERY_CODE`. Run it under `secrets-env` so neither reaches
    /// your shell history:
    ///
    ///     secrets-env cargo run -p heyl-fixtures -- probe-signing
    ProbeSigning {
        /// The `client-type` header to send.
        ///
        /// 400 is `CLIENT_TYPE_CLI`, which is what heyl ships. Vary it only to
        /// find out where a backend constraint lives — 100 is WEB, 300 is EXT.
        #[arg(long, default_value = heyl_grpc::CLIENT_TYPE_CLI)]
        client_type: String,

        /// Sign for a different authenticator id than the `BACKUP_CODE` one.
        ///
        /// The signature will not verify — we do not have that authenticator's
        /// seed. The point is *which error comes back*: if naming a PUSH
        /// authenticator changes `invalid session type` into a credential
        /// error, the session-type check is keyed on the authenticator's type,
        /// and `BACKUP_CODE` is what the backend is refusing.
        #[arg(long)]
        authenticator: Option<String>,

        /// Do not attach a self-granted session unlock.
        ///
        /// `finishChallenge` always sends one, but it is the part of the
        /// request most likely to be handled differently per client type.
        #[arg(long)]
        no_unlock: bool,

        /// Flip a bit in the signature before sending it.
        ///
        /// A control: if a corrupt signature draws a *well-formed* credential
        /// error where the correct one does not, then verification is being
        /// reached and the correct signature is passing it.
        #[arg(long)]
        corrupt_signature: bool,

        /// Try only this session type, by name (e.g. `backup-code`).
        ///
        /// The full sweep is five requests. When the question is narrower than
        /// that, ask it with one — the backend rate-limits repeated failures.
        #[arg(long)]
        only: Option<String>,

        /// Seconds to wait between attempts.
        ///
        /// Each attempt submits a deliberately wrong signature until one is
        /// right, and heylogin's lockout behaviour on repeated failures is
        /// unknown. Pace it rather than hammering.
        #[arg(long, default_value_t = 5)]
        delay: u64,
    },

    /// Describe what `CreateChallenge` returns for this account.
    ///
    /// Unauthenticated and read-only: it submits no signature, so it costs no
    /// login attempt and cannot trip the backend's rate limiting. Run this
    /// before probing anything.
    Describe,

    /// Open a phone-swipe login channel and print the QR URL.
    ///
    /// Establishes whether the long-poll path — the flow production actually
    /// uses — is reachable from `CLIENT_TYPE_CLI`. The call blocks until a
    /// phone completes the channel, so a hang is the *success* signal.
    ProbeLongPoll {
        /// The `client-type` header to send.
        #[arg(long, default_value = heyl_grpc::CLIENT_TYPE_CLI)]
        client_type: String,
    },

    /// Re-key a real account's data into a committed fixture.
    Rekey {
        /// Where to write the fixture.
        #[arg(long, default_value = "tests/fixtures/vault")]
        out: std::path::PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    if let Err(e) = heyl_platform::harden_process() {
        eprintln!("heyl-fixtures: {e}");
        return std::process::ExitCode::FAILURE;
    }

    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("heyl-fixtures: could not start the runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let result = match cli.command {
        Command::ProbeSigning {
            client_type,
            authenticator,
            no_unlock,
            corrupt_signature,
            only,
            delay,
        } => runtime.block_on(probe::run(
            &cli.endpoint,
            &client_type,
            authenticator.as_deref(),
            no_unlock,
            corrupt_signature,
            only.as_deref(),
            delay,
        )),
        Command::Describe => runtime.block_on(probe::describe(&cli.endpoint)),
        Command::ProbeLongPoll { client_type } => {
            runtime.block_on(probe::long_poll(&cli.endpoint, &client_type))
        }
        Command::Rekey { out } => rekey::run(&out),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("heyl-fixtures: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
