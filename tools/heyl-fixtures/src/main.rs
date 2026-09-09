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
            only,
            delay,
        } => runtime.block_on(probe::run(
            &cli.endpoint,
            &client_type,
            only.as_deref(),
            delay,
        )),
        Command::Describe => runtime.block_on(probe::describe(&cli.endpoint)),
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
