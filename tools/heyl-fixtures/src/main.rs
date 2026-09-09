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
        /// Seconds to wait between attempts.
        ///
        /// Each attempt submits a deliberately wrong signature until one is
        /// right, and heylogin's lockout behaviour on repeated failures is
        /// unknown. Pace it rather than hammering.
        #[arg(long, default_value_t = 5)]
        delay: u64,
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
        Command::ProbeSigning { delay } => runtime.block_on(probe::run(&cli.endpoint, delay)),
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
