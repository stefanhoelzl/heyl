//! Development tooling. Not published, not shipped, not on any user's machine.
//!
//! One job, which needs a real account and therefore cannot live in the test
//! suite: `record` fills in a scenario, running the shipped binary against a
//! live account and then re-keying what it captured so the throwaway account's
//! seed and recovery code never enter the repository.
//!
//! `rekey` is no longer a separate step. Fusing it into `record` means the raw
//! recording — real key material, a live token — need never be written down;
//! `--no-rekey` is the one path that writes it, for debugging a recording that
//! went wrong, which is the right way round.
//!
//! `derive` is gone too. It materialised a situation by copying the base corpus
//! and editing it, back when situations were copies of one recording. Every
//! scenario is recorded independently now, and its two documented edits — set a
//! JSON pointer, replace a response with a refusal — turned out to be things a
//! person can do in an editor. The crypto-consistency argument that justified
//! it belongs to `rekey`, which really cannot be done by hand.
//!
//! The probing subcommands are gone: `heyl api` does that job now, and better.
//! `probe-signing` existed to settle what `CreateTokens` verifies by varying
//! `client-type`, the authenticator and the signature; `heyl api call` varies
//! all three as ordinary arguments, against any RPC rather than one.

mod record;
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
    /// Fill in a scenario against a real account.
    ///
    /// Reads the invocations from the scenario file, runs each as the shipped
    /// binary, re-keys what was captured, and leaves a file that is safe to
    /// commit. A destructive recovery cannot be repeated without pairing a
    /// phone again, so the whole sequence is captured in one run.
    Record {
        /// The scenario file to fill in.
        #[arg(long)]
        scenario: std::path::PathBuf,

        /// Keep the raw recording instead of re-keying it.
        ///
        /// Writes **real key material and a live token** beside the scenario,
        /// for debugging a recording that went wrong. Never commit the result.
        #[arg(long)]
        no_rekey: bool,
    },
}

fn main() -> std::process::ExitCode {
    if let Err(e) = heyl_platform::harden_process() {
        eprintln!("heyl-fixtures: {e}");
        return std::process::ExitCode::FAILURE;
    }

    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
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
        Command::Record { scenario, no_rekey } => {
            runtime.block_on(record::run(&cli.endpoint, &scenario, !no_rekey))
        }
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("heyl-fixtures: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
