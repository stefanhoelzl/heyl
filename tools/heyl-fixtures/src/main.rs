//! Development tooling. Not published, not shipped, not on any user's machine.
//!
//! One job, which needs a real account and therefore cannot live in the test
//! suite: `record` fills in a scenario by running the real binary against a
//! live account and keeping what crossed the wire.
//!
//! It does not re-key. The recording account is a **burner whose keys are
//! published**: its seed is in the committed fixtures, which is exactly what
//! lets them open with nothing but this repository. The cost is a ritual
//! rather than a program — reset the phone with the backup code, then
//! regenerate the backup code — and `tools/README.md` states it where it
//! cannot be missed.
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
    /// Reads the invocations from the scenario file, runs each as the real
    /// binary, and keeps what crossed the wire — the account's own material,
    /// published deliberately. The recording account is a burner whose keys
    /// are public; a sitting ends by retiring them (`tools/README.md`).
    Record {
        /// Which scenario to fill in. Repeatable, and recorded in the order
        /// given.
        #[arg(long, conflicts_with = "all")]
        scenario: Vec<std::path::PathBuf>,

        /// Record every scenario that has invocations but no recording.
        ///
        /// One sitting, one command. The order is alphabetical with one
        /// exception that is not cosmetic: a scenario that runs `recovery`
        /// goes **last**, because it deletes the authenticator every other
        /// recording pairs with.
        #[arg(long)]
        all: bool,
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
        Command::Record { scenario, all } => runtime.block_on(async {
            let paths = if all {
                record::unrecorded()?
            } else if scenario.is_empty() {
                return Err("pass --scenario <file>, repeatable, or --all".to_owned());
            } else {
                scenario
            };

            // Each file is written as it finishes, so a failure costs the file
            // it was filling and nothing that came before it.
            let total = paths.len();
            for (index, path) in paths.iter().enumerate() {
                if total > 1 {
                    eprintln!("=== {} of {total}: {}", index + 1, path.display());
                }
                record::run(&cli.endpoint, path).await?;
            }
            Ok(())
        }),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("heyl-fixtures: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
