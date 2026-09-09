//! Development tooling. Not published, not shipped, not on any user's machine.
//!
//! Two jobs, both of which need a real account and therefore cannot live in
//! the test suite:
//!
//! * `record` — capture a whole session's gRPC-Web bytes in one pass, during
//!   the destructive recovery that is the only chance to see the login
//!   sequence.
//! * `rekey` — turn a real recorded exchange into a committed fixture whose
//!   key material is entirely synthetic, so the throwaway account's seed and
//!   recovery code never enter the repository.
//!
//! The probing subcommands are gone: `heyl api` does that job now, and better.
//! `probe-signing` existed to settle what `CreateTokens` verifies by varying
//! `client-type`, the authenticator and the signature; `heyl api call` varies
//! all three as ordinary arguments, against any RPC rather than one.

mod derive;
mod mem;
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
    /// Materialise a situation from the base corpus.
    ///
    /// A situation is a whole corpus on disk, not a patch applied at load
    /// time — but every record has to stay crypto-consistent, so it is the
    /// base copied and edited rather than hand-authored. `diff -r` against
    /// the base then shows the whole difference from reality.
    Derive {
        /// The corpus to copy.
        #[arg(long, default_value = "tests/fixtures/api/base")]
        base: std::path::PathBuf,

        /// Where the situation goes.
        #[arg(long)]
        out: std::path::PathBuf,

        /// `<record>:<pointer>=<json>`, repeatable. `null` removes the key.
        #[arg(long = "set")]
        set: Vec<String>,

        /// `<record>:<status>[:<domain-code>[:<message>]]`, repeatable.
        #[arg(long = "fail")]
        fail: Vec<String>,

        /// Keep only the first N records.
        #[arg(long)]
        truncate: Option<usize>,
    },

    /// Record a whole session against a real account, in one pass.
    ///
    /// Captures the gRPC-Web bytes for the recovery and every read `doctor`
    /// performs. The output holds **real key material and a live token** and is
    /// input to `rekey`, never something to commit.
    ///
    /// A destructive recovery cannot be repeated without pairing a phone
    /// again, so this captures everything a wire-level replay needs in a
    /// single run.
    Record {
        /// Where to write the raw recording. A directory of records.
        #[arg(long, default_value = ".work/recording")]
        out: std::path::PathBuf,

        /// Proceed without asking before disconnecting anything.
        #[arg(long)]
        confirm: bool,
    },

    /// Re-key a real recording into a committable fixture.
    ///
    /// Replaces every secret with synthetic material while keeping the real
    /// vault documents, then asserts the result opens with the committed test
    /// code and **not** with the real one.
    Rekey {
        /// The raw recording from `record`.
        #[arg(long, default_value = ".work/recording")]
        input: std::path::PathBuf,

        /// Where to write the fixture.
        #[arg(long, default_value = "tests/fixtures/api/base")]
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
        Command::Derive {
            base,
            out,
            set,
            fail,
            truncate,
        } => set
            .iter()
            .map(|raw| derive::parse_set(raw))
            .chain(fail.iter().map(|raw| derive::parse_fail(raw)))
            .chain(truncate.map(|n| Ok(derive::Edit::Truncate(n))))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|edits: Vec<derive::Edit>| derive::run(&base, &out, &edits)),

        Command::Record { out, confirm } => {
            runtime.block_on(record::run(&cli.endpoint, &out, confirm))
        }
        Command::Rekey { input, out } => rekey::run(&input, &out),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("heyl-fixtures: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
