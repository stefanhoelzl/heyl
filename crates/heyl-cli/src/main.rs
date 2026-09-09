//! `heyl` — the composition root.
//!
//! This is the **only** crate that names an adapter. `heyl-app` depends on the
//! port traits and on nothing that implements them, so it is physically
//! incapable of reaching an OS API or constructing a request; the wiring
//! happens here, once (DESIGN.md §4).

mod output;
mod wiring;

use clap::{Parser, Subcommand};
use heyl_app::{AppError, ExitCode};

/// Unofficial command-line client for heylogin.
#[derive(Debug, Parser)]
#[command(name = "heyl", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Backend endpoint. For testing against a recorded or local server.
    #[arg(long, global = true, env = "HEYL_ENDPOINT", hide = true)]
    endpoint: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Log in and store a session.
    Login {
        #[command(subcommand)]
        method: LoginMethod,
    },

    /// Check the key hierarchy against the backend, link by link.
    ///
    /// Recovers the seed from this session's unlock grant, derives every key,
    /// compares each against the public half heylogin publishes, then opens
    /// every vault. This is what confirms that the reverse-engineered
    /// derivation actually agrees with heylogin.
    Doctor {
        /// Output format. `json` is **unstable** until the output contract
        /// lands with `list` and `get`.
        #[arg(long, value_enum, default_value_t = output::Format::Human)]
        format: output::Format,
    },
}

#[derive(Debug, Subcommand)]
enum LoginMethod {
    /// Log in with a recovery code.
    ///
    /// The code is read from `HEYL_RECOVERY_CODE`, or prompted for without
    /// echo, or read from stdin when piped. There is deliberately **no
    /// `--code` flag**: a recovery code is a reusable master credential for
    /// every vault, so putting it in argv would leak it into `ps` output and
    /// shell history.
    Recovery {
        /// The account's email address.
        #[arg(long, env = "HEYL_EMAIL")]
        email: Option<String>,
    },
}

fn main() -> std::process::ExitCode {
    // Before anything can reach for a secret: no core dumps, and memory
    // locking must actually work. Failing here is deliberate -- see
    // `heyl_platform::process`.
    if let Err(e) = heyl_platform::harden_process() {
        eprintln!("heyl: {e}");
        return std::process::ExitCode::from(ExitCode::Failure as u8);
    }

    // `current_thread`: measured ~650 µs cheaper per invocation than
    // `multi_thread`, with an identical binary size (DESIGN.md §4).
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("heyl: could not start the async runtime: {e}");
            return std::process::ExitCode::from(ExitCode::Failure as u8);
        }
    };

    match runtime.block_on(run(Cli::parse())) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("heyl: {e}");
            std::process::ExitCode::from(e.exit_code() as u8)
        }
    }
}

async fn run(cli: Cli) -> Result<std::process::ExitCode, AppError> {
    let adapters = wiring::Adapters::new(cli.endpoint.as_deref())?;
    let ports = adapters.ports();

    match cli.command {
        Command::Login {
            method: LoginMethod::Recovery { email },
        } => {
            let email = match email {
                Some(email) => email,
                None => ports.terminal.prompt_line("heylogin email: ")?,
            };
            let outcome = heyl_app::login::run(
                &ports,
                &email,
                wiring::code_source(),
                heyl_domain::ChallengeEncoding::Utf8,
                heyl_domain::SessionType::BackupCode,
            )
            .await?;
            output::login(&outcome);
            Ok(std::process::ExitCode::SUCCESS)
        }

        Command::Doctor { format } => {
            let report = heyl_app::doctor::run(&ports).await?;
            output::doctor(&report, format);
            Ok(if report.has_failures() {
                std::process::ExitCode::from(ExitCode::Failure as u8)
            } else {
                std::process::ExitCode::SUCCESS
            })
        }
    }
}
