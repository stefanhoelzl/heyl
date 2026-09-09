//! `heyl` — the composition root.
//!
//! This is the **only** crate that names an adapter. `heyl-app` depends on the
//! port traits and on nothing that implements them, so it is physically
//! incapable of reaching an OS API or constructing a request; the wiring
//! happens here, once (DESIGN.md §4).

#[cfg(feature = "api")]
mod api;
mod output;
mod wiring;

use std::sync::LazyLock;

use clap::{Parser, Subcommand};
use heyl_app::{AppError, ExitCode};

/// What `--version` prints: the crate version, and the commit it was built
/// from.
///
/// `HEYL_BUILD_SHA` is set by the artifact build in
/// `.github/workflows/ci.yml`. `option_env!` is what keeps a plain
/// `cargo build` working without it -- and printing no sha there is the honest
/// answer, because a local build is a working tree rather than a commit. Until
/// a version number is actually assigned (DESIGN.md §7) every build says
/// `0.0.0`, so the sha is the only thing that tells two binaries apart.
///
/// A `LazyLock<String>` rather than a `const`: the two halves cannot be
/// concatenated at compile time without pulling in a crate for it, and passing
/// clap an owned `String` would mean enabling its `string` feature. Borrowing
/// from a `static` costs one lazy allocation at startup and leaves the
/// dependency surface alone.
static VERSION: LazyLock<String> = LazyLock::new(|| match option_env!("HEYL_BUILD_SHA") {
    Some(sha) => format!("{} ({sha})", env!("CARGO_PKG_VERSION")),
    None => env!("CARGO_PKG_VERSION").to_owned(),
});

/// Unofficial command-line client for heylogin.
#[derive(Debug, Parser)]
#[command(name = "heyl", version = VERSION.as_str(), about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Backend endpoint. For testing against a recorded or local server.
    #[arg(long, global = true, env = "HEYL_ENDPOINT", hide = true)]
    endpoint: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Recover access with a recovery code, and store a session.
    ///
    /// This is **not** a login. heylogin treats a recovery code as an account
    /// recovery: the server disconnects your phone's authenticator and its
    /// locks, and pairing a phone again afterwards regenerates every profile.
    /// You will be shown what is about to be disconnected, and asked, unless
    /// there is nothing left to lose.
    ///
    /// The code is read from `HEYL_RECOVERY_CODE`, or prompted for without
    /// echo, or read from stdin when piped. There is deliberately **no
    /// `--code` flag**: a recovery code unlocks every vault, so putting it in
    /// argv would leak it into `ps` output and shell history.
    Recovery {
        /// The account's email address.
        #[arg(long, env = "HEYL_EMAIL")]
        email: Option<String>,

        /// Proceed without asking.
        ///
        /// Required to disconnect anything when there is no terminal to ask
        /// at — a destructive operation does not run silently just because
        /// nobody was there to object.
        #[arg(long)]
        confirm: bool,
    },

    /// heylogin's gRPC surface, by hand. **Unsafe by construction.**
    ///
    /// No guards, destructive RPCs reachable by name, key material printable.
    /// Point it at a throwaway account. Hidden, and only present in a build
    /// made with `--features api` (DESIGN.md §5).
    #[cfg(feature = "api")]
    #[command(hide = true)]
    Api {
        #[command(subcommand)]
        command: api::Api,
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
        #[cfg(feature = "api")]
        Command::Api { command } => match api::run(command, cli.endpoint.as_deref()).await {
            Ok(()) => Ok(std::process::ExitCode::SUCCESS),
            // Reported here rather than mapped into `AppError`: this is not a
            // use case, and the core should not learn a vocabulary for a tool
            // that is not shipped.
            Err(e) => {
                eprintln!("heyl: {e}");
                Ok(std::process::ExitCode::from(ExitCode::Failure as u8))
            }
        },

        Command::Recovery { email, confirm } => {
            let email = match email {
                Some(email) => email,
                None => ports.terminal.prompt_line("heylogin email: ")?,
            };
            let outcome = heyl_app::recovery::run(
                &ports,
                &email,
                if confirm {
                    heyl_app::recovery::Confirmation::Granted
                } else {
                    heyl_app::recovery::Confirmation::Ask("Disconnect and recover? [y/N] ")
                },
                wiring::code_source(),
                heyl_domain::ChallengeEncoding::Utf8,
                heyl_domain::SessionType::BackupCode,
            )
            .await?;
            output::recovery(&outcome);
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
