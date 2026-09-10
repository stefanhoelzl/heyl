//! Running a scenario: the real binary, against a recorded backend.
//!
//! A scenario is a list of `heyl` invocations recorded once against a live
//! account and replayed here — the shipped binary, its own argv parsing, its
//! own output, over a real socket (DESIGN.md §6).
//!
//! Two ports cannot travel over that socket and are injected instead:
//!
//! * **randomness**, because the recorded unlock grant is sealed to the session
//!   key the recording derived. `meta.session_seed` states the first draw, and
//!   `rekey` re-sealed the corpus against exactly the sequence that follows it.
//! * **the keychain**, because the steps are separate processes and step one
//!   stores what step two reads.
//!
//! The clock is *not* injected: nothing compares an expiry against `now()`, and
//! the only port sleep is the one-second pacing of the unlock poll, which costs
//! a scenario whatever its recording contains.
//!
//! What is asserted is the exit code and the JSON on stdout. Not stderr, which
//! is prose for people and would make every copy edit a test failure; and not
//! the traffic, because the corpus is an *input*, not an expectation.

use std::{path::PathBuf, sync::Arc};

use heyl_grpc::{RecordedApi, Scenario, Server};

/// Set to rewrite each step's expected output from what the run produced.
const BLESS_ENV: &str = "HEYL_BLESS";

/// Run one scenario by name. Called by the tests `build.rs` generates.
///
/// # Panics
/// With a message naming the step, whenever the run disagrees with the file.
pub fn run(name: &str) {
    // Multi-threaded on purpose: the server has to keep answering while this
    // thread waits on a child process.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(run_scenario(name));
}

fn path_of(name: &str) -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/scenarios"))
        .join(format!("{name}.json"))
}

async fn run_scenario(name: &str) {
    let path = path_of(name);
    let mut scenario = Scenario::load(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    let bless = std::env::var_os(BLESS_ENV).is_some();

    let server = Server::start(Arc::new(RecordedApi::new(Vec::new())))
        .await
        .expect("a loopback port");
    let state = TestDir::new(name);
    let mut blessed = false;

    for (index, step) in scenario.steps.iter_mut().enumerate() {
        let number = index + 1;
        server.serve_from(Arc::new(RecordedApi::new(step.calls.clone())));

        let outcome = invoke(
            step,
            &server.endpoint(),
            &state,
            &scenario.meta.session_seed,
        )
        .await;

        // Reaching past what a scenario records is a test problem. It is
        // reported as one here rather than as whatever the binary printed
        // when the backend it was talking to ran out of answers.
        let unmatched = server.unmatched();
        assert!(
            unmatched.is_empty(),
            "{name} step {number} ({}) asked for calls the scenario has no record of:\n  {}",
            step.argv.join(" "),
            unmatched.join("\n  "),
        );

        assert_eq!(
            outcome.code,
            step.exit,
            "{name} step {number} ({}) exited {}, expected {}\n--- stderr ---\n{}",
            step.argv.join(" "),
            outcome.code,
            step.exit,
            outcome.stderr,
        );

        let printed = parse_stdout(&outcome.stdout, name, number);
        match (&step.stdout, bless) {
            (_, true) => {
                blessed |= step.stdout.as_ref() != Some(&printed);
                step.stdout = Some(printed);
            }
            (Some(expected), false) => {
                let (expected, printed) = (
                    redacted(expected.clone(), &step.redact),
                    redacted(printed, &step.redact),
                );
                let differences = differences(&expected, &printed);
                assert!(
                    differences.is_empty(),
                    "{name} step {number} ({}) printed something else:\n{}\n\
                     Run with {BLESS_ENV}=1 if the new output is the intended one.",
                    step.argv.join(" "),
                    differences.join("\n"),
                );
            }
            (None, false) => panic!(
                "{name} step {number} ({}) has no expected output.\n\
                 Run with {BLESS_ENV}=1 to write it, then read the diff before committing.",
                step.argv.join(" "),
            ),
        }
    }

    if blessed {
        scenario
            .write(&path)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        eprintln!("{name}: wrote expectations to {}", path.display());
    }
}

/// What one invocation did.
struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
}

async fn invoke(step: &heyl_grpc::Step, endpoint: &str, state: &TestDir, seed: &str) -> Outcome {
    use tokio::io::AsyncWriteExt as _;

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_heyl"));
    command
        .args(&step.argv)
        // `heyl` reads several variables from the environment on purpose, so a
        // scenario starts from nothing: the developer's own session, endpoint or
        // recovery code must not reach it.
        .env_clear();

    // What the OS itself needs to run a process at all. Windows is the reason
    // this is not just `PATH`: without `SYSTEMROOT` a process cannot initialise
    // winsock or the platform crypto provider, so every step would fail to
    // reach even the loopback server. CI builds and tests all five shipped
    // targets, so a Windows-only break fails the pull request that wrote it.
    for name in [
        "PATH",
        #[cfg(windows)]
        "SYSTEMROOT",
        #[cfg(windows)]
        "TEMP",
        #[cfg(windows)]
        "TMP",
    ] {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }

    command
        // The scenario's own directory, so nothing reaches a real keychain even
        // if an adapter went looking for one.
        .env("HOME", state.path.display().to_string())
        .env("USERPROFILE", state.path.display().to_string())
        .env("HEYL_ENDPOINT", endpoint)
        .env("HEYL_STORE", state.store().display().to_string())
        .env("HEYL_SEED", seed)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = command.spawn().expect("the binary under test runs");
    if let Some(stdin) = step.stdin.as_deref() {
        let mut pipe = child.stdin.take().expect("piped");
        pipe.write_all(stdin.as_bytes()).await.expect("writes");
        pipe.shutdown().await.expect("closes");
    } else {
        drop(child.stdin.take());
    }

    let output = child.wait_with_output().await.expect("the child exits");
    Outcome {
        // A signal leaves no code; -1 is not a code any command returns, so it
        // fails the comparison rather than accidentally matching one.
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn parse_stdout(raw: &str, name: &str, step: usize) -> serde_json::Value {
    if raw.trim().is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::from_str(raw).unwrap_or_else(|e| {
        panic!("{name} step {step} printed something that is not JSON: {e}\n{raw}")
    })
}

/// Where two documents disagree, by JSON pointer.
///
/// The whole assertion is the output, so a failure has to read as one line
/// about one value — not as two four-kilobyte documents printed side by side
/// for a reader to diff by eye.
fn differences(expected: &serde_json::Value, actual: &serde_json::Value) -> Vec<String> {
    /// Enough to see the shape of a problem; beyond this the file is the place
    /// to look.
    const LIMIT: usize = 12;

    let mut out = Vec::new();
    walk("", expected, actual, &mut out);
    if out.len() > LIMIT {
        let extra = out.len() - LIMIT;
        out.truncate(LIMIT);
        out.push(format!("  … and {extra} more"));
    }
    out
}

fn walk(at: &str, expected: &serde_json::Value, actual: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value::{Array, Object};

    let here = || if at.is_empty() { "/" } else { at };
    match (expected, actual) {
        (Object(want), Object(got)) => {
            for (key, value) in want {
                match got.get(key) {
                    Some(other) => walk(&format!("{at}/{key}"), value, other, out),
                    None => out.push(format!("  {at}/{key}: missing (expected {})", brief(value))),
                }
            }
            for key in got.keys().filter(|key| !want.contains_key(*key)) {
                out.push(format!("  {at}/{key}: unexpected"));
            }
        }
        (Array(want), Array(got)) if want.len() == got.len() => {
            for (index, (value, other)) in want.iter().zip(got).enumerate() {
                walk(&format!("{at}/{index}"), value, other, out);
            }
        }
        (Array(want), Array(got)) => out.push(format!(
            "  {}: {} items, expected {}",
            here(),
            got.len(),
            want.len()
        )),
        _ if expected != actual => out.push(format!(
            "  {}: expected {}, got {}",
            here(),
            brief(expected),
            brief(actual)
        )),
        _ => {}
    }
}

/// A value, short enough to sit on one line.
fn brief(value: &serde_json::Value) -> String {
    let rendered = value.to_string();
    if rendered.chars().count() <= 60 {
        return rendered;
    }
    format!("{}…", rendered.chars().take(59).collect::<String>())
}

/// Blank the values a step declares as local rather than server-provided.
fn redacted(mut document: serde_json::Value, pointers: &[String]) -> serde_json::Value {
    for pointer in pointers {
        if let Some(slot) = document.pointer_mut(pointer) {
            *slot = serde_json::Value::String("<redacted>".to_owned());
        }
    }
    document
}

/// A scenario's own directory, removed when it finishes.
struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let unique = format!(
            "heyl-scenario-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default(),
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self { path }
    }

    fn store(&self) -> PathBuf {
        self.path.join("store.json")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
