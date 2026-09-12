//! Running a scenario: the real binary, against a recorded backend.
//!
//! A scenario is a list of `heyl` invocations recorded once against a live
//! account and replayed here — the real binary, its own argv parsing, its own
//! output, over a real socket (DESIGN.md §6).
//!
//! Not the *shipped* binary, and the distinction is worth keeping honest: these
//! steps drive `recovery` and `doctor`, which a release build does not have, and
//! the two ports below need `--features dev` anyway. The suite covers the argv →
//! stdout contract over real traffic; it will cover a release build's own
//! commands when the read path has recordings.
//!
//! Two ports cannot travel over that socket and are injected instead:
//!
//! * **randomness**, because what a recording sealed — the phone's pairing
//!   reply, the unlock grant — is sealed to keys the recording derived from its
//!   own draws. `meta.first_draw` states the first one, and `rekey` re-sealed
//!   the corpus against exactly the sequence that follows it.
//! * **the keychain**, because the steps are separate processes and step one
//!   stores what step two reads. `meta.store` seeds it, for the scenarios whose
//!   whole subject is a refusal that never reaches the backend.
//!
//! The clock is *not* injected: nothing compares an expiry against `now()`, and
//! the only port sleep is the one-second pacing of the unlock poll — which a
//! step keeps short by declaring `collapse`, so the corpus holds one "still
//! locked" answer rather than one per second a person took to approve.
//!
//! **The runner supplies `--format json`**; no step's argv carries it. That is
//! deliberate: every command a scenario runs must render documents, and one
//! that went back to printing prose fails to parse here rather than quietly
//! asserting nothing.
//!
//! **A scenario with no recording fails**, naming the command that would make
//! one. `build.rs` turns every file in the directory into a test, so writing
//! the invocations is enough to make the suite demand the traffic behind them —
//! which is the property worth having, because a recording costs a phone swipe
//! and is therefore the step most likely to be put off.
//!
//! What is asserted is the exit code and the documents on stdout. Not stderr,
//! which is prose for people and would make every copy edit a test failure; and
//! not the traffic, because the corpus is an *input*, not an expectation.

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

    // A scenario nobody has recorded yet fails here rather than twelve lines
    // into a replay, where it would read as "the backend ran out of answers".
    // Failing at all is the point: an invocation list somebody wrote and never
    // recorded is work that is not finished, and a suite that stayed green
    // over it would be the thing that let it be forgotten.
    if !bless {
        assert_unrecorded(name, &scenario, &path);
    }

    let server = Server::start(Arc::new(RecordedApi::new(Vec::new())))
        .await
        .expect("a loopback port");
    let state = TestDir::new(name, &scenario.meta.store);
    let mut blessed = false;

    for (index, step) in scenario.steps.iter_mut().enumerate() {
        let number = index + 1;
        server.serve_from(Arc::new(RecordedApi::new(step.calls.clone())));

        let outcome = invoke(step, &server.endpoint(), &state, &scenario.meta.first_draw).await;

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
                let differences = documents_differ(&expected, &printed);
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

/// Fail, with the command that finishes the job, if this is not a recording.
///
/// Two states look alike from here and are not: a file whose steps were never
/// run against an account, and one that was recorded but whose expectations
/// have not been written. Each has its own next command, so each gets its own
/// message.
///
/// # Panics
/// When any step has no expected output.
fn assert_unrecorded(name: &str, scenario: &Scenario, path: &std::path::Path) {
    if scenario.steps.iter().all(|step| step.stdout.is_some()) {
        return;
    }

    // A scenario with no traffic anywhere and no stated draw has never met an
    // account. One with either has, and only needs blessing.
    let never_recorded = scenario.steps.iter().all(|step| step.calls.is_empty())
        && scenario.meta.first_draw.is_empty();

    let message = if never_recorded {
        format!(
            "{name} has invocations but no recording.\n\
             \n\
             Record it against a real account. It asks for the swipes and approvals\n\
             its steps declare, one banner at a time:\n\
             \n\
             \x20   cargo run -p heyl-fixtures -- record --scenario {}\n\
             \n\
             A scenario that needs no account instead states its own local state in\n\
             `meta.store`, and carries \"stdout\": [].",
            path.display(),
        )
    } else {
        format!(
            "{name} is recorded, but has no expected output yet.\n\
             \n\
             \x20   HEYL_BLESS=1 cargo test -p heyl --features dev scenario::{}\n\
             \n\
             Read the diff before committing: blessing writes whatever the binary\n\
             printed, so an expectation is only as good as the reading of it.",
            name.replace(['-', '.', ' '], "_"),
        )
    };
    panic!("{message}");
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
        // Supplied here rather than written into every step's argv: what the
        // suite asserts is the documents on stdout, so every command it runs
        // has to render them. A verb that printed prose instead would fail to
        // parse rather than assert an empty document list.
        .args(["--format", "json"])
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

    // What the step asked for, before what the harness owns: a scenario may add
    // `HEYL_SESSION` to drive the selection rule, and may not point the binary
    // at a real backend or unbind the draw sequence by naming those variables.
    command.envs(&step.env);

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

/// Everything a step printed on stdout, as documents.
///
/// A stream rather than one value: `session create` prints its pairing URL and
/// then its result, and `--format json-pretty` spreads a document over many
/// lines, so neither "one document" nor "one per line" would read both. A
/// `StreamDeserializer` reads concatenated values whatever the whitespace
/// between them.
fn parse_stdout(raw: &str, name: &str, step: usize) -> Vec<serde_json::Value> {
    serde_json::Deserializer::from_str(raw)
        .into_iter::<serde_json::Value>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| {
            panic!("{name} step {step} printed something that is not JSON: {e}\n{raw}")
        })
}

/// Where two *lists* of documents disagree.
///
/// The count comes first and stops there: a step that printed one document
/// where two were expected has a different story to tell than whatever its
/// first document says about the second's contents.
fn documents_differ(expected: &[serde_json::Value], actual: &[serde_json::Value]) -> Vec<String> {
    if expected.len() != actual.len() {
        return vec![format!(
            "  printed {} document(s), expected {}",
            actual.len(),
            expected.len()
        )];
    }

    let mut out = Vec::new();
    for (index, (want, got)) in expected.iter().zip(actual).enumerate() {
        // The pointer prefix names the document, so a failure in a two-document
        // step says which one.
        let at = if expected.len() == 1 {
            String::new()
        } else {
            format!("[{index}]")
        };
        walk(&at, want, got, &mut out);
    }
    trimmed(out)
}

/// Keep a failure readable.
///
/// The whole assertion is the output, so it has to read as a few lines about a
/// few values — not as two four-kilobyte documents printed side by side for a
/// reader to diff by eye.
fn trimmed(mut out: Vec<String>) -> Vec<String> {
    /// Enough to see the shape of a problem; beyond this the file is the place
    /// to look.
    const LIMIT: usize = 12;

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
///
/// Pointers address the **list** of documents the step printed, so
/// `/0/pairingUrl` is a field of the first one. A miss is not an error: a
/// pointer describes where a value lives when it is there.
fn redacted(documents: Vec<serde_json::Value>, pointers: &[String]) -> Vec<serde_json::Value> {
    let mut list = serde_json::Value::Array(documents);
    for pointer in pointers {
        if let Some(slot) = list.pointer_mut(pointer) {
            *slot = serde_json::Value::String("<redacted>".to_owned());
        }
    }
    match list {
        serde_json::Value::Array(documents) => documents,
        // Unreachable: it was an array a moment ago, and a pointer cannot
        // replace the root.
        other => vec![other],
    }
}

/// A scenario's own directory, removed when it finishes.
struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str, store: &std::collections::BTreeMap<String, String>) -> Self {
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
        let dir = Self { path };

        // The local state a scenario says it starts from. Written in the shape
        // `TestState` reads, because that is the only reader it will ever have
        // — and a scenario about a purely local refusal can then state its
        // precondition instead of spending a phone swipe on it.
        if !store.is_empty() {
            let state = serde_json::json!({ "secrets": store, "draws": 0 });
            std::fs::write(
                dir.store(),
                serde_json::to_string_pretty(&state).expect("a JSON object"),
            )
            .expect("the scenario's store is writable");
        }
        dir
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `redact` addresses the list of documents, because that is what a step
    /// prints. The value it exists for is `session create`'s pairing URL: the
    /// recording's carries a fresh random key, the fixture's carries the key a
    /// replay derives, and they are both right.
    #[test]
    fn a_pointer_reaches_into_the_document_it_names() {
        let printed = vec![
            serde_json::json!({ "pairingUrl": "https://app.heylogin.com/pair#live" }),
            serde_json::json!({ "slot": "ci", "sessionId": "0192a1b2" }),
        ];
        let blanked = redacted(printed, &["/0/pairingUrl".to_owned()]);

        assert_eq!(blanked[0]["pairingUrl"], "<redacted>");
        assert_eq!(blanked[1]["sessionId"], "0192a1b2", "only what was named");
    }

    /// A pointer that finds nothing is not a failure: it says where a value
    /// lives when it is there, and a step that exits early prints less.
    #[test]
    fn a_pointer_that_misses_is_harmless() {
        let printed = vec![serde_json::json!({ "slot": "ci" })];
        let blanked = redacted(printed, &["/0/pairingUrl".to_owned(), "/7/x".to_owned()]);
        assert_eq!(blanked, vec![serde_json::json!({ "slot": "ci" })]);
    }

    /// Two documents where one was expected is its own message: what the first
    /// one says about the second's contents is not the story.
    #[test]
    fn a_missing_document_is_reported_as_a_count() {
        let differences = documents_differ(
            &[serde_json::json!({ "a": 1 }), serde_json::json!({ "b": 2 })],
            &[serde_json::json!({ "a": 1 })],
        );
        assert_eq!(differences.len(), 1);
        assert!(differences[0].contains("printed 1 document(s), expected 2"));
    }
}
