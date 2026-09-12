//! Making a scenario: the real binary, the real account, one command.
//!
//! A scenario file starts as a hand-written list of invocations. This fills in
//! the rest: each step runs as the real `heyl` binary, pointed by
//! `HEYL_ENDPOINT` at a **recording proxy** on loopback which decodes each
//! call, forwards it to the real backend, keeps what crossed, and encodes the
//! reply back. The calls are heylogin's own, in the order the product actually
//! asks for them, because it *is* the product asking — and the binary carries
//! no recording code, only the endpoint variable a `dev` build reads. The
//! proxy and the replay server are the same server over a different
//! `HeyloginApi`. What each step printed is kept too, and it is the
//! expectation: stdout is captured while stderr stays inherited, so the QR
//! still draws for your phone.
//!
//! # What is committed, and why there is no re-key
//!
//! Everything. The account's seed is in the pairing reply, its profile seeds
//! and vault keys follow from that, and `meta.first_draw` states the draw the
//! reply is sealed to — so a replay opens the corpus with nothing but this
//! repository. That is the whole trick, and the whole cost: **the recording
//! account is a burner whose keys are public.**
//!
//! The alternative was to rebuild every layer under synthetic keys, which is
//! what this tool used to do in about five hundred lines. Measured against
//! what it protects, that was the wrong trade for an account that holds only
//! fabricated credentials — so the keys are published and retired instead.
//!
//! **Retiring them is a ritual, and it is not optional** (see
//! `tools/README.md`). After a sitting, before publishing:
//!
//! 1. **reset the phone with the backup code.** The server deletes the old
//!    PUSH authenticator and the phone re-enrols with a fresh seed, so the
//!    published seed's authenticator no longer exists and cannot log in.
//!    On its own this rotates nothing — measured.
//! 2. **regenerate the backup code.** That deletes an authenticator through
//!    the client path, which regenerates every profile seed and rotates the
//!    vault keys — measured: four profiles and five vaults moved. On its own
//!    it is useless, because a surviving authenticator's published seed simply
//!    receives the new locks.
//!
//! Together: the published seed belongs to an authenticator that is gone, and
//! every key it ever derived is stale. Forget them and a live account is in a
//! public repository — which is the failure mode this design accepts in
//! exchange for not having a re-key.

use std::{path::Path, sync::Arc};

use base64::Engine as _;

use heyl_grpc::{RecordingApi, Scenario, Server};

/// Record every step of a scenario against a live account.
///
/// # Errors
/// A message naming the phase that failed.
pub async fn run(endpoint: &str, path: &Path) -> Result<(), String> {
    let mut scenario = Scenario::load(path).map_err(|e| e.to_string())?;
    if scenario.steps.is_empty() {
        return Err(format!("{} has no steps to record", path.display()));
    }

    let binary = binary()?;

    let work = std::env::temp_dir().join(format!("heyl-recording-{}", std::process::id()));
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let store = work.join("store.json");

    // The draw the phone seals the seed to. Fresh, so nothing predictable
    // reaches the account; kept here, so phase 2 can open what the phone sent.
    // It is never written to disk, and never reaches the scenario file.
    let first_draw = {
        use heyl_ports::RandomSource as _;
        heyl_platform::OsRandom.seed()
    };

    // The proxy is bound before the first step and outlives all of them, so a
    // step's calls are simply what its own recorder kept.
    let config = heyl_grpc::GrpcConfig {
        endpoint: endpoint.to_owned(),
        ..heyl_grpc::GrpcConfig::default()
    };
    let proxy = Server::start(Arc::new(heyl_grpc::RecordedApi::new(Vec::new())))
        .await
        .map_err(|e| format!("binding the recording proxy: {e}"))?;

    eprintln!("recording against {endpoint}");
    for (index, step) in scenario.steps.iter_mut().enumerate() {
        eprintln!("  step {}: heyl {}", index + 1, step.argv.join(" "));
        // What the person at the keyboard has to do, before the step that
        // needs it runs. The scenario file is the runbook: a sitting that wants
        // a swipe here and a deliberate refusal there says so in the file
        // rather than in someone's memory.
        if let Some(note) = step.note.as_deref() {
            eprintln!("  >>> {note}");
        }

        let recorder = Arc::new(RecordingApi::new(
            heyl_grpc::GrpcClient::new(config.clone()).map_err(|e| format!("client: {e}"))?,
        ));
        proxy.serve_from(Arc::clone(&recorder) as Arc<dyn heyl_grpc::HeyloginApi>);

        let printed = invoke(&binary, step, &proxy.endpoint(), &store, &first_draw)?;
        step.stdout = Some(printed.documents);
        step.calls = recorder.records();
        let captured = step.calls.len();
        let collapsed = collapse(&mut step.calls, &step.collapse);
        if collapsed > 0 {
            eprintln!("           {captured} calls ({collapsed} repeated answers collapsed)");
        } else {
            eprintln!("           {captured} calls");
        }

        if printed.code != step.exit {
            return Err(format!(
                "step {} exited {}, but the scenario says {}",
                index + 1,
                printed.code,
                step.exit
            ));
        }
    }

    // The draw the pairing reply is sealed to. Stating it is what lets a replay
    // derive the same ephemeral key and open the account seed the phone sent —
    // which is how the corpus opens with nothing but this repository.
    scenario.meta.first_draw = base64::engine::general_purpose::STANDARD.encode(first_draw);

    // Two values do not go in verbatim — see `scrub`.
    let mut replaced: usize = scenario
        .steps
        .iter_mut()
        .flat_map(|step| step.calls.iter_mut())
        .map(scrub)
        .sum();

    // And once more over the hand-written argv, which is not traffic and so is
    // not reached above: `recovery --email <address>` needs the real one to
    // find the account, and a replay does not (its request falls back to
    // matching on method and order).
    for argument in scenario
        .steps
        .iter_mut()
        .flat_map(|step| step.argv.iter_mut())
    {
        if argument.contains('@') && argument.contains('.') {
            "fixture@example.com".clone_into(argument);
            replaced += 1;
        }
    }
    eprintln!("         scrubbed {replaced} value(s): access tokens, the account address");

    scenario.write(path).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&work);
    eprintln!("         wrote {}", path.display());

    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().replace(['-', '.', ' '], "_"))
        .ok_or_else(|| format!("{} has no file name", path.display()))?;
    eprintln!("         it is a test now; run it:");
    eprintln!("           cargo test -p heyl --features dev scenario::{name}");
    ritual();
    Ok(())
}

/// The two things that must happen before any of this is published.
///
/// Printed rather than documented-only because the failure is silent: a
/// forgotten ritual leaves a live account in a public repository and nothing
/// anywhere goes red. This is the one place a person is guaranteed to be
/// looking.
fn ritual() {
    eprintln!();
    eprintln!("  ┌─ BEFORE YOU COMMIT ─────────────────────────────────────────┐");
    eprintln!("  │ This file contains the account's seed, and everything it     │");
    eprintln!("  │ unlocks. That is deliberate. Retire the keys now:            │");
    eprintln!("  │                                                              │");
    eprintln!("  │  1. reset the phone with the backup code                      │");
    eprintln!("  │     (deletes the PUSH authenticator; the phone re-enrols      │");
    eprintln!("  │      with a fresh seed, so the published one cannot log in)   │");
    eprintln!("  │  2. regenerate the backup code in the app                     │");
    eprintln!("  │     (regenerates every profile seed and rotates the vault     │");
    eprintln!("  │      keys, so the published seed derives nothing current)     │");
    eprintln!("  │                                                              │");
    eprintln!("  │ Neither step works without the other. tools/README.md says    │");
    eprintln!("  │ why, and what was measured.                                   │");
    eprintln!("  └──────────────────────────────────────────────────────────────┘");
}

/// Every scenario that has invocations but no recording, in the order to
/// record them.
///
/// "No recording" is the same test the suite applies: a step with no expected
/// output has never run. Alphabetical, except that a scenario driving
/// `recovery` is recorded **last** — the backup-code login deletes the PUSH
/// authenticator, so recording it first would leave every other scenario
/// without a phone to pair with.
///
/// # Errors
/// If the scenario directory cannot be read.
pub fn unrecorded() -> Result<Vec<std::path::PathBuf>, String> {
    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/heyl-cli/tests/scenarios"
    );
    unrecorded_in(Path::new(DIR))
}

/// The same, over a named directory, so the ordering rule can be tested.
///
/// # Errors
/// If the directory cannot be read.
fn unrecorded_in(dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut found: Vec<(bool, std::path::PathBuf)> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .filter_map(|path| {
            let scenario = heyl_grpc::Scenario::load(&path).ok()?;
            let unrecorded = scenario.steps.iter().any(|step| step.stdout.is_none());
            let destructive = scenario
                .steps
                .iter()
                .any(|step| step.argv.first().is_some_and(|verb| verb == "recovery"));
            unrecorded.then_some((destructive, std::fs::canonicalize(&path).unwrap_or(path)))
        })
        .collect();

    found.sort();
    if found.is_empty() {
        return Err(
            "every scenario is already recorded; name one with --scenario to redo it".to_owned(),
        );
    }
    Ok(found.into_iter().map(|(_, path)| path).collect())
}

/// The binary to record: built here, so it is this working tree's.
///
/// A recording is expensive — a phone swipe, a device on a real account — and
/// the way to waste one is to drive a `heyl` from last week. Building it is a
/// no-op when it is already current, and the path comes from cargo's own
/// report rather than from a guess about where the target directory is.
///
/// `HEYL_BINARY` still overrides, for the case this cannot serve: recording
/// against a binary that is deliberately *not* the working tree.
fn binary() -> Result<String, String> {
    if let Ok(path) = std::env::var("HEYL_BINARY") {
        eprintln!("phase 0  HEYL_BINARY is set; using {path} as it is");
        return Ok(path);
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    eprintln!("phase 0  building heyl --features dev");
    let out = std::process::Command::new(cargo)
        .args([
            "build",
            "-p",
            "heyl",
            "--features",
            "dev",
            "--message-format=json-render-diagnostics",
        ])
        // Diagnostics stay human and go to the terminal; the JSON this reads
        // is on stdout.
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("running cargo build: {e}"))?;

    if !out.status.success() {
        return Err("building `heyl --features dev` failed; nothing was recorded".to_owned());
    }

    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == "heyl")
        .filter_map(|m| m["executable"].as_str().map(str::to_owned))
        .next_back()
        .ok_or_else(|| "cargo built nothing it calls `heyl`".to_owned())
}

/// Run one step, pointed at the proxy.
/// What one step did: its exit code, and the documents it printed.
struct Printed {
    code: i32,
    documents: Vec<serde_json::Value>,
}

fn invoke(
    binary: &str,
    step: &heyl_grpc::Step,
    endpoint: &str,
    store: &Path,
    first_draw: &[u8; 32],
) -> Result<Printed, String> {
    use base64::Engine as _;
    use std::io::Write as _;

    // stdout is captured, because it is the expectation being recorded. That
    // costs nothing a person needs: the QR and every prompt go to *stderr*,
    // which stays inherited, and `is_interactive` tests *stdin* — so a pairing
    // code still draws for the phone while the binary takes the
    // non-interactive branch a replay takes.
    let mut child = std::process::Command::new(binary)
        // The same flag the replay supplies, so phase 1 and phase 3 drive one
        // code path. The QR still draws: it goes to stderr, and stderr is
        // inherited here.
        .args(["--format", "json"])
        .args(&step.argv)
        .envs(&step.env)
        .env("HEYL_ENDPOINT", endpoint)
        .env("HEYL_STORE", store)
        // The first draw, and only the first: `TestState` hands this out once
        // and then continues with its counter bytes. That first value is the
        // pairing key the account seed is sealed to, so it is fresh randomness
        // held in memory — and knowing it is what lets `rekey` open the reply.
        .env(
            "HEYL_SEED",
            base64::engine::general_purpose::STANDARD.encode(first_draw),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("running {binary}: {e}"))?;

    if let Some(stdin) = step.stdin.as_deref() {
        child
            .stdin
            .as_mut()
            .ok_or("stdin was piped")?
            .write_all(stdin.as_bytes())
            .map_err(|e| format!("writing stdin: {e}"))?;
    }
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
        .map_err(|e| format!("waiting for {binary}: {e}"))?;
    let code = output
        .status
        .code()
        .ok_or_else(|| "the step was killed by a signal".to_owned())?;

    // A stream of documents rather than one: `session create` prints its
    // pairing URL and then its result, and `json-pretty` spreads a document
    // over many lines, so neither "one value" nor "one per line" reads both.
    let raw = String::from_utf8_lossy(&output.stdout);
    let documents = serde_json::Deserializer::from_str(&raw)
        .into_iter::<serde_json::Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            format!(
                "heyl {} printed something that is not JSON: {e}\n{raw}",
                step.argv.join(" ")
            )
        })?;

    Ok(Printed { code, documents })
}

/// Keep only the ends of each run of consecutive calls to a declared method.
///
/// The unlock poll is why this exists: it asks `Sync` every second until a
/// person approves, so a recording carries one answer per second they took,
/// and a replay pays a second for each. The corpus is an *input* rather than an
/// expectation, and the loop is driven by two of those answers — the one that
/// said "still locked" and the one that carried the grant.
///
/// **The ends, not the identical ones.** Every poll's answer differs: the
/// backend stamps `serverTime` and bumps `syncVersion`, so a rule about equal
/// responses would never fire once against real traffic. Keeping the first and
/// last of a run is what actually holds, and it says something true about a
/// polling loop rather than about byte equality.
///
/// Opt-in per step and per method, because dropping the middle of a run is only
/// safe for a caller that stops when an answer tells it to. A caller that makes
/// a fixed number of identical calls would find the corpus short — which is the
/// declarer's business, and it fails loudly at the next replay.
///
/// Returns how many records were dropped.
fn collapse(calls: &mut Vec<heyl_grpc::Record>, methods: &[String]) -> usize {
    if methods.is_empty() {
        return 0;
    }
    let declared = |method: &str| methods.iter().any(|m| method.ends_with(m.as_str()));

    let before = calls.len();
    let mut kept: Vec<heyl_grpc::Record> = Vec::with_capacity(before);
    let mut run: Vec<heyl_grpc::Record> = Vec::new();

    let flush =
        |run: &mut Vec<heyl_grpc::Record>, kept: &mut Vec<heyl_grpc::Record>| match run.len() {
            0 => {}
            1..=2 => kept.append(run),
            _ => {
                kept.push(run.first().cloned().expect("non-empty"));
                kept.push(run.last().cloned().expect("non-empty"));
                run.clear();
            }
        };

    for call in calls.drain(..) {
        let continues = run
            .last()
            .is_some_and(|last: &heyl_grpc::Record| last.method == call.method);
        if !continues {
            flush(&mut run, &mut kept);
        }
        if declared(&call.method) {
            run.push(call);
        } else {
            flush(&mut run, &mut kept);
            kept.push(call);
        }
    }
    flush(&mut run, &mut kept);

    *calls = kept;
    before - calls.len()
}

/// Replace the two values a fixture should not carry verbatim.
///
/// Neither is a secret next to what sits beside it — the seed in the same file
/// opens everything these could reach — and each is here for its own reason:
///
/// * the **access token** expires, but a bearer token in a public repository is
///   what secret scanners are built to find, and the noise is avoidable;
/// * the **email address** is the account holder's rather than the account's.
///   The account is published on purpose; a person's mailbox is not part of
///   that bargain.
///
/// Returns how many values were replaced.
fn scrub(record: &mut heyl_grpc::Record) -> usize {
    /// What stands in for the account holder's address.
    const FIXTURE_EMAIL: &str = "fixture@example.com";

    fn walk(value: &mut serde_json::Value, replaced: &mut usize) {
        match value {
            serde_json::Value::Object(fields) => {
                for (key, value) in fields.iter_mut() {
                    let stand_in = match key.as_str() {
                        "token" => Some("fixture-access-token"),
                        "email" => Some(FIXTURE_EMAIL),
                        _ => None,
                    };
                    match stand_in {
                        Some(text) if value.is_string() => {
                            *value = serde_json::Value::String(text.to_owned());
                            *replaced += 1;
                        }
                        _ => walk(value, replaced),
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, replaced);
                }
            }
            _ => {}
        }
    }

    let mut replaced = 0;
    for response in &mut record.responses {
        walk(response, &mut replaced);
    }
    if let Some(request) = record.request.as_mut() {
        walk(request, &mut replaced);
    }
    replaced
}

#[cfg(test)]
mod tests {
    use heyl_grpc::corpus::{Record, RecordedError};

    use super::*;

    const SYNC: &str = "/domain.SyncService/Sync";

    fn sync(unlocked: bool) -> Record {
        Record {
            method: SYNC.to_owned(),
            request: None,
            responses: vec![serde_json::json!({
                "syncUpdate": { "sessions": [{ "unlockedUntil": unlocked.then_some("2026-01-01T00:00:00.000Z") }] }
            })],
            error: None,
        }
    }

    /// The unlock poll: one answer per second the person took, each differing
    /// by `serverTime`, then the one that carried the grant. A replay drives
    /// the same loop from the two ends.
    #[test]
    fn a_run_keeps_its_ends() {
        let mut calls = vec![
            sync(false),
            sync(false),
            sync(false),
            sync(false),
            sync(true),
        ];
        let dropped = collapse(&mut calls, &[SYNC.to_owned()]);

        assert_eq!(dropped, 3);
        assert_eq!(
            calls.len(),
            2,
            "the first answer, and the one that ended it"
        );
        assert_ne!(calls[0].responses, calls[1].responses);
    }

    /// A run is consecutive: a different method in between ends it, so the
    /// `Sync` before `RequestSessionUnlock` is not folded into the poll after
    /// it.
    #[test]
    fn a_different_method_ends_the_run() {
        let request = Record {
            method: "/domain.SessionService/RequestSessionUnlock".to_owned(),
            request: None,
            responses: vec![serde_json::json!({})],
            error: None,
        };
        let mut calls = vec![
            sync(false),
            request,
            sync(false),
            sync(false),
            sync(false),
            sync(true),
        ];
        assert_eq!(collapse(&mut calls, &[SYNC.to_owned()]), 2);
        assert_eq!(
            calls.iter().filter(|c| c.method == SYNC).count(),
            3,
            "the lone pre-check, plus the poll's two ends"
        );
    }

    /// Only the methods the step names, and only consecutive answers: a caller
    /// that legitimately asks twice still makes both calls, and would find one
    /// record if this guessed.
    #[test]
    fn nothing_is_collapsed_that_the_step_did_not_name() {
        let mut calls = vec![sync(false), sync(false)];
        assert_eq!(collapse(&mut calls, &[]), 0);
        assert_eq!(calls.len(), 2);

        let mut calls = vec![
            Record {
                method: "/domain.VaultService/ListCommits".to_owned(),
                request: None,
                responses: vec![serde_json::json!({ "newerCommits": [] })],
                error: None,
            },
            Record {
                method: "/domain.VaultService/ListCommits".to_owned(),
                request: None,
                responses: vec![serde_json::json!({ "newerCommits": [] })],
                error: None,
            },
        ];
        assert_eq!(collapse(&mut calls, &[SYNC.to_owned()]), 0);
        assert_eq!(calls.len(), 2);
    }

    /// A run of two keeps both — there is no middle to drop.
    #[test]
    fn refusals_are_left_alone() {
        let refusal = Record {
            method: SYNC.to_owned(),
            request: None,
            responses: Vec::new(),
            error: Some(RecordedError {
                status: 16,
                domain_code: None,
                message: "unauthenticated".to_owned(),
            }),
        };
        let mut calls = vec![refusal.clone(), refusal];
        assert_eq!(collapse(&mut calls, &[SYNC.to_owned()]), 0);
        assert_eq!(calls.len(), 2);
    }
}

#[cfg(test)]
mod scrub_tests {
    use heyl_grpc::corpus::Record;

    use super::*;

    /// The two values that do not go in verbatim, wherever they sit — a token
    /// nested under `accessToken`, an address in a list of profiles.
    #[test]
    fn the_token_and_the_address_are_replaced_wherever_they_are() {
        let mut record = Record {
            method: "/domain.CredentialService/CreateTokens".to_owned(),
            request: Some(serde_json::json!({ "email": "someone@example.org" })),
            responses: vec![serde_json::json!({
                "accessToken": { "token": "eyJhbGciOiJIUzI1NiJ9.real" },
                "syncUpdate": { "relatedProfiles": [{ "email": "someone@example.org" }] }
            })],
            error: None,
        };

        assert_eq!(scrub(&mut record), 3);
        let text = serde_json::to_string(&record).expect("renders");
        assert!(!text.contains("someone@example.org"));
        assert!(!text.contains("eyJhbGciOiJIUzI1NiJ9.real"));
        assert_eq!(
            record.responses[0]["syncUpdate"]["relatedProfiles"][0]["email"],
            "fixture@example.com"
        );
    }

    /// Everything else is kept exactly as the backend sent it — that is the
    /// whole design, and a scrub that reached further would be re-keying by
    /// accident.
    #[test]
    fn nothing_else_is_touched() {
        let sealed = "c2VhbGVkLXNlZWQtYnl0ZXM=";
        let mut record = Record {
            method: "/domain.SyncService/Sync".to_owned(),
            request: None,
            responses: vec![serde_json::json!({
                "syncUpdate": { "sessionUnlock": { "encryptedSecret": sealed } }
            })],
            error: None,
        };

        assert_eq!(scrub(&mut record), 0);
        assert_eq!(
            record.responses[0]["syncUpdate"]["sessionUnlock"]["encryptedSecret"],
            sealed
        );
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    fn write(dir: &Path, name: &str, argv: &[&str], recorded: bool) {
        let stdout = if recorded { "\"stdout\": []," } else { "" };
        let argv = argv
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            dir.join(name),
            format!(
                r#"{{"meta": {{"code": "", "first_draw": ""}},
                     "steps": [{{"argv": [{argv}], {stdout} "calls": []}}]}}"#
            ),
        )
        .expect("writes");
    }

    /// A sitting records what has no recording, and the destructive one goes
    /// last: the backup-code login deletes the authenticator every other
    /// recording pairs with, so recording it first would waste the sitting.
    #[test]
    fn the_recovery_is_recorded_last() {
        let dir = std::env::temp_dir().join(format!("heyl-discovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a directory");

        write(&dir, "a-recovery.json", &["recovery", "--confirm"], false);
        write(&dir, "b-session.json", &["session", "list"], false);
        write(&dir, "c-done.json", &["session", "list"], true);

        let found = unrecorded_in(&dir).expect("reads");
        let names: Vec<String> = found
            .iter()
            .map(|p| {
                p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        assert_eq!(
            names,
            ["b-session.json", "a-recovery.json"],
            "the recorded one is skipped, and the recovery is last despite sorting first"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
