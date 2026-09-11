//! Making a scenario: the real binary, the real account, one command.
//!
//! A scenario file starts as a hand-written list of invocations and nothing
//! else. This fills in the rest, in four phases:
//!
//! 1. **record** — run each step as the real `heyl` binary, pointed by
//!    `HEYL_ENDPOINT` at a *recording proxy* on loopback: it decodes each call,
//!    forwards it to the real backend, keeps what crossed, and encodes the reply
//!    back. The calls are heylogin's own, in the order the product actually asks
//!    for them, because it *is* the product asking — and the binary needs no
//!    recording code of its own, only the endpoint flag it already ships with.
//! 2. **rekey** — replace everything from which the seed could be recovered,
//!    keeping the real plaintext: genuine `serialize` framing, genuine snappy, a
//!    genuine heymerge document. That is what makes the file committable, and
//!    `verify` asserts it before anything is written.
//! 3. **replay** — run the scenario back against the re-keyed calls, which
//!    proves the result actually drives the binary rather than merely parsing.
//! 4. **expect** — write each step's output from *that* run, not from the live
//!    one: rekey moves identifiers, and live output would carry the real
//!    account's.
//!
//! Phases 3 and 4 are the scenario suite itself, run with `HEYL_BLESS=1`, so
//! there is one replay implementation rather than two that must agree.
//!
//! Between phase 1 and phase 2 the calls hold **real key material and a live
//! token**. They are held in memory and never written, unless `--no-rekey` is
//! passed to debug a recording that went wrong.

use std::{path::Path, sync::Arc};

use heyl_grpc::{RecordingApi, Scenario, Server};

/// Record every step of a scenario against a live account.
///
/// # Errors
/// A message naming the phase that failed.
pub async fn run(endpoint: &str, path: &Path, rekey_after: bool) -> Result<(), String> {
    let mut scenario = Scenario::load(path).map_err(|e| e.to_string())?;
    if scenario.steps.is_empty() {
        return Err(format!("{} has no steps to record", path.display()));
    }

    let binary = std::env::var("HEYL_BINARY").map_err(|_| {
        "set HEYL_BINARY to the `heyl` built with --features dev \
         (cargo build --features dev; target/debug/heyl)"
            .to_owned()
    })?;

    let work = std::env::temp_dir().join(format!("heyl-recording-{}", std::process::id()));
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let store = work.join("store.json");

    // The proxy is bound before the first step and outlives all of them, so a
    // step's calls are simply what its own recorder kept.
    let config = heyl_grpc::GrpcConfig {
        endpoint: endpoint.to_owned(),
        ..heyl_grpc::GrpcConfig::default()
    };
    let proxy = Server::start(Arc::new(heyl_grpc::RecordedApi::new(Vec::new())))
        .await
        .map_err(|e| format!("binding the recording proxy: {e}"))?;

    eprintln!("phase 1  recording against {endpoint}");
    for (index, step) in scenario.steps.iter_mut().enumerate() {
        eprintln!("  step {}: heyl {}", index + 1, step.argv.join(" "));

        let recorder = Arc::new(RecordingApi::new(
            heyl_grpc::GrpcClient::new(config.clone()).map_err(|e| format!("client: {e}"))?,
        ));
        proxy.serve_from(Arc::clone(&recorder) as Arc<dyn heyl_grpc::HeyloginApi>);

        let status = invoke(&binary, step, &proxy.endpoint(), &store)?;
        step.calls = recorder.records();
        eprintln!("           {} calls", step.calls.len());

        if status != step.exit {
            return Err(format!(
                "step {} exited {status}, but the scenario says {}",
                index + 1,
                step.exit
            ));
        }
    }

    if !rekey_after {
        let raw = path.with_extension("raw.json");
        scenario.write(&raw).map_err(|e| e.to_string())?;
        return Err(format!(
            "--no-rekey: wrote {} with REAL key material and a live token. \
             Do not commit it.",
            raw.display()
        ));
    }

    // One flat pass, because the re-key walks the chain in call order — the
    // five `ListCommits` are told apart by where they fall — and steps are put
    // back together afterwards from the lengths.
    eprintln!("phase 2  rekey");
    let lengths: Vec<usize> = scenario.steps.iter().map(|s| s.calls.len()).collect();
    let mut flat: Vec<_> = scenario
        .steps
        .iter_mut()
        .flat_map(|s| std::mem::take(&mut s.calls))
        .collect();
    let note = scenario.meta.note.clone();
    scenario.meta = crate::rekey::apply(&mut flat)?;
    scenario.meta.note = note;

    let mut rest = flat.into_iter();
    for (step, len) in scenario.steps.iter_mut().zip(lengths) {
        step.calls = rest.by_ref().take(len).collect();
    }

    // Expectations are deliberately dropped: they describe the previous
    // recording's identifiers, and phase 4 writes them from the new one.
    for step in &mut scenario.steps {
        step.stdout = None;
    }
    scenario.write(path).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&work);
    eprintln!("         wrote {}", path.display());

    eprintln!("phase 3  replay, and phase 4  expect");
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().replace(['-', '.', ' '], "_"))
        .ok_or_else(|| format!("{} has no file name", path.display()))?;
    eprintln!("         run: HEYL_BLESS=1 cargo test -p heyl --features dev scenario::{name}");
    Ok(())
}

/// Run one step, pointed at the proxy.
fn invoke(
    binary: &str,
    step: &heyl_grpc::Step,
    endpoint: &str,
    store: &Path,
) -> Result<i32, String> {
    use std::io::Write as _;

    // stdin is piped but stdout and stderr are inherited, which is not an
    // accident: `render_qr` tests *stdout* for a terminal while
    // `is_interactive` tests *stdin*, so a pairing code draws for the phone
    // while the binary still takes the non-interactive branch a replay takes.
    let mut child = std::process::Command::new(binary)
        .args(&step.argv)
        .env("HEYL_ENDPOINT", endpoint)
        .env("HEYL_STORE", store)
        // Without a seed the store is bound but the OS random source stays,
        // which is what a recording needs: `rekey` substitutes the synthetic
        // material afterwards, and predictable key material must never reach a
        // live account.
        .env_remove("HEYL_SEED")
        .stdin(std::process::Stdio::piped())
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

    child
        .wait()
        .map_err(|e| format!("waiting for {binary}: {e}"))?
        .code()
        .ok_or_else(|| "the step was killed by a signal".to_owned())
}
