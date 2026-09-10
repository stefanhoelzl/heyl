//! What the commands print.
//!
//! Secrets go to stdout raw and everything else goes to stderr (DESIGN.md §5).
//! Neither command here emits a secret at all: `login` reports a session, and
//! `doctor` reports comparisons. No key, plaintext or ciphertext is printed by
//! either, in either format.

use heyl_app::doctor::{Outcome, Report};
use heyl_app::recovery::RecoveryOutcome;
use heyl_app::session::{Created, Removed, Setting, Slot, SlotStatus};
use heyl_domain::SessionPolicy;

/// How to render a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// A table for a human.
    Human,
    /// JSON. **Unstable** until §5's output contract lands at M6 with `list`
    /// and `get` — `--format` is the only compatibility promise heyl makes,
    /// and it is not spent on a diagnostic before the read path exists.
    Json,
}

/// Report a completed recovery.
///
/// Says what was lost as well as what was gained: the user has a session, and
/// no longer has whatever the recovery disconnected.
pub fn recovery(outcome: &RecoveryOutcome, format: Format) {
    match format {
        Format::Human => recovery_human(outcome),
        Format::Json => recovery_json(outcome),
    }
}

/// `recovery`, as a machine reads it.
///
/// Every value here comes from the backend — the account, the session, the
/// window heylogin actually granted, the authenticators it listed as about to
/// go. Nothing is derived from the local clock, which is what lets a scenario
/// assert this document verbatim without normalising anything out of it.
fn recovery_json(outcome: &RecoveryOutcome) {
    let disconnected: Vec<_> = outcome
        .disconnected
        .iter()
        .map(|d| {
            serde_json::json!({
                "id": d.id.to_string(),
                "kind": format!("{:?}", d.kind),
            })
        })
        .collect();

    let document = serde_json::json!({
        "unstable": "recovery's JSON shape is not a compatibility promise until M6",
        "userId": outcome.user_id,
        "sessionId": outcome.session_id.to_string(),
        "unlockedUntil": outcome.unlocked_until.map(|t| t.to_string()),
        "disconnected": disconnected,
    });

    match serde_json::to_string_pretty(&document) {
        Ok(rendered) => println!("{rendered}"),
        Err(e) => eprintln!("heyl: could not render the recovery as JSON: {e}"),
    }
}

fn recovery_human(outcome: &RecoveryOutcome) {
    eprintln!("Recovered access to {}.", outcome.user_id);
    eprintln!("Session {} is registered.", outcome.session_id);
    match outcome.unlocked_until {
        Some(until) => eprintln!("Unlocked until {until} (the backend's value, not ours)."),
        None => eprintln!(
            "The backend reported no unlock window; `heyl doctor` will say whether the grant took."
        ),
    }

    if outcome.disconnected.is_empty() {
        return;
    }
    eprintln!("\nDisconnected from the account:");
    for d in &outcome.disconnected {
        eprintln!("  {:?}  {}", d.kind, d.id);
    }
    eprintln!(
        "\nPair a phone again to restore push access. That regenerates every profile and \
         re-locks every vault,\nso this session's keys stop working once you do."
    );
}

/// Report a hierarchy walk.
pub fn doctor(report: &Report, format: Format) {
    match format {
        Format::Human => human(report),
        Format::Json => json(report),
    }
}

fn human(report: &Report) {
    for check in &report.checks {
        let line = match &check.detail {
            Some(detail) => format!("{:<4}  {}  — {detail}", check.outcome.label(), check.name),
            None => format!("{:<4}  {}", check.outcome.label(), check.name),
        };
        println!("{line}");
    }

    let (pass, fail, skip) = report.tally();
    println!();
    println!("{pass} passed, {fail} failed, {skip} skipped");
    if fail > 0 {
        // Only key comparisons say anything about the hierarchy. A vault that
        // failed to *fetch* says nothing about our contexts, and telling
        // someone their context salt is wrong when the response was truncated
        // sends them to the wrong place entirely.
        let key_failures = report
            .checks
            .iter()
            .any(|c| c.outcome == Outcome::Fail && c.name.starts_with("link "));
        if key_failures {
            eprintln!(
                "\nA failed *link* means the derived key disagrees with the one heylogin\n\
                 publishes: the context salt for that link is wrong. See DESIGN.md §6."
            );
        } else {
            eprintln!(
                "\nNo derivation link failed — every key we derived matches the one heylogin\n\
                 publishes. The failures above are fetch or decode problems, which say nothing\n\
                 about the key hierarchy."
            );
        }
    }
}

fn json(report: &Report) {
    let checks: Vec<_> = report
        .checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "outcome": match c.outcome {
                    Outcome::Pass => "pass",
                    Outcome::Fail => "fail",
                    Outcome::Skip => "skip",
                },
                "detail": c.detail,
            })
        })
        .collect();

    let (pass, fail, skip) = report.tally();
    let document = serde_json::json!({
        "unstable": "doctor's JSON shape is not a compatibility promise until M6",
        "checks": checks,
        "summary": { "passed": pass, "failed": fail, "skipped": skip },
    });

    match serde_json::to_string_pretty(&document) {
        Ok(rendered) => println!("{rendered}"),
        Err(e) => eprintln!("heyl: could not render the report as JSON: {e}"),
    }
}

/// How to draw a pairing code, as a flag value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Qr {
    /// Unicode half-blocks: about 37 columns.
    Utf8,
    /// Two spaces per module — twice as wide, but survives odd fonts.
    Ascii,
    /// Print the URL only.
    None,
}

impl From<Qr> for heyl_ports::QrStyle {
    fn from(value: Qr) -> Self {
        match value {
            Qr::Utf8 => Self::Utf8,
            Qr::Ascii => Self::Ascii,
            Qr::None => Self::None,
        }
    }
}

/// Report a session that was just paired.
pub fn session_created(slot: &Slot, created: &Created, policy: SessionPolicy) {
    eprintln!(
        "Paired {} as {:?} — the name your phone will show.",
        slot.name(),
        created.display
    );
    eprintln!("Session {}.", created.session_id);
    eprintln!("Policy: {}.", describe(policy));
    match created.unlocked_until {
        Some(until) => eprintln!("Unlocked until {until}."),
        // The normal case, and worth saying plainly: pairing establishes an
        // identity, approving an unlock is a separate act.
        None => eprintln!("Locked. The first command that needs a secret will ask your phone."),
    }
}

/// Report an approved unlock.
pub fn session_unlocked(slot: &Slot, until: heyl_domain::Timestamp) {
    eprintln!("{} is unlocked until {until}.", slot.name());
}

/// Report what a removal managed to do.
///
/// Says what it could *not* do as well: a device left listed in the app is the
/// kind of drift a user should hear about immediately, not discover later.
pub fn session_removed(slot: &Slot, removed: &Removed) {
    match (removed.tombstoned, removed.deleted) {
        (true, true) => eprintln!("Removed {}.", slot.name()),
        (false, true) => eprintln!(
            "Deleted {} and forgot its keys, but could not tombstone its device entry — \
             it will keep appearing in the heylogin app until you remove it there.",
            slot.name()
        ),
        (true, false) => eprintln!(
            "Tombstoned {} and forgot its keys, but the backend session is still there.",
            slot.name()
        ),
        (false, false) => eprintln!(
            "Forgot {}'s keys locally; nothing else could be cleaned up.",
            slot.name()
        ),
    }
}

/// Print settings as `key=value`.
///
/// The vault-side name reads `<locked>` rather than being fetched: reading
/// settings must never reach the phone.
pub fn session_settings(values: &[(Setting, Option<String>)]) {
    for (key, value) in values {
        match value {
            Some(value) => println!("{key}={value}"),
            None => println!("{key}=<locked>"),
        }
    }
}

/// Print every local slot and what the backend says about it.
pub fn session_list(statuses: &[SlotStatus]) {
    if statuses.is_empty() {
        eprintln!("No sessions on this machine. `heyl session create` pairs one.");
        return;
    }

    println!("{:<16}  {:<24}  POLICY", "SLOT", "STATE");
    for status in statuses {
        let state = if !status.known {
            "gone".to_owned()
        } else if let Some(until) = status.unlocked_until {
            format!("unlocked until {until}")
        } else if status.unlock_requested {
            "locked, request pending".to_owned()
        } else {
            "locked".to_owned()
        };
        let policy = status.policy.map_or_else(|| "—".to_owned(), describe);
        println!("{:<16}  {state:<24}  {policy}", status.slot);
    }
}

fn describe(policy: SessionPolicy) -> String {
    let mut parts = vec![if policy.timeout_minutes.is_multiple_of(60) {
        format!("timeout {}h", policy.timeout_minutes / 60)
    } else {
        format!("timeout {}m", policy.timeout_minutes)
    }];
    if policy.strict {
        parts.push("strict".to_owned());
    }
    if policy.auto_extend {
        parts.push("auto-extend".to_owned());
    }
    parts.join(", ")
}
