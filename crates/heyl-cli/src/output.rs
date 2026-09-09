//! What the commands print.
//!
//! Secrets go to stdout raw and everything else goes to stderr (DESIGN.md §5).
//! Neither command here emits a secret at all: `login` reports a session, and
//! `doctor` reports comparisons. No key, plaintext or ciphertext is printed by
//! either, in either format.

use heyl_app::doctor::{Outcome, Report};
use heyl_app::login::LoginOutcome;

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

/// Report a successful login.
pub fn login(outcome: &LoginOutcome) {
    eprintln!("Logged in as {}.", outcome.user_id);
    eprintln!("Session {} is registered.", outcome.session_id);
    match outcome.unlocked_until {
        Some(until) => eprintln!("Unlocked until {until} (the backend's value, not ours)."),
        None => eprintln!(
            "The backend reported no unlock window; `heyl doctor` will say whether the grant took."
        ),
    }
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
