//! What the commands print.
//!
//! Secrets go to stdout raw and everything else goes to stderr (DESIGN.md §5).
//! Nothing here emits a secret at all: sessions report identities and policies,
//! and `doctor` reports comparisons. No key, plaintext or ciphertext is printed
//! by any of it, in any format.
//!
//! # Two audiences, one place
//!
//! `--format human` is the prose below; `--format json` and `--format
//! json-pretty` are the same facts as documents on **stdout**. A document is
//! the machine's rendering of a report, so under either JSON format the prose
//! version is *not* also printed — saying it twice, on two streams, would make
//! a wrapper parse what it already has. Prompts and progress still reach
//! stderr, because they happen while stdout has nothing yet, and so do the
//! warnings the use cases raise: `tombstoned: false` says *what* happened, the
//! warning says why.
//!
//! `json` is one **compact document per line**, which is what lets a reader
//! consume `session create`'s pairing URL while the command is still waiting
//! for a swipe. `json-pretty` is the same documents, indented, for reading.
//!
//! None of these shapes is a compatibility promise yet — the read path fixes
//! the surface at M6 — but that is said in `--help` and the documentation
//! rather than carried in every payload as a field consumers must skip.

use std::io::Write as _;

use heyl_app::get::{Located, LoginView, Selection};
use heyl_app::session::{Created, Removed, Setting, SettingValue, Slot, SlotStatus};
use heyl_domain::SessionPolicy;
#[cfg(feature = "dev")]
use {
    heyl_app::doctor::{Outcome, Report},
    heyl_app::recovery::RecoveryOutcome,
};

/// How to render a report.
///
/// Global, because `--format` is a property of the invocation rather than of
/// one verb: a wrapper sets it once and every command it drives answers in
/// kind. The scenario suite leans on exactly that — its runner supplies the
/// flag itself, so a command that failed to render a document would fail to
/// parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Prose and tables, for a person.
    Human,
    /// One compact JSON document per line.
    Json,
    /// The same documents, indented.
    JsonPretty,
}

impl Format {
    /// Whether this format speaks in documents.
    const fn is_json(self) -> bool {
        matches!(self, Self::Json | Self::JsonPretty)
    }
}

/// Print one document, and get it out of the buffer.
///
/// The flush is the point of writing this by hand rather than with `println!`:
/// `session create` prints its pairing URL and then blocks on a person, so a
/// document still sitting in a line buffer would reach the reader after the
/// swipe it was meant to prompt.
fn emit(format: Format, document: &serde_json::Value) {
    match render(format, document) {
        Ok(text) => {
            let mut out = std::io::stdout();
            let _ = writeln!(out, "{text}");
            let _ = out.flush();
        }
        // Unreachable for the documents built here — every value is a string,
        // number, bool or null — and silence would be the wrong failure.
        Err(e) => eprintln!("heyl: could not render the output as JSON: {e}"),
    }
}

/// One document, as the format writes it.
///
/// Separate from printing it so both renderings can be asserted: a scenario
/// cannot tell them apart, because the harness compares parsed values, so what
/// distinguishes `json` from `json-pretty` is only ever visible here.
fn render(format: Format, document: &serde_json::Value) -> Result<String, serde_json::Error> {
    match format {
        Format::JsonPretty => serde_json::to_string_pretty(document),
        _ => serde_json::to_string(document),
    }
}

/// A policy, as the backend holds it.
///
/// Minutes rather than `8h`: the number is what the server enforces, and a
/// duration string would make a consumer parse a rendering back into the value
/// it started as.
fn policy_document(policy: SessionPolicy) -> serde_json::Value {
    serde_json::json!({
        "timeoutMinutes": policy.timeout_minutes,
        "strict": policy.strict,
        "autoExtend": policy.auto_extend,
    })
}

/// The key a setting has in a document.
///
/// The wildcard is not dead code: `Setting` is `non_exhaustive`, so a key
/// added in `heyl-app` reaches here before anyone writes it a spelling. It
/// falls back to the name the CLI already uses for it, which is a worse
/// document key than a chosen one and a better answer than a wrong one.
const fn setting_key(setting: Setting) -> &'static str {
    match setting {
        Setting::DisplayName => "displayName",
        // Named for what it carries, like the policy above.
        Setting::Timeout => "timeoutMinutes",
        Setting::Strict => "strict",
        Setting::AutoExtend => "autoExtend",
        other => other.name(),
    }
}

/// A setting's value. `null` is the document's spelling of `<locked>`, so the
/// shape does not change with lock state.
///
/// A value this layer has not learned yet renders as its human string rather
/// than as `null`, which already means "vault content, not fetched".
fn setting_value(value: SettingValue) -> serde_json::Value {
    match value {
        SettingValue::Minutes(minutes) => serde_json::json!(minutes),
        SettingValue::Flag(flag) => serde_json::json!(flag),
        SettingValue::Locked => serde_json::Value::Null,
        other => serde_json::json!(other.human()),
    }
}

/// The pairing URL, the moment it is known.
///
/// Printed *before* the long-poll, which is the whole reason `session create`
/// emits two documents: a wrapper can draw its own code or open the link while
/// the command waits. In human format the URL has already reached stderr,
/// under the QR, so there is nothing to add.
pub fn pairing_url(url: &str, format: Format) {
    if format.is_json() {
        emit(format, &serde_json::json!({ "pairingUrl": url }));
    }
}

/// Report a session that was just paired.
pub fn session_created(slot: &Slot, created: &Created, policy: SessionPolicy, format: Format) {
    if format.is_json() {
        return emit(
            format,
            &serde_json::json!({
                "slot": slot.name(),
                "sessionId": created.session_id.to_string(),
                "display": created.display,
                "policy": policy_document(policy),
                "unlockedUntil": created.unlocked_until.map(|t| t.to_string()),
            }),
        );
    }

    for line in created_lines(slot, created, policy) {
        eprintln!("{line}");
    }
}

fn created_lines(slot: &Slot, created: &Created, policy: SessionPolicy) -> Vec<String> {
    vec![
        format!(
            "Paired {} as {:?} — the name your phone will show.",
            slot.name(),
            created.display
        ),
        format!("Session {}.", created.session_id),
        format!("Policy: {}.", describe(policy)),
        match created.unlocked_until {
            Some(until) => format!("Unlocked until {until}."),
            // The normal case, and worth saying plainly: pairing establishes
            // an identity, approving an unlock is a separate act.
            None => "Locked. The first command that needs a secret will ask your phone.".to_owned(),
        },
    ]
}

/// Report an approved unlock.
pub fn session_unlocked(slot: &Slot, until: heyl_domain::Timestamp, format: Format) {
    if format.is_json() {
        return emit(
            format,
            &serde_json::json!({
                "slot": slot.name(),
                "unlockedUntil": until.to_string(),
            }),
        );
    }
    eprintln!("{} is unlocked until {until}.", slot.name());
}

/// Report a dropped unlock.
pub fn session_locked(slot: &Slot, format: Format) {
    if format.is_json() {
        return emit(
            format,
            &serde_json::json!({ "slot": slot.name(), "locked": true }),
        );
    }
    eprintln!("heyl: {} is locked", slot.name());
}

/// Report a setting that was written.
///
/// The value is echoed as it was given: it is what the caller passed and what
/// `session get` will parse back, and the command has nothing else to report.
pub fn session_set(slot: &Slot, setting: Setting, value: &str, format: Format) {
    if format.is_json() {
        return emit(
            format,
            &serde_json::json!({
                "slot": slot.name(),
                "key": setting.name(),
                "value": value,
            }),
        );
    }
    eprintln!("heyl: {}.{setting} = {value}", slot.name());
}

/// Print settings.
///
/// The vault-side name reads `<locked>` — `null` in a document — rather than
/// being fetched: reading settings must never reach the phone.
pub fn session_settings(slot: &Slot, values: &[(Setting, SettingValue)], format: Format) {
    if format.is_json() {
        let settings: serde_json::Map<String, serde_json::Value> = values
            .iter()
            .map(|(key, value)| (setting_key(*key).to_owned(), setting_value(*value)))
            .collect();
        return emit(
            format,
            &serde_json::json!({ "slot": slot.name(), "settings": settings }),
        );
    }

    for (key, value) in values {
        println!("{key}={}", value.human());
    }
}

/// Report what a removal managed to do.
///
/// Says what it could *not* do as well: a device left listed in the app is the
/// kind of drift a user should hear about immediately, not discover later. In
/// a document that is two booleans; the *reason* each is false has already
/// reached stderr as a warning from the use case, in either format.
pub fn session_removed(slot: &Slot, removed: &Removed, format: Format) {
    if format.is_json() {
        return emit(
            format,
            &serde_json::json!({
                "slot": slot.name(),
                "tombstoned": removed.tombstoned,
                "deleted": removed.deleted,
            }),
        );
    }

    eprintln!("{}", removed_line(slot, removed));
}

fn removed_line(slot: &Slot, removed: &Removed) -> String {
    match (removed.tombstoned, removed.deleted) {
        (true, true) => format!("Removed {}.", slot.name()),
        (false, true) => format!(
            "Deleted {} and forgot its keys, but could not tombstone its device entry — \
             it will keep appearing in the heylogin app until you remove it there.",
            slot.name()
        ),
        (true, false) => format!(
            "Tombstoned {} and forgot its keys, but the backend session is still there.",
            slot.name()
        ),
        (false, false) => format!(
            "Forgot {}'s keys locally; nothing else could be cleaned up.",
            slot.name()
        ),
    }
}

/// Print every local slot and what the backend says about it.
///
/// The document is a bare array, like the read path's own listing, so both are
/// read the same way — `jq -r '.[].slot'`. An empty one prints `[]`, which is
/// an answer; the human rendering says so in words instead.
pub fn session_list(statuses: &[SlotStatus], format: Format) {
    if format.is_json() {
        let sessions: Vec<serde_json::Value> = statuses
            .iter()
            .map(|status| {
                serde_json::json!({
                    "slot": status.slot,
                    "known": status.known,
                    "unlockedUntil": status.unlocked_until.map(|t| t.to_string()),
                    "unlockRequested": status.unlock_requested,
                    "policy": status.policy.map(policy_document),
                })
            })
            .collect();
        return emit(format, &serde_json::Value::Array(sessions));
    }

    if statuses.is_empty() {
        eprintln!("No sessions on this machine. `heyl session create` pairs one.");
        return;
    }

    for line in table(statuses) {
        println!("{line}");
    }
}

/// The human listing: a header, then one line per slot.
fn table(statuses: &[SlotStatus]) -> Vec<String> {
    let mut lines = vec![format!("{:<16}  {:<24}  POLICY", "SLOT", "STATE")];
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
        lines.push(format!("{:<16}  {state:<24}  {policy}", status.slot));
    }
    lines
}

/// Report a completed recovery.
///
/// Says what was lost as well as what was gained: the user has a session, and
/// no longer has whatever the recovery disconnected.
#[cfg(feature = "dev")]
pub fn recovery(outcome: &RecoveryOutcome, format: Format) {
    if format.is_json() {
        return recovery_json(outcome, format);
    }
    recovery_human(outcome);
}

/// `recovery`, as a machine reads it.
///
/// Every value here comes from the backend — the account, the session, the
/// window heylogin actually granted, the authenticators it listed as about to
/// go. Nothing is derived from the local clock, which is what lets a scenario
/// assert this document verbatim without normalising anything out of it.
#[cfg(feature = "dev")]
fn recovery_json(outcome: &RecoveryOutcome, format: Format) {
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

    emit(
        format,
        &serde_json::json!({
            "userId": outcome.user_id,
            "sessionId": outcome.session_id.to_string(),
            "unlockedUntil": outcome.unlocked_until.map(|t| t.to_string()),
            "disconnected": disconnected,
        }),
    );
}

#[cfg(feature = "dev")]
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
#[cfg(feature = "dev")]
pub fn doctor(report: &Report, format: Format) {
    if format.is_json() {
        return json(report, format);
    }
    human(report);
}

#[cfg(feature = "dev")]
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

#[cfg(feature = "dev")]
fn json(report: &Report, format: Format) {
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
    emit(
        format,
        &serde_json::json!({
            "checks": checks,
            "summary": { "passed": pass, "failed": fail, "skipped": skip },
        }),
    );
}

/// What `heyl get` found.
///
/// The one command that prints a **secret** to stdout, so the rules are
/// DESIGN.md §5's to the letter: with `-f`, the raw value with a trailing
/// newline only on a TTY, so `$(…)` is byte-exact; without, `name: value` lines
/// that always end in a newline. Under `--format json`, a `-f` value is a bare
/// JSON string and a whole login is a wire-shaped object with its secrets
/// decrypted in place. An ambiguity note goes to stderr, where it does not
/// disturb either stdout rendering.
pub fn get(located: &Located, format: Format) {
    if located.match_count > 1 {
        eprintln!(
            "heyl: {} logins match; using the most recently changed. \
             Pass --login-id to pick one exactly.",
            located.match_count
        );
    }
    match &located.selection {
        Selection::Value(value) => get_value(value, format),
        Selection::Login(view) => get_login(view, format),
    }
}

/// A single field value.
fn get_value(value: &str, format: Format) {
    if format.is_json() {
        emit(format, &serde_json::Value::String(value.to_owned()));
        return;
    }
    // Raw, with a trailing newline only when stdout is a terminal — an exact
    // capture in `$(…)`, a readable line at a prompt (DESIGN.md §5).
    let mut out = std::io::stdout();
    let _ = write!(out, "{value}");
    if std::io::IsTerminal::is_terminal(&out) {
        let _ = writeln!(out);
    }
    let _ = out.flush();
}

/// A whole login.
fn get_login(view: &LoginView, format: Format) {
    if format.is_json() {
        emit(format, &login_document(view));
        return;
    }
    let mut out = std::io::stdout();
    for line in login_lines(view) {
        let _ = writeln!(out, "{line}");
    }
    let _ = out.flush();
}

/// The human `name: value` lines, in the fixed field order, non-empty only.
fn login_lines(view: &LoginView) -> Vec<String> {
    let mut lines = Vec::new();
    let mut push = |key: &str, value: &str| lines.push(field_line(key, value));

    push("id", &view.id);
    if let Some(name) = &view.name {
        push("name", name);
    }
    if let Some(title) = &view.title {
        push("title", title);
    }
    if let Some(username) = &view.username {
        push("username", username);
    }
    if let Some(password) = &view.password {
        push("password", password);
    }
    if !view.websites.is_empty() {
        push("website", &view.websites.join(", "));
    }
    if let Some(note) = &view.note {
        push("note", note);
    }
    if !view.labels.is_empty() {
        push("labels", &view.labels.join(", "));
    }
    for (name, value) in &view.custom {
        push(name, value);
    }
    if let Some(created) = &view.created {
        push("created", created);
    }
    if let Some(edited) = &view.edited {
        push("edited", edited);
    }
    if view.is_deleted {
        push("deleted", "true");
    }
    if view.is_archived {
        push("archived", "true");
    }
    lines
}

/// `key: value`, with a multi-line value's continuation lines indented under
/// the value column so one field still reads as one block (DESIGN.md §5).
fn field_line(key: &str, value: &str) -> String {
    if value.contains('\n') {
        let indent = " ".repeat(key.len() + 2);
        format!("{key}: {}", value.replace('\n', &format!("\n{indent}")))
    } else {
        format!("{key}: {value}")
    }
}

/// The JSON document: the wire object's key names, secrets decrypted in place,
/// only the fields the login actually has (DESIGN.md §5).
fn login_document(view: &LoginView) -> serde_json::Value {
    let mut doc = serde_json::Map::new();
    doc.insert("id".to_owned(), view.id.clone().into());
    if let Some(name) = &view.name {
        doc.insert("displayHeadline".to_owned(), name.clone().into());
    }
    if let Some(title) = &view.title {
        doc.insert("title".to_owned(), title.clone().into());
    }
    if let Some(username) = &view.username {
        doc.insert("username".to_owned(), username.clone().into());
    }
    if let Some(password) = &view.password {
        doc.insert("password".to_owned(), password.clone().into());
    }
    if !view.websites.is_empty() {
        doc.insert("websites".to_owned(), view.websites.clone().into());
    }
    if let Some(note) = &view.note {
        doc.insert("note".to_owned(), note.clone().into());
    }
    if !view.labels.is_empty() {
        doc.insert("tags".to_owned(), view.labels.clone().into());
    }
    if !view.custom.is_empty() {
        let fields: Vec<serde_json::Value> = view
            .custom
            .iter()
            .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
            .collect();
        doc.insert("customFields".to_owned(), fields.into());
    }
    if let Some(created) = &view.created {
        doc.insert("creationTime".to_owned(), created.clone().into());
    }
    if let Some(edited) = &view.edited {
        doc.insert("editTime".to_owned(), edited.clone().into());
    }
    if let Some(change_time) = &view.change_time {
        doc.insert("changeTime".to_owned(), change_time.clone().into());
    }
    if view.is_deleted {
        doc.insert("isDeleted".to_owned(), true.into());
    }
    if view.is_archived {
        doc.insert("isArchived".to_owned(), true.into());
    }
    serde_json::Value::Object(doc)
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

#[cfg(test)]
mod tests {
    use heyl_app::session::Slot;

    use super::*;

    fn policy() -> SessionPolicy {
        SessionPolicy {
            timeout_minutes: 480,
            strict: true,
            auto_extend: false,
        }
    }

    /// What the scenario suite structurally cannot see.
    ///
    /// The harness compares *parsed* documents, so `json` and `json-pretty`
    /// reach it identically. The difference between them is a property of the
    /// bytes, and this is the only place it can be asserted.
    #[test]
    fn json_is_one_line_and_json_pretty_is_not() {
        let document = serde_json::json!({ "slot": "ci", "policy": policy_document(policy()) });

        let compact = render(Format::Json, &document).expect("renders");
        assert!(!compact.contains('\n'), "one document, one line: {compact}");

        let pretty = render(Format::JsonPretty, &document).expect("renders");
        assert!(pretty.contains("\n  "), "indented: {pretty}");

        // Same facts either way, which is why a scenario cannot tell them
        // apart and this test exists.
        let (a, b): (serde_json::Value, serde_json::Value) = (
            serde_json::from_str(&compact).expect("valid"),
            serde_json::from_str(&pretty).expect("valid"),
        );
        assert_eq!(a, b);
    }

    /// Minutes, not `8h`: the number is what the backend enforces.
    #[test]
    fn a_policy_document_carries_wire_values() {
        assert_eq!(
            policy_document(policy()),
            serde_json::json!({
                "timeoutMinutes": 480,
                "strict": true,
                "autoExtend": false,
            })
        );
    }

    /// `null` is the document's `<locked>`, so the shape never changes with
    /// lock state — a consumer reads `settings.displayName` either way.
    #[test]
    fn a_locked_setting_is_null_rather_than_absent() {
        assert_eq!(setting_value(SettingValue::Locked), serde_json::Value::Null);
        assert_eq!(setting_key(Setting::DisplayName), "displayName");
        assert_eq!(setting_key(Setting::Timeout), "timeoutMinutes");
        assert_eq!(setting_value(SettingValue::Minutes(480)), 480);
        assert_eq!(setting_value(SettingValue::Flag(false)), false);
    }

    /// The human rendering says the same things in prose. It is not a
    /// scenario's business — every step there runs `--format json` — so it is
    /// pinned here.
    #[test]
    fn the_human_rendering_names_the_slot_the_session_and_the_policy() {
        let created = Created {
            session_id: heyl_domain::SessionId::parse("0192a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b")
                .expect("a uuid"),
            display: "CI runner".to_owned(),
            unlocked_until: None,
        };
        let lines = created_lines(&Slot::new(Some("ci")), &created, policy());

        assert!(lines[0].contains("ci") && lines[0].contains("CI runner"));
        assert!(lines[1].contains("0192a1b2"));
        assert_eq!(lines[2], "Policy: timeout 8h, strict.");
        assert!(
            lines[3].starts_with("Locked."),
            "pairing establishes an identity; the unlock is a separate act"
        );
    }

    /// A removal that could not do everything says so, in both renderings: the
    /// document has the booleans, the prose has the consequence.
    #[test]
    fn a_degraded_removal_is_reported_rather_than_rounded_up() {
        let removed = Removed {
            tombstoned: false,
            deleted: true,
        };
        let line = removed_line(&Slot::new(Some("ci")), &removed);
        assert!(line.contains("could not tombstone"));
        assert!(
            line.contains("heylogin app"),
            "a device left listed is the drift a user has to hear about"
        );
    }

    #[test]
    fn the_table_has_a_row_per_slot_and_says_what_the_backend_forgot() {
        let statuses = vec![
            SlotStatus {
                slot: "ci".to_owned(),
                known: true,
                unlocked_until: None,
                unlock_requested: true,
                policy: Some(policy()),
            },
            SlotStatus {
                slot: "stale".to_owned(),
                known: false,
                unlocked_until: None,
                unlock_requested: false,
                policy: None,
            },
        ];
        let lines = table(&statuses);
        assert_eq!(lines.len(), 3, "a header and a row each");
        assert!(lines[1].contains("locked, request pending"));
        assert!(lines[2].contains("gone"));
    }
}
