//! What the scenario suite cannot reach.
//!
//! Everything this file used to hold is now a scenario: a mistyped code is a
//! step with different stdin, a backend refusal is a step expecting a non-zero
//! exit, and the whole `recovery` → `doctor` walk is
//! `tests/scenarios/recovery-then-doctor.json`, run against the real binary
//! over a real socket.
//!
//! Two things stayed, for reasons that are about the boundary rather than the
//! coverage. A scenario's steps are processes with piped stdin, so
//! `Terminal::is_interactive` is false in all of them and the **confirmation
//! prompt** — the guard that stops a recovery destroying an account when
//! someone answers `n` — is unreachable from out there. And the corpus's one
//! honest limitation is worth stating where a reader of the suite will find it.

mod support;

use std::path::PathBuf;

use heyl_app::{AppError, Ports, recovery::Confirmation};
use heyl_grpc::{ClientContext, DomainApi, RecordedApi, Scenario};
use support::{CorpusRandom, FixedClock, MemoryStore, ScriptedTerminal};

fn scenario_path() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/scenarios/recovery-then-doctor.json"
    ))
}

#[tokio::test]
async fn a_declined_prompt_does_not_reach_create_tokens() {
    let scenario = Scenario::load(&scenario_path()).expect("the scenario loads");
    let seed = scenario.session_seed().expect("a 32-byte seed");
    let recovery = &scenario.steps[0];

    let api = DomainApi::new(
        RecordedApi::new(recovery.calls.clone()),
        ClientContext::default(),
    );
    let store = MemoryStore::default();
    let terminal = ScriptedTerminal::with(&["n"]);
    let clock = FixedClock {
        now: heyl_domain::Timestamp::from_millisecond(1_757_376_000_000).expect("valid"),
        deadline: heyl_domain::Timestamp::from_millisecond(1_757_469_600_000).expect("valid"),
    };
    let random = CorpusRandom::new(seed);

    let err = heyl_app::recovery::run(
        &Ports {
            api: &api,
            store: &store,
            terminal: &terminal,
            clock: &clock,
            random: &random,
        },
        "fixture@example.com",
        Confirmation::Ask("Disconnect and recover? [y/N] "),
        heyl_app::recovery::CodeSource::Given(zeroize::Zeroizing::new(scenario.meta.code.clone())),
        heyl_domain::ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect_err("the user said no");

    assert!(matches!(err, AppError::NotConfirmed));
    // The record is still there, unused — which is the assertion: nothing was
    // submitted, so nothing was destroyed.
    assert!(
        api.inner()
            .unused()
            .contains(&"/domain.CredentialService/CreateTokens")
    );
}

/// The corpus proves the plumbing. It cannot prove the **context salts**.
///
/// Every ciphertext in it was re-encrypted by `rekey` under our own derivation,
/// so a mistyped context would yield stable, self-consistent, wrong keys and
/// the whole suite would stay green. Any artifact that *could* prove it offline
/// would, by construction, be openable with a committed key.
///
/// The confirmation is `heyl doctor` against a real account, comparing each
/// derived public key against the one heylogin publishes. That is live-only,
/// and it is why M2 was sized the way it was (DESIGN.md §6).
#[test]
fn the_corpus_cannot_confirm_the_context_salts() {
    // Deliberately trivial: this exists so the limitation is stated where
    // someone reading the suite will find it, not only in a design document.
    assert!(scenario_path().exists());
}
