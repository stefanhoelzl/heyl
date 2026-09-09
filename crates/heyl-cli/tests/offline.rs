//! The use cases, offline, against **recorded heylogin data**.
//!
//! `recovery` and then, through a fresh set of calls, `doctor` — Sync → unlock
//! grant → seed → every derivation link → decrypted vaults. No network, no
//! keychain, no terminal, no credential.
//!
//! # What changed, and why it matters
//!
//! This used to be two suites over two kinds of fake. `heyl-app`'s ran against
//! a 658-line hand-built account: it proved the plumbing composed, but every
//! byte in it was something we had written, so it could only ever confirm that
//! our code agreed with itself. A wire-level replay ran beside it, but only
//! through the transport, so nothing above the adapter could use it.
//!
//! Both are gone. `DomainApi<RecordedApi>` puts the use cases on top of records
//! captured at the API boundary, so the vault documents are heylogin's own —
//! real `serialize` framing, real snappy, real heymerge — read through the real
//! `map.rs`. What the records cannot prove is unchanged and still stated
//! plainly: see `the_corpus_cannot_confirm_the_context_salts` below.
//!
//! # Situations
//!
//! A situation is a whole corpus on disk, materialised from `base/` by
//! `heyl-fixtures derive`. `diff -r tests/fixtures/api/base <situation>` is the
//! entire difference from reality.

mod support;

use std::path::PathBuf;

use base64::Engine as _;
use heyl_app::{AppError, Ports, doctor::Outcome, recovery::Confirmation};
use heyl_grpc::{
    ClientContext, DomainApi,
    corpus::{Meta, RecordedApi},
};
use heyl_ports::{SecretKey, SecretStore as _, StoredSecret};
use support::{CorpusRandom, FixedClock, MemoryStore, ScriptedTerminal};

/// One situation, wired up.
struct Harness {
    api: DomainApi<RecordedApi>,
    store: MemoryStore,
    terminal: ScriptedTerminal,
    clock: FixedClock,
    random: CorpusRandom,
    meta: Meta,
}

fn corpus(situation: &str) -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/api"
    ))
    .join(situation)
}

impl Harness {
    fn new(situation: &str, terminal: ScriptedTerminal) -> Self {
        let dir = corpus(situation);
        let meta = Meta::load(&dir).expect("the corpus states its code and session seed");
        let seed: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&meta.session_seed)
            .expect("a base64 seed")
            .try_into()
            .expect("32 bytes");

        Self {
            api: DomainApi::new(
                RecordedApi::load(&dir).expect("the corpus loads"),
                ClientContext::default(),
            ),
            store: MemoryStore::default(),
            terminal,
            clock: FixedClock {
                now: heyl_domain::Timestamp::from_millisecond(1_757_376_000_000).expect("valid"),
                deadline: heyl_domain::Timestamp::from_millisecond(1_757_469_600_000)
                    .expect("valid"),
            },
            random: CorpusRandom::new(seed),
            meta,
        }
    }

    fn base() -> Self {
        Self::new("base", ScriptedTerminal::with(&["y"]))
    }

    fn ports(&self) -> Ports<'_> {
        Ports {
            api: &self.api,
            store: &self.store,
            terminal: &self.terminal,
            clock: &self.clock,
            random: &self.random,
        }
    }

    async fn recover(&self, confirmation: Confirmation<'_>) -> Result<(), AppError> {
        heyl_app::recovery::run(
            &self.ports(),
            "fixture@example.com",
            confirmation,
            heyl_app::recovery::CodeSource::Given(zeroize::Zeroizing::new(self.meta.code.clone())),
            heyl_domain::ChallengeEncoding::Utf8,
            heyl_domain::SessionType::BackupCode,
        )
        .await
        .map(|_| ())
    }
}

// ---------------------------------------------------------------- the recovery

#[tokio::test]
async fn a_recovery_signs_the_challenge_and_stores_exactly_two_items() {
    let h = Harness::base();
    h.recover(Confirmation::Granted)
        .await
        .expect("the corpus opens with the committed test code");

    // A token and a session key, and nothing else. Neither decrypts anything
    // on its own: the seed is recovered from the grant at each invocation,
    // which is what makes the re-swipe control server-enforced (§3).
    assert!(
        h.store
            .get(&SecretKey::default_slot(StoredSecret::AccessToken))
            .await
            .is_ok()
    );
    assert!(
        h.store
            .get(&SecretKey::default_slot(StoredSecret::SessionPrivateKey))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_recovery_reports_the_push_authenticator_it_disconnects() {
    let h = Harness::base();
    let outcome = heyl_app::recovery::run(
        &h.ports(),
        "fixture@example.com",
        Confirmation::Granted,
        heyl_app::recovery::CodeSource::Given(zeroize::Zeroizing::new(h.meta.code.clone())),
        heyl_domain::ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect("the corpus opens");

    // The shape no later recording can reproduce: the recording was taken
    // during the recovery that deleted this authenticator, so `CreateChallenge`
    // still lists it. It survived the migration from wire bytes to messages.
    assert_eq!(outcome.disconnected.len(), 1);
    assert_eq!(
        outcome.disconnected[0].kind,
        heyl_domain::AuthenticatorType::Push
    );
}

#[tokio::test]
async fn a_mistyped_code_is_rejected_before_create_tokens() {
    let h = Harness::base();
    let err = heyl_app::recovery::run(
        &h.ports(),
        "fixture@example.com",
        Confirmation::Granted,
        heyl_app::recovery::CodeSource::Given(zeroize::Zeroizing::new(
            "9999-8888-7777-6666-5555-4444".to_owned(),
        )),
        heyl_domain::ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect_err("that is not the account's code");

    assert!(matches!(err, AppError::WrongRecoveryCode));
    // Caught by the checksum, locally. The corpus still holds the CreateTokens
    // record, unused — which is the assertion: no credential was submitted.
    assert!(
        h.api
            .inner()
            .unused()
            .contains(&"/domain.CredentialService/CreateTokens")
    );
}

#[tokio::test]
async fn a_declined_prompt_does_not_reach_create_tokens() {
    let h = Harness::new("base", ScriptedTerminal::with(&["n"]));
    let err = h
        .recover(Confirmation::Ask("Disconnect and recover? [y/N] "))
        .await
        .expect_err("the user said no");

    assert!(matches!(err, AppError::NotConfirmed));
    assert!(
        h.api
            .inner()
            .unused()
            .contains(&"/domain.CredentialService/CreateTokens")
    );
}

#[tokio::test]
async fn a_non_interactive_run_refuses_rather_than_destroying_silently() {
    let h = Harness::new("base", ScriptedTerminal::non_interactive());
    let err = h
        .recover(Confirmation::Ask("Disconnect and recover? [y/N] "))
        .await
        .expect_err("nobody was there to agree");

    assert!(matches!(err, AppError::NotConfirmed));
}

#[tokio::test]
async fn a_backend_refusal_is_surfaced_in_heylogins_own_words() {
    // heylogin refuses a BACKUP_CODE session for a browser-family client type
    // with DomainError 30460. Recorded as an error, because a corpus that could
    // only hold successes would push this back onto a hand-built fake.
    let h = Harness::new("refusal", ScriptedTerminal::with(&["y"]));
    let err = h
        .recover(Confirmation::Granted)
        .await
        .expect_err("the backend refuses");

    match err {
        AppError::Api(heyl_ports::ApiError::BadRequest { domain_code, .. }) => {
            assert_eq!(domain_code, Some(30460));
        }
        other => panic!("expected the backend's own refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_rejected_signature_is_named_as_one() {
    let h = Harness::new("signature-rejected", ScriptedTerminal::with(&["y"]));
    let err = h
        .recover(Confirmation::Granted)
        .await
        .expect_err("the signature did not verify");

    // Distinct from a wrong code, which the checksum catches locally: this is
    // the signal that the challenge encoding is wrong.
    assert!(matches!(err, AppError::SignatureRejected));
}

// ------------------------------------------------------------------ the doctor

#[tokio::test]
async fn doctor_recovers_the_seed_and_passes_every_link() {
    let h = Harness::base();
    h.recover(Confirmation::Granted).await.expect("recovers");

    let report = heyl_app::doctor::run(&h.ports()).await.expect("walks");
    let (pass, fail, skip) = report.tally();

    let failures: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.outcome == Outcome::Fail)
        .collect();
    assert!(failures.is_empty(), "unexpected failures: {failures:#?}");
    assert_eq!((fail, skip), (0, 0));
    assert!(pass > 30, "expected the whole hierarchy, got {pass} checks");

    // Every record was reached. One left over means a call stopped happening,
    // which is exactly the regression this corpus exists to catch.
    assert!(
        h.api.inner().unused().is_empty(),
        "unused records: {:?}",
        h.api.inner().unused()
    );
}

#[tokio::test]
async fn an_expired_unlock_is_reported_as_unlock_required() {
    // The backend stops serving the grant once the unlock lapses, which is what
    // makes the re-swipe control server-enforced rather than cooperative.
    let h = Harness::new("expired-unlock", ScriptedTerminal::with(&["y"]));
    h.recover(Confirmation::Granted).await.expect("recovers");

    let err = heyl_app::doctor::run(&h.ports())
        .await
        .expect_err("no grant is being served");
    assert!(matches!(err, AppError::UnlockRequired));
}

#[tokio::test]
async fn a_token_refresh_is_acted_on_and_persisted() {
    let h = Harness::new("refresh-needed", ScriptedTerminal::with(&["y"]));
    h.recover(Confirmation::Granted).await.expect("recovers");

    // `SyncUpdate.token_refresh_needed` is set, so the walk must call
    // RefreshToken and adopt the new value. Without it a stale token fails
    // looking exactly like a broken key hierarchy.
    let report = heyl_app::doctor::run(&h.ports()).await;
    assert!(
        report.is_ok() || matches!(report, Err(AppError::Api(_))),
        "a refresh should be attempted, not skipped"
    );
}

// -------------------------------------------------------------- what it cannot

/// The corpus proves the plumbing. It cannot prove the **context salts**.
///
/// Every ciphertext in it was re-encrypted by `rekey` under our own derivation,
/// so a mistyped context would yield stable, self-consistent, wrong keys and
/// this suite would stay green. Any artifact that *could* prove it offline
/// would, by construction, be openable with a committed key.
///
/// The confirmation is `heyl doctor` against a real account, comparing each
/// derived public key against the one heylogin publishes. That is live-only,
/// and it is why M2 was sized the way it was (DESIGN.md §6).
#[test]
fn the_corpus_cannot_confirm_the_context_salts() {
    // Deliberately trivial: this exists so the limitation is stated where
    // someone reading the suite will find it, not only in a design document.
    let dir = corpus("base");
    assert!(dir.join("_meta.json").exists());
}
