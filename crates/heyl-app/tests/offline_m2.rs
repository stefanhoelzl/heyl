//! The whole M2 use case, offline.
//!
//! `login recovery` then, in a *separate* pass with only the two stored items,
//! `doctor` — Sync → unlock grant → seed → every link → decrypted commit. No
//! network, no keychain, no terminal, no credential.
//!
//! This is the layer that keeps M2 honest afterwards. What it cannot do is
//! confirm the context salts against heylogin: see `fakes::account`.

mod fakes;

use fakes::account::{Account, TEST_CODE};
use fakes::{CountingRandom, FakeBackend, FixedClock, MemoryStore, ScriptedTerminal};
use heyl_app::{
    AppError, Ports,
    doctor::Outcome,
    recovery::{CodeSource, Confirmation},
};
use heyl_domain::{ChallengeEncoding, Timestamp};
use heyl_ports::{SecretKey, SecretStore as _, StoredSecret};
use zeroize::Zeroizing;

/// Valid base64 *and* valid UTF-8, so every encoding candidate produces bytes
/// — which is what makes the "wrong encoding" test measure a rejected
/// signature rather than a decode failure.
const CHALLENGE: &str = "YS1jaGFsbGVuZ2UtZnJvbS10aGUtYmFja2VuZA==";

struct Harness {
    account: Account,
    api: FakeBackend,
    store: MemoryStore,
    terminal: ScriptedTerminal,
    clock: FixedClock,
    random: CountingRandom,
}

impl Harness {
    fn new(answers: &[&str]) -> Self {
        let account = Account::new();
        let api = FakeBackend::new(
            account.challenge(CHALLENGE),
            account.tokens(),
            account.sync(true),
            account.authenticators(),
            account.commits(),
            account.login_verifier(),
        );
        Self {
            account,
            api,
            store: MemoryStore::default(),
            terminal: ScriptedTerminal::with(answers),
            clock: FixedClock {
                now: Timestamp::from_millisecond(1_757_376_000_000).expect("valid"),
                deadline: Timestamp::from_millisecond(1_757_469_600_000).expect("valid"),
            },
            random: CountingRandom::default(),
        }
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

    /// Put the account's real session key in the store, as a login that
    /// self-granted the fixture's unlock would have.
    fn seed_session(&self) {
        self.store.put(
            &SecretKey::default_slot(StoredSecret::AccessToken),
            "test-access-token",
        );
        self.store.put(
            &SecretKey::default_slot(StoredSecret::SessionPrivateKey),
            &heyl_app::recovery::encode_key(&self.account.session_key),
        );
    }
}

#[tokio::test]
async fn login_signs_the_challenge_and_stores_exactly_two_items() {
    let h = Harness::new(&[]);
    let outcome = heyl_app::recovery::run(
        &h.ports(),
        "someone@example.com",
        Confirmation::Granted,
        CodeSource::Given(Zeroizing::new(TEST_CODE.to_owned())),
        ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect("login succeeds");

    assert_eq!(outcome.user_id, "test-user");
    assert_eq!(h.api.calls(), ["create_challenge", "create_tokens"]);

    // The keychain holds a token and a session key. Nothing else, and above all
    // not the seed (DESIGN.md §3).
    for secret in StoredSecret::ALL {
        h.store
            .get(&SecretKey::default_slot(secret))
            .await
            .unwrap_or_else(|_| panic!("{} was stored", secret.name()));
    }

    // The effective expiry is the backend's, not the one we asked for.
    assert_eq!(
        outcome.unlocked_until,
        Some(Timestamp::from_millisecond(1_757_462_400_000).expect("valid")),
        "login must report the backend's unlock window, not the clock's request"
    );
}

/// The code is read through the Terminal port when it is not already in hand,
/// and it is never echoed back anywhere.
#[tokio::test]
async fn the_recovery_code_can_come_from_the_terminal() {
    let h = Harness::new(&[TEST_CODE]);
    heyl_app::recovery::run(
        &h.ports(),
        "someone@example.com",
        Confirmation::Granted,
        CodeSource::Ask("recovery code: "),
        ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect("login succeeds");
}

/// The checksum catches a mistyped code locally — before `CreateTokens`, which
/// is as early as it can be caught, since the checksum arrives with
/// `CreateChallenge`.
#[tokio::test]
async fn a_mistyped_code_is_rejected_before_create_tokens() {
    let h = Harness::new(&[]);
    let err = heyl_app::recovery::run(
        &h.ports(),
        "someone@example.com",
        Confirmation::Granted,
        CodeSource::Given(Zeroizing::new("1111-2222-3333-4444-5555-9999".to_owned())),
        ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect_err("rejected");

    assert!(matches!(err, AppError::WrongRecoveryCode), "{err:?}");
    assert_eq!(
        h.api.calls(),
        ["create_challenge"],
        "CreateTokens must not be reached with a code we already know is wrong"
    );
}

/// The signing input is pinned: the fake verifies the signature the way the
/// backend does, so signing the wrong bytes fails here rather than only in
/// production. This is the failure mode decision 9's probe exists to resolve —
/// a valid signature over the wrong message, with no diagnostic pointing at
/// the cause.
#[tokio::test]
async fn signing_the_wrong_bytes_is_rejected() {
    let h = Harness::new(&[]);
    let err = heyl_app::recovery::run(
        &h.ports(),
        "someone@example.com",
        Confirmation::Granted,
        CodeSource::Given(Zeroizing::new(TEST_CODE.to_owned())),
        // The fake expects Utf8. Base64 decodes the same challenge into
        // entirely different bytes, and signs those.
        ChallengeEncoding::Base64,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect_err("rejected");

    assert!(matches!(err, AppError::SignatureRejected), "{err:?}");
}

/// A candidate that cannot even decode the challenge is ruled out with no
/// network call at all — which is evidence for the probe, not a failure.
#[tokio::test]
async fn an_undecodable_challenge_rules_a_candidate_out_before_the_network() {
    let account = Account::new();
    let api = FakeBackend::new(
        // Not base64: contains `-` and the wrong length.
        account.challenge("a-challenge-from-the-backend"),
        account.tokens(),
        account.sync(true),
        account.authenticators(),
        account.commits(),
        account.login_verifier(),
    );
    let store = MemoryStore::default();
    let terminal = ScriptedTerminal::with(&[]);
    let clock = FixedClock {
        now: Timestamp::from_millisecond(1_757_376_000_000).expect("valid"),
        deadline: Timestamp::from_millisecond(1_757_469_600_000).expect("valid"),
    };
    let random = CountingRandom::default();
    let ports = Ports {
        api: &api,
        store: &store,
        terminal: &terminal,
        clock: &clock,
        random: &random,
    };

    let err = heyl_app::recovery::run(
        &ports,
        "someone@example.com",
        Confirmation::Granted,
        CodeSource::Given(Zeroizing::new(TEST_CODE.to_owned())),
        ChallengeEncoding::Base64,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect_err("ruled out");

    assert!(
        matches!(
            err,
            AppError::Domain(heyl_domain::DomainError::MalformedChallenge { .. })
        ),
        "{err:?}"
    );
    assert_eq!(
        api.calls(),
        ["create_challenge"],
        "a candidate that cannot decode must not reach CreateTokens"
    );
}

/// The point of decision 2: a *separate* invocation, holding only the two
/// stored items, recovers the seed and walks the whole chain.
#[tokio::test]
async fn doctor_recovers_the_seed_and_passes_every_link() {
    let h = Harness::new(&[]);
    h.seed_session();

    let report = heyl_app::doctor::run(&h.ports()).await.expect("walks");

    let failures: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.outcome == Outcome::Fail)
        .collect();
    assert!(failures.is_empty(), "unexpected failures: {failures:#?}");

    let (pass, fail, skip) = report.tally();
    assert!(pass >= 10, "expected the full chain, got {pass} passes");
    assert_eq!(fail, 0);
    assert_eq!(skip, 0);
    assert!(!report.has_failures());

    // Every link is named, so a failure points at a context salt rather than
    // at "crypto".
    let names: Vec<_> = report.checks.iter().map(|c| c.name.as_str()).collect();
    for link in [
        "link 1", "link 2", "link 3", "link 4", "link 5", "link 6", "link 7", "link 8",
    ] {
        assert!(
            names.iter().any(|n| n.starts_with(link)),
            "{link} is not reported; names were {names:#?}"
        );
    }

    // And the vault actually decrypted, through the framing layer.
    let vault = report
        .checks
        .iter()
        .find(|c| c.name.starts_with("vault "))
        .expect("the vault is reported");
    let detail = vault.detail.as_deref().unwrap_or_default();
    assert!(detail.contains("both tiers unwrapped"), "{detail}");
    assert!(detail.contains("commit decrypted"), "{detail}");
    assert!(detail.contains("LoginVaultContentV2"), "{detail}");
    assert!(detail.contains("descriptor v2"), "{detail}");
}

/// Without a grant being served there is nothing to decrypt with, and that is
/// exit code 4 rather than a generic failure.
#[tokio::test]
async fn an_expired_unlock_is_reported_as_unlock_required() {
    let h = Harness::new(&[]);
    h.seed_session();
    *h.api.sync.lock().expect("not poisoned") = h.account.sync(false);

    let err = heyl_app::doctor::run(&h.ports()).await.expect_err("locked");
    assert!(matches!(err, AppError::UnlockRequired), "{err:?}");
    assert_eq!(err.exit_code(), heyl_app::ExitCode::UnlockRequired);
}

/// A stale token must not surface as a broken hierarchy, so the refresh is
/// acted on and the new token is both stored and presented.
#[tokio::test]
async fn a_token_refresh_is_acted_on_and_persisted() {
    let h = Harness::new(&[]);
    h.seed_session();
    h.api.demand_token_refresh();

    heyl_app::doctor::run(&h.ports()).await.expect("walks");

    assert!(
        h.api.calls().contains(&"refresh_token"),
        "token_refresh_needed must be acted on: {:?}",
        h.api.calls()
    );
    assert_eq!(
        h.api.presented_token().as_deref(),
        Some("refreshed-token"),
        "later calls must use the refreshed token"
    );
    assert_eq!(
        h.store
            .get(&SecretKey::default_slot(StoredSecret::AccessToken))
            .await
            .expect("stored")
            .as_str(),
        "refreshed-token",
        "the refreshed token must be persisted, or the next run re-refreshes"
    );
}

/// heylogin's own diagnostics are surfaced as it worded them.
///
/// We do not rewrite them. Our reading of a backend error can be wrong, and a
/// hardcoded explanation goes stale the moment heylogin changes behaviour --
/// so the code, title and detail it sends are what the user is shown.
#[tokio::test]
async fn a_backend_refusal_is_surfaced_in_heylogins_own_words() {
    let h = Harness::new(&[]);
    *h.api.refuse_with.lock().expect("not poisoned") = Some(heyl_ports::ApiError::Backend {
        status: 3,
        domain_code: Some(30460),
        message: "Invalid session type".to_owned(),
        detail: "The session type reported by your client is invalid.".to_owned(),
    });

    let err = heyl_app::recovery::run(
        &h.ports(),
        "someone@example.com",
        Confirmation::Granted,
        CodeSource::Given(Zeroizing::new(TEST_CODE.to_owned())),
        ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect_err("refused");

    let rendered = err.to_string();
    assert!(rendered.contains("30460"), "names the code: {rendered}");
    assert!(
        rendered.contains("Invalid session type"),
        "keeps heylogin's title: {rendered}"
    );
    assert!(
        rendered.contains("The session type reported by your client is invalid."),
        "keeps heylogin's detail: {rendered}"
    );
}

// ------------------------------------------------------- the confirmation gate

/// Build a harness whose account still has a phone attached, so a recovery has
/// something to destroy.
fn harness_with_push(answers: &[&str]) -> Harness {
    let mut h = Harness::new(answers);
    let account = Account::new();
    h.api = FakeBackend::new(
        account.challenge_with(CHALLENGE, true),
        account.tokens(),
        account.sync(true),
        account.authenticators(),
        account.commits(),
        account.login_verifier(),
    );
    h
}

async fn recover(h: &Harness, confirmation: Confirmation<'_>) -> Result<(), AppError> {
    heyl_app::recovery::run(
        &h.ports(),
        "someone@example.com",
        confirmation,
        CodeSource::Given(Zeroizing::new(TEST_CODE.to_owned())),
        ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .map(|_| ())
}

/// Answering anything but yes leaves the account untouched — and, critically,
/// never reaches `CreateTokens`, which is the call that does the damage.
#[tokio::test]
async fn declining_the_prompt_does_not_reach_create_tokens() {
    let h = harness_with_push(&["n"]);
    let err = recover(&h, Confirmation::Ask("go ahead? "))
        .await
        .expect_err("declined");

    assert!(matches!(err, AppError::NotConfirmed), "{err:?}");
    assert_eq!(
        h.api.calls(),
        ["create_challenge"],
        "the destructive call must not be made: {:?}",
        h.api.calls()
    );
}

#[tokio::test]
async fn accepting_the_prompt_proceeds_and_reports_what_was_lost() {
    let h = harness_with_push(&["y"]);
    let outcome = heyl_app::recovery::run(
        &h.ports(),
        "someone@example.com",
        Confirmation::Ask("go ahead? "),
        CodeSource::Given(Zeroizing::new(TEST_CODE.to_owned())),
        ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect("confirmed");

    // The account's phone is named, from the pre-recovery CreateChallenge --
    // afterwards it is gone and could not be reported at all.
    assert_eq!(outcome.disconnected.len(), 1);
    assert_eq!(
        outcome.disconnected[0].kind,
        heyl_domain::AuthenticatorType::Push
    );
    assert!(h.api.calls().contains(&"create_tokens"));
}

/// `--confirm` is the scripted path, and skips the question.
#[tokio::test]
async fn confirm_flag_proceeds_without_asking() {
    // No scripted answers: a prompt would fail the test by running out.
    let h = harness_with_push(&[]);
    recover(&h, Confirmation::Granted).await.expect("proceeds");
    assert!(h.api.calls().contains(&"create_tokens"));
}

/// Nothing to lose, nothing to ask. A second recovery, with the phone already
/// gone, must not train anyone to dismiss a warning.
#[tokio::test]
async fn nothing_to_disconnect_means_nothing_is_asked() {
    let h = Harness::new(&[]);
    let outcome = heyl_app::recovery::run(
        &h.ports(),
        "someone@example.com",
        Confirmation::Ask("go ahead? "),
        CodeSource::Given(Zeroizing::new(TEST_CODE.to_owned())),
        ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect("proceeds unasked");

    assert!(outcome.disconnected.is_empty());
    assert!(h.api.calls().contains(&"create_tokens"));
}

/// Without a terminal to ask at and without `--confirm`, refuse. A destructive
/// operation does not run silently because nobody was there to object.
#[tokio::test]
async fn a_non_interactive_run_refuses_rather_than_destroying_silently() {
    let mut h = harness_with_push(&[]);
    h.terminal = ScriptedTerminal::non_interactive();

    let err = recover(&h, Confirmation::Ask("go ahead? "))
        .await
        .expect_err("refused");
    assert!(matches!(err, AppError::NotConfirmed), "{err:?}");
    assert_eq!(h.api.calls(), ["create_challenge"]);
}
