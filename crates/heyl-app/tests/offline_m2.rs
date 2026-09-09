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
use heyl_app::{AppError, Ports, doctor::Outcome, login::CodeSource};
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
            &heyl_app::login::encode_key(&self.account.session_key),
        );
    }
}

#[tokio::test]
async fn login_signs_the_challenge_and_stores_exactly_two_items() {
    let h = Harness::new(&[]);
    let outcome = heyl_app::login::run(
        &h.ports(),
        "someone@example.com",
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
    heyl_app::login::run(
        &h.ports(),
        "someone@example.com",
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
    let err = heyl_app::login::run(
        &h.ports(),
        "someone@example.com",
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
    let err = heyl_app::login::run(
        &h.ports(),
        "someone@example.com",
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

    let err = heyl_app::login::run(
        &ports,
        "someone@example.com",
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

    let err = heyl_app::login::run(
        &h.ports(),
        "someone@example.com",
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
