//! Record, then replay.
//!
//! The two generated surfaces are each other's inverse, so the honest test is
//! the round trip: wrap an API, make calls, and check that a `RecordedApi` over
//! what was kept answers the same way. Anything the recorder drops or the
//! replay mismatches shows up here rather than as a puzzling failure in a
//! use-case test three layers up.

#![cfg(feature = "api")]

use heyl_grpc::{ClientContext, HeyloginApi, Record, RecordedApi, RecordingApi, Request, corpus};
use heyl_ports::ApiError;

/// An API that answers `Sync` and `ListCommits`, and refuses `CreateTokens`.
struct Backend;

#[async_trait::async_trait]
impl HeyloginApi for Backend {
    async fn sync_sync(
        &self,
        _request: Request<heyl_proto::SyncRequest>,
    ) -> Result<heyl_proto::SyncResponse, ApiError> {
        Ok(heyl_proto::SyncResponse {
            sync_update: Some(heyl_proto::SyncUpdate {
                token_refresh_needed: true,
                ..Default::default()
            }),
        })
    }

    async fn vault_list_commits(
        &self,
        request: Request<heyl_proto::ListCommitsRequest>,
    ) -> Result<heyl_proto::ListCommitsResponse, ApiError> {
        // Answers differ per vault, which is what makes request matching
        // load-bearing on replay.
        Ok(heyl_proto::ListCommitsResponse {
            current_generation_id: request.message.vault_id.clone(),
            ..Default::default()
        })
    }

    async fn credential_create_tokens(
        &self,
        _request: Request<heyl_proto::CreateTokensRequest>,
    ) -> Result<heyl_proto::CreateTokensResponse, ApiError> {
        Err(ApiError::BadRequest {
            domain_code: Some(30460),
            message: "Invalid session type".to_owned(),
        })
    }
}

fn commits_for(vault: &str) -> heyl_proto::ListCommitsRequest {
    heyl_proto::ListCommitsRequest {
        vault_id: vault.to_owned(),
        force_locks: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn what_is_recorded_replays_the_same_way() {
    let context = ClientContext::default();
    let recorder = RecordingApi::new(Backend);

    let live_sync = recorder
        .sync_sync(context.request(heyl_proto::SyncRequest::default()))
        .await
        .expect("the backend answers");
    let live_first = recorder
        .vault_list_commits(context.request(commits_for("vault-a")))
        .await
        .expect("the backend answers");

    let replay = RecordedApi::new(recorder.records());

    assert_eq!(
        replay
            .sync_sync(context.request(heyl_proto::SyncRequest::default()))
            .await
            .expect("the corpus answers"),
        live_sync
    );
    assert_eq!(
        replay
            .vault_list_commits(context.request(commits_for("vault-a")))
            .await
            .expect("the corpus answers"),
        live_first
    );
}

#[tokio::test]
async fn calls_that_differ_only_by_request_are_matched_by_it() {
    let context = ClientContext::default();
    let recorder = RecordingApi::new(Backend);

    // Recorded in one order...
    for vault in ["vault-a", "vault-b", "vault-c"] {
        recorder
            .vault_list_commits(context.request(commits_for(vault)))
            .await
            .expect("the backend answers");
    }

    // ...and asked for in another. Five `ListCommits` in a real session differ
    // only by `vaultId`, so order alone would hand back the wrong vault's
    // commits — silently, which is the worst way for a fixture to be wrong.
    let replay = RecordedApi::new(recorder.records());
    for vault in ["vault-c", "vault-a", "vault-b"] {
        let answer = replay
            .vault_list_commits(context.request(commits_for(vault)))
            .await
            .expect("the corpus answers");
        assert_eq!(answer.current_generation_id, vault);
    }
    assert!(replay.unused().is_empty());
}

#[tokio::test]
async fn a_refusal_is_recorded_and_replayed_as_one() {
    let context = ClientContext::default();
    let recorder = RecordingApi::new(Backend);

    let _ = recorder
        .credential_create_tokens(context.request(heyl_proto::CreateTokensRequest::default()))
        .await;

    // A corpus that could only hold successes would push every "the backend
    // refuses this" test back onto a hand-built fake.
    let replay = RecordedApi::new(recorder.records());
    let err = replay
        .credential_create_tokens(context.request(heyl_proto::CreateTokensRequest::default()))
        .await
        .expect_err("the refusal was recorded");

    match err {
        ApiError::BadRequest { domain_code, .. } => assert_eq!(domain_code, Some(30460)),
        other => panic!("expected the recorded refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_call_with_no_record_names_itself() {
    let context = ClientContext::default();
    let replay = RecordedApi::new(Vec::new());

    let err = replay
        .health_ping(context.request(heyl_proto::PingRequest::default()))
        .await
        .expect_err("the corpus is empty");

    // Reaching past what a situation records is a test problem, and the error
    // says which call it was rather than looking like a transport failure.
    assert!(matches!(
        err,
        ApiError::Unimplemented {
            method: "/domain.HealthService/Ping"
        }
    ));
}

#[tokio::test]
async fn no_token_reaches_the_corpus() {
    let context = ClientContext {
        access_token: Some("a-live-bearer-token".to_owned()),
        ..ClientContext::default()
    };
    let recorder = RecordingApi::new(Backend);
    recorder
        .sync_sync(context.request(heyl_proto::SyncRequest::default()))
        .await
        .expect("the backend answers");

    // The token is metadata on the request like any other, so a recorder sees
    // it. It is dropped at the point of recording rather than redacted later,
    // because a redaction step that runs after the fact can be forgotten.
    let written = serde_json::to_string(&recorder.records()).expect("records serialize");
    assert!(
        !written.contains("a-live-bearer-token"),
        "a recorded corpus must never carry a token"
    );
}

#[test]
fn a_scenario_round_trips_through_the_filesystem() {
    let dir = std::env::temp_dir().join(format!("heyl-scenario-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("round-trip.json");

    let scenario = corpus::Scenario {
        meta: corpus::Meta {
            code: "1111-2222-3333-4444-5555-6666".to_owned(),
            first_draw: "ERERERERERERERERERERERERERERERERERERERERERE=".to_owned(),
            store: [("heyl/slots".to_owned(), "[\"ci\"]".to_owned())]
                .into_iter()
                .collect(),
            note: None,
        },
        steps: vec![
            corpus::Step {
                argv: vec!["recovery".to_owned(), "--confirm".to_owned()],
                stdin: Some("1111-2222-3333-4444-5555-6666\n".to_owned()),
                env: [("HEYL_SESSION".to_owned(), "ci".to_owned())]
                    .into_iter()
                    .collect(),
                note: Some("approve on your phone".to_owned()),
                collapse: vec!["/domain.SyncService/Sync".to_owned()],
                exit: 0,
                redact: Vec::new(),
                calls: vec![Record {
                    method: "/domain.SyncService/Sync".to_owned(),
                    request: None,
                    responses: vec![
                        serde_json::json!({ "syncUpdate": { "tokenRefreshNeeded": true } }),
                    ],
                    error: None,
                }],
                stdout: Some(vec![serde_json::json!({ "userId": "u" })]),
            },
            corpus::Step {
                argv: vec!["doctor".to_owned()],
                stdin: None,
                env: std::collections::BTreeMap::new(),
                note: None,
                collapse: Vec::new(),
                exit: 3,
                redact: vec!["/summary/elapsed".to_owned()],
                calls: Vec::new(),
                stdout: None,
            },
        ],
    };
    scenario.write(&path).expect("writes");

    let loaded = corpus::Scenario::load(&path).expect("loads");
    assert_eq!(loaded.steps.len(), 2);
    assert_eq!(loaded.steps[0].calls[0].method, "/domain.SyncService/Sync");
    assert_eq!(
        loaded.steps[0].stdin.as_deref(),
        Some("1111-2222-3333-4444-5555-6666\n")
    );
    // A step that has not been blessed yet is legible as such rather than as
    // an empty expectation, which would pass against a command printing
    // nothing.
    assert!(loaded.steps[1].stdout.is_none());
    assert_eq!(loaded.steps[1].exit, 3);
    assert_eq!(loaded.first_draw().expect("32 bytes"), [0x11; 32]);

    // The hand-written half survives the round trip: what a person must do,
    // what the step's environment holds, and which method's repeated answers
    // the recorder keeps once.
    assert_eq!(loaded.steps[0].env["HEYL_SESSION"], "ci");
    assert_eq!(
        loaded.steps[0].note.as_deref(),
        Some("approve on your phone")
    );
    assert_eq!(loaded.steps[0].collapse, ["/domain.SyncService/Sync"]);
    assert_eq!(loaded.meta.store["heyl/slots"], "[\"ci\"]");

    // A step that printed one document still reads as a list of one, because
    // `session list` prints a top-level array and the two must be tellable
    // apart.
    assert_eq!(loaded.steps[0].stdout.as_ref().expect("blessed").len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A step's calls answer that step, and no other.
///
/// The flat corpus this replaced had one cursor for a whole session, so a call
/// made during the wrong invocation still found a record — silently, which is
/// the worst way for a fixture to be wrong.
#[tokio::test]
async fn a_step_answers_only_its_own_calls() {
    let context = ClientContext::default();
    let recorder = RecordingApi::new(Backend);
    recorder
        .sync_sync(context.request(heyl_proto::SyncRequest::default()))
        .await
        .expect("the backend answers");

    let first = RecordedApi::new(recorder.records());
    assert!(
        first
            .sync_sync(context.request(heyl_proto::SyncRequest::default()))
            .await
            .is_ok()
    );

    // A second step, with its own calls: this one records none, so the same
    // call has nothing to match.
    let second = RecordedApi::new(Vec::new());
    assert!(matches!(
        second
            .sync_sync(context.request(heyl_proto::SyncRequest::default()))
            .await,
        Err(ApiError::Unimplemented { .. })
    ));
}
