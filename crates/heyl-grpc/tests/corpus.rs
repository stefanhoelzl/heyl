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
fn a_corpus_round_trips_through_the_filesystem() {
    let dir = std::env::temp_dir().join(format!("heyl-corpus-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let record = Record {
        method: "/domain.SyncService/Sync".to_owned(),
        request: None,
        responses: vec![serde_json::json!({ "syncUpdate": { "tokenRefreshNeeded": true } })],
        error: None,
    };
    let path = corpus::write(&dir, 0, &record).expect("writes");
    assert!(
        path.ends_with("01-sync.json"),
        "records are numbered so lexical order is call order: {}",
        path.display()
    );

    corpus::Meta {
        code: "1111-2222-3333-4444-5555-6666".to_owned(),
        session_seed: "ERERERERERERERERERERERERERERERERERERERERERE=".to_owned(),
    }
    .write(&dir)
    .expect("writes meta");

    let loaded = corpus::load(&dir).expect("loads");
    assert_eq!(loaded.len(), 1, "_meta.json is not a call");
    assert_eq!(loaded[0].method, record.method);
    assert!(corpus::Meta::load(&dir).is_ok());

    let _ = std::fs::remove_dir_all(&dir);
}
