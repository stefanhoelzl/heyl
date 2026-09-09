//! The generated `HeyloginApi`, checked where it can actually be wrong.
//!
//! **Not one test per RPC.** A per-method test that fed canned bytes through
//! `GrpcClient` would assert that `prost` decodes protobuf and that `tonic-web`
//! unframes gRPC-Web — upstream's test suite, not ours. What *is* ours is the
//! generator, and it varies along exactly two axes: unary versus
//! server-streaming. So there are two shape tests, not 123.
//!
//! The rest of what is checked here is the trait's contract: that the surface
//! is complete, that the default bodies name themselves, and that a stub can
//! implement one method and inherit 122.

use heyl_domain::VaultId;
use heyl_grpc::{ClientContext, HeyloginApi, METHODS, Request};
use heyl_ports::ApiError;

/// A stub that serves exactly one RPC.
///
/// This is the property the defaults exist for: a 123-method trait that
/// required every method would make a fake unusable, and there is no way to
/// write one generic "look it up by name" implementation of a typed trait.
#[derive(Default)]
struct OneMethod;

#[async_trait::async_trait]
impl HeyloginApi for OneMethod {
    async fn sync_sync(
        &self,
        request: Request<heyl_proto::SyncRequest>,
    ) -> Result<heyl_proto::SyncResponse, ApiError> {
        // Metadata is data on the request, so a stub can assert on what the
        // caller sent without going anywhere near a header map.
        assert_eq!(request.client_type, heyl_grpc::CLIENT_TYPE_CLI);
        Ok(heyl_proto::SyncResponse {
            sync_update: Some(heyl_proto::SyncUpdate::default()),
        })
    }
}

#[test]
fn the_surface_is_every_rpc_in_the_schema() {
    // M0 measured 19 services and 123 methods from `descriptors/heylogin.binpb`.
    // If a descriptor refresh drops one, the trait shrinks silently and nothing
    // else in the workspace would notice.
    assert_eq!(METHODS.len(), 123);

    // Names are qualified by service on purpose: `Update` appears on five
    // services, `List` on five, `Delete` on four.
    let mut names: Vec<&str> = METHODS.iter().map(|(_, name)| *name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(
        names.len(),
        before,
        "two RPCs generated the same method name"
    );

    let mut paths: Vec<&str> = METHODS.iter().map(|(path, _)| *path).collect();
    paths.sort_unstable();
    paths.dedup();
    assert_eq!(paths.len(), before);
}

#[tokio::test]
async fn an_unimplemented_method_names_itself() {
    let api = OneMethod;
    let context = ClientContext::default();

    let err = api
        .health_ping(context.request(heyl_proto::PingRequest::default()))
        .await
        .expect_err("the stub serves only Sync");

    match err {
        ApiError::Unimplemented { method } => assert_eq!(method, "/domain.HealthService/Ping"),
        other => panic!("expected Unimplemented, got {other:?}"),
    }
}

#[tokio::test]
async fn a_stub_implements_one_method_and_inherits_the_rest() {
    let api = OneMethod;
    let context = ClientContext::default();

    let response = api
        .sync_sync(context.request(heyl_proto::SyncRequest::default()))
        .await
        .expect("the stub serves Sync");
    assert!(response.sync_update.is_some());
}

#[tokio::test]
async fn the_streaming_method_has_a_stream_shape() {
    // The generator's second and only other branch. `StreamingSync` is the one
    // server-streaming RPC in the schema; there is no client-streaming and no
    // bidirectional anywhere, which is why the generator asserts rather than
    // models them.
    let api = OneMethod;
    let context = ClientContext::default();

    // The stream is not `Debug`, so this matches rather than unwrapping.
    match api
        .sync_streaming_sync(context.request(heyl_proto::StreamingSyncRequest::default()))
        .await
    {
        Err(ApiError::Unimplemented { method }) => {
            assert_eq!(method, "/domain.SyncService/StreamingSync");
        }
        Err(other) => panic!("expected Unimplemented, got {other:?}"),
        Ok(_) => panic!("the stub serves only Sync"),
    }
}

#[tokio::test]
async fn the_domain_port_runs_on_any_api() {
    use heyl_ports::HeylApi as _;

    // The point of the split: `DomainApi` is generic, so the port `heyl-app`
    // depends on can be driven by something that is not a socket.
    let api = heyl_grpc::DomainApi::new(OneMethod, ClientContext::default());

    let snapshot = api.sync().await.expect("the stub serves Sync");
    assert!(snapshot.vaults.is_empty());

    // And an RPC the stub does not serve fails as itself rather than as a
    // transport error.
    let err = api
        .list_commits(VaultId::parse("00000000-0000-4000-8000-000000000001").expect("a uuid"))
        .await
        .expect_err("the stub serves only Sync");
    assert!(matches!(err, ApiError::Unimplemented { .. }));
}

#[tokio::test]
async fn the_recovery_client_type_exception_is_visible_at_its_call_site() {
    use heyl_ports::HeylApi as _;

    /// Captures the `client-type` a call was made with.
    #[derive(Default)]
    struct Spy(std::sync::Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl HeyloginApi for Spy {
        async fn credential_create_tokens(
            &self,
            request: Request<heyl_proto::CreateTokensRequest>,
        ) -> Result<heyl_proto::CreateTokensResponse, ApiError> {
            self.0
                .lock()
                .expect("not poisoned")
                .push(request.client_type);
            Err(ApiError::Transport {
                reason: "stub".to_owned(),
            })
        }
    }

    let api = heyl_grpc::DomainApi::new(Spy::default(), ClientContext::default());

    // heylogin refuses a BACKUP_CODE session for any browser-family client
    // type, so a recovery is the one call that does not say 400. It is keyed on
    // the session type here rather than plumbed down from `heyl-app`.
    let _ = api
        .create_tokens(
            heyl_domain::AuthenticatorId::parse("00000000-0000-4000-8000-000000000002")
                .expect("a uuid"),
            "challenge",
            &[0_u8; 64],
            heyl_domain::SessionType::BackupCode,
            None,
        )
        .await;

    let _ = api
        .create_tokens(
            heyl_domain::AuthenticatorId::parse("00000000-0000-4000-8000-000000000002")
                .expect("a uuid"),
            "challenge",
            &[0_u8; 64],
            heyl_domain::SessionType::SelfUnlockingPrimary,
            None,
        )
        .await;

    let seen = api.inner().0.lock().expect("not poisoned").clone();
    assert_eq!(
        seen,
        vec![
            heyl_grpc::CLIENT_TYPE_RECOVERY.to_owned(),
            heyl_grpc::CLIENT_TYPE_CLI.to_owned(),
        ]
    );
}
