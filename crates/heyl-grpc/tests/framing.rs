//! gRPC-Web framing, in isolation.
//!
//! This is what the retired wire fixture uniquely covered, tested directly
//! instead of as a side effect of replaying a session. `client.rs` documents
//! the failure it guards: gRPC-Web carries its trailers **inside the body**, so
//! an HTTP/1-vs-2 mismatch or a dropped trailer frame shows up as an
//! intermittently truncated response *on larger payloads* rather than as a
//! connection error.
//!
//! A recording could only ever exercise whatever size it happened to contain.
//! Building the body here means choosing the size and the frame count, which is
//! how the vendored `tonic-web` fix — trailers arriving in the same buffer as
//! the final data frame — gets a test that names it.

use std::task::{Context, Poll};

use heyl_grpc::{ClientContext, GrpcClient, GrpcConfig, HeyloginApi};
use prost::Message as _;

/// Serve one canned gRPC-Web body, however it was framed.
#[derive(Clone)]
struct Canned {
    body: bytes::Bytes,
}

impl<ReqBody> tower::Service<http::Request<ReqBody>> for Canned {
    type Response = http::Response<http_body_util::Full<bytes::Bytes>>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: http::Request<ReqBody>) -> Self::Future {
        let body = self.body.clone();
        Box::pin(async move {
            Ok(http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc-web+proto")
                .body(http_body_util::Full::new(body))
                .expect("a valid response"))
        })
    }
}

/// Frame a message and its trailers as gRPC-Web does.
///
/// Flag `0x00` is a message; `0x80` is the trailer block, and `grpc-status`
/// lives there rather than in HTTP trailers.
fn grpc_web_body(message: &[u8], status: u32) -> bytes::Bytes {
    let mut out = Vec::new();
    out.push(0x00);
    out.extend_from_slice(&u32::try_from(message.len()).expect("fits").to_be_bytes());
    out.extend_from_slice(message);

    let trailers = format!("grpc-status:{status}\r\n");
    out.push(0x80);
    out.extend_from_slice(&u32::try_from(trailers.len()).expect("fits").to_be_bytes());
    out.extend_from_slice(trailers.as_bytes());
    bytes::Bytes::from(out)
}

/// A `SyncResponse` of roughly `size` bytes.
///
/// Padding goes in a `bytes` field, so the message is large in the way real
/// ones are — sealed blobs, not repeated small fields.
fn large_response(size: usize) -> heyl_proto::SyncResponse {
    heyl_proto::SyncResponse {
        sync_update: Some(heyl_proto::SyncUpdate {
            session_unlock: Some(heyl_proto::sync_update::SessionUnlock {
                encrypted_secret: vec![0x5A; size],
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

async fn call_with(body: bytes::Bytes) -> heyl_proto::SyncResponse {
    use tower::Layer as _;

    let transport = tonic_web::GrpcWebClientLayer::new().layer(Canned { body });
    let client = GrpcClient::with_transport(GrpcConfig::default(), transport);
    let context = ClientContext::default();

    client
        .sync_sync(context.request(heyl_proto::SyncRequest::default()))
        .await
        .expect("a well-framed body decodes")
}

#[tokio::test]
async fn a_small_body_round_trips() {
    let message = large_response(8);
    let body = grpc_web_body(&message.encode_to_vec(), 0);
    assert_eq!(call_with(body).await, message);
}

#[tokio::test]
async fn a_body_over_the_buffer_boundary_round_trips() {
    // The size that mattered: `tonic-web` 0.14.6 dropped trailers arriving in
    // the same buffer as the final data frame, which surfaced as "missing
    // grpc-status trailer" on anything over roughly 4 KiB. The vendored fix is
    // what this pins (see vendor/tonic-web/README.md).
    for size in [4_000, 4_096, 8_192, 65_536] {
        let message = large_response(size);
        let body = grpc_web_body(&message.encode_to_vec(), 0);
        assert_eq!(
            call_with(body).await,
            message,
            "a {size}-byte payload should survive framing"
        );
    }
}

#[tokio::test]
async fn a_status_in_the_trailer_frame_becomes_an_error() {
    use heyl_ports::ApiError;

    // gRPC-Web puts the status inside the body. Reading it from the wrong place
    // was one of the two defects M2 shipped, so it is asserted directly rather
    // than reached through a recorded session.
    let body = grpc_web_body(&heyl_proto::SyncResponse::default().encode_to_vec(), 7);

    let transport = {
        use tower::Layer as _;
        tonic_web::GrpcWebClientLayer::new().layer(Canned { body })
    };
    let client = GrpcClient::with_transport(GrpcConfig::default(), transport);
    let context = ClientContext::default();

    let err = client
        .sync_sync(context.request(heyl_proto::SyncRequest::default()))
        .await
        .expect_err("status 7 is a refusal");
    assert!(
        matches!(err, ApiError::PermissionDenied { .. }),
        "expected PermissionDenied, got {err:?}"
    );
}
