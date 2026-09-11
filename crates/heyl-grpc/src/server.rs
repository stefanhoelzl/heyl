//! heylogin, on loopback — answered from a corpus, or proxied to the real one.
//!
//! A scenario's steps are separate `heyl` processes, so whatever answers them
//! has to do it the way heylogin does: gRPC-Web over HTTP/1.1. The binary is
//! then the shipped one, talking through its own transport — `tonic-web`'s
//! framing, the vendored trailer fix, `status.rs`' decoding — none of which a
//! port-level fake reaches. Both defects M2 actually shipped lived in that
//! layer.
//!
//! **One server, both directions.** [`serve`](crate::serve) takes any
//! [`HeyloginApi`], so what sits behind this decides what it is:
//!
//! * a [`RecordedApi`](crate::RecordedApi) makes it a **replay** — the corpus,
//!   served. Swapped per step, so a call arriving during the wrong invocation
//!   finds nothing rather than quietly matching a record meant for a later
//!   command.
//! * a [`RecordingApi`](crate::RecordingApi) over a real [`GrpcClient`] makes it
//!   a **recording proxy** — it forwards to heylogin and keeps what crossed.
//!
//! That is why the binary needs no recording code of its own: pointing
//! `HEYL_ENDPOINT` at this is the whole of it, and a `--features dev` build
//! reads that variable. A release build does not — it always talks to
//! heylogin — which is the point of reading it there and nowhere else.
//!
//! Request metadata is rebuilt from the incoming headers rather than
//! defaulted, because a proxy that dropped it would change what it is
//! recording: the token, and the one call that identifies as
//! [`CLIENT_TYPE_RECOVERY`](crate::CLIENT_TYPE_RECOVERY) rather than
//! `CLIENT_TYPE_CLI`.
//!
//! The 122 decode-call-encode arms are generated from the same descriptor walk
//! as the client. Hand-writing them is exactly the drift the generator exists
//! to prevent.

use std::{
    convert::Infallible,
    fmt::Write as _,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use heyl_ports::ApiError;
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, Response, body::Bytes, service::service_fn};

use crate::{ClientContext, HeyloginApi};

/// What the handler needs, and what the caller reads back.
struct Shared {
    /// What answers calls. Replaced between steps.
    api: Arc<dyn HeyloginApi>,
    /// Calls the backend had no answer for, in order.
    ///
    /// Reaching past what a scenario records is a test problem, and it is
    /// reported as one rather than reaching the binary as an ordinary backend
    /// failure it will dutifully print.
    unmatched: Vec<String>,
}

/// heylogin, on loopback.
pub struct Server {
    addr: SocketAddr,
    shared: Arc<Mutex<Shared>>,
}

impl Server {
    /// Bind an ephemeral port and start serving from `api`.
    ///
    /// Ephemeral because scenarios run in parallel; nothing coordinates ports.
    ///
    /// # Errors
    /// [`std::io::Error`] if the loopback port cannot be bound.
    pub async fn start(api: Arc<dyn HeyloginApi>) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Mutex::new(Shared {
            api,
            unmatched: Vec::new(),
        }));

        let accepting = Arc::clone(&shared);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let shared = Arc::clone(&accepting);
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let service = service_fn(move |req| handle(req, Arc::clone(&shared)));
                    // A client that hangs up mid-request is ordinary here: the
                    // step's process has exited and the test moves on.
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });

        Ok(Self { addr, shared })
    }

    /// What to put in `HEYL_ENDPOINT`.
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Answer from this from now on, and forget what went unanswered.
    ///
    /// # Panics
    /// Never in practice: only a panic mid-request could poison the lock.
    pub fn serve_from(&self, api: Arc<dyn HeyloginApi>) {
        let mut shared = self.shared.lock().expect("not poisoned");
        shared.api = api;
        shared.unmatched.clear();
    }

    /// Calls made since the last [`Self::serve_from`] that had no answer.
    ///
    /// # Panics
    /// Never in practice: only a panic mid-request could poison the lock.
    #[must_use]
    pub fn unmatched(&self) -> Vec<String> {
        self.shared.lock().expect("not poisoned").unmatched.clone()
    }
}

async fn handle(
    request: Request<hyper::body::Incoming>,
    shared: Arc<Mutex<Shared>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = request.uri().path().to_owned();
    let context = context_from(request.headers());
    let body = request
        .into_body()
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();

    // A gRPC frame: one flag byte, four bytes of big-endian length, the
    // message. gRPC-Web's binary framing is the same, which is why the client
    // layer passes the request body through untouched.
    let message = match body.get(..5) {
        Some(header) => {
            let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            body.get(5..5 + len).unwrap_or_default().to_vec()
        }
        None => Vec::new(),
    };

    let api = Arc::clone(&shared.lock().expect("not poisoned").api);
    let outcome = crate::serve(&*api, &context, &path, &message).await;

    if let Err(ApiError::Unimplemented { method }) = &outcome {
        shared
            .lock()
            .expect("not poisoned")
            .unmatched
            .push((*method).to_owned());
    }

    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/grpc-web+proto")
        .body(Full::new(grpc_web_body(&outcome)))
        .expect("a valid response"))
}

/// Rebuild the caller's identity from the headers it sent.
///
/// A proxy that defaulted these would record something other than what the
/// client asked: heylogin refuses a `BACKUP_CODE` session for any
/// browser-family `client-type`, so the one call that says `200` has to keep
/// saying it.
fn context_from(headers: &http::HeaderMap) -> ClientContext {
    let mut context = ClientContext::default();
    let text = |name: &str| headers.get(name)?.to_str().ok().map(str::to_owned);

    if let Some(value) = text("client-id") {
        context.client_id = value;
    }
    if let Some(value) = text("client-type") {
        context.client_type = value;
    }
    if let Some(value) = text("client-version") {
        context.client_version = value;
    }
    if let Some(value) = text("user-agent") {
        context.user_agent = value;
    }
    // `backend <token>`, not `Bearer <token>` — heylogin namespaces the
    // credential by which service it is for.
    context.access_token =
        text("authorization").and_then(|value| value.strip_prefix("backend ").map(str::to_owned));
    context
}

/// Frame a reply as gRPC-Web does.
///
/// Flag `0x00` is a message; `0x80` is the trailer block, and `grpc-status`
/// lives there rather than in HTTP trailers — which is the whole reason
/// `framing.rs` exists as a test.
fn grpc_web_body(outcome: &Result<Vec<u8>, ApiError>) -> Bytes {
    let mut out = Vec::new();
    let trailers = match outcome {
        Ok(message) => {
            out.push(0x00);
            out.extend_from_slice(&(u32::try_from(message.len()).expect("fits")).to_be_bytes());
            out.extend_from_slice(message);
            "grpc-status:0\r\n".to_owned()
        }
        Err(e) => {
            let (status, domain_code, message) = wire_error(e);
            let mut trailers = format!("grpc-status:{status}\r\ngrpc-message:{message}\r\n");
            // heylogin puts the code a client acts on in the details, not the
            // message, so a replay that dropped them would quietly turn a
            // `DomainError 30460` into an unremarkable bad request.
            if let Some(code) = domain_code {
                let _ = write!(
                    trailers,
                    "grpc-status-details-bin:{}\r\n",
                    encode_details(status, code, &message)
                );
            }
            trailers
        }
    };

    out.push(0x80);
    out.extend_from_slice(&(u32::try_from(trailers.len()).expect("fits")).to_be_bytes());
    out.extend_from_slice(trailers.as_bytes());
    Bytes::from(out)
}

/// The gRPC status, domain code and message an [`ApiError`] came from.
///
/// The inverse of `RecordedError::to_api_error`, so a recorded refusal reaches
/// the binary as the refusal that was recorded.
fn wire_error(e: &ApiError) -> (i32, Option<i32>, String) {
    match e {
        ApiError::Unauthenticated { domain_code } => (16, *domain_code, "unauthenticated".into()),
        ApiError::PermissionDenied { domain_code } => (7, *domain_code, "permission denied".into()),
        ApiError::BadRequest {
            domain_code,
            message,
        } => (3, *domain_code, sanitise(message)),
        ApiError::Backend {
            status,
            domain_code,
            message,
            ..
        } => (*status, *domain_code, sanitise(message)),
        ApiError::Unimplemented { method } => (
            12,
            None,
            sanitise(&format!("the scenario has no record for {method}")),
        ),
        other => (2, None, sanitise(&other.to_string())),
    }
}

/// Trailers are a line-oriented block, so a message may not carry its own
/// framing.
fn sanitise(message: &str) -> String {
    message.replace(['\r', '\n', ':'], " ")
}

/// A `google.rpc.Status` carrying a `DomainError`, base64 and unpadded.
fn encode_details(status: i32, code: i32, message: &str) -> String {
    use base64::Engine as _;
    use prost::Message as _;

    let detail = heyl_proto::DomainError {
        code,
        user_title: message.to_owned(),
        ..Default::default()
    };
    let envelope = heyl_proto::RpcStatus {
        code: status,
        message: message.to_owned(),
        details: vec![prost_types::Any {
            type_url: "type.googleapis.com/domain.DomainError".to_owned(),
            value: detail.encode_to_vec(),
        }],
    };
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(envelope.encode_to_vec())
}
