//! Recording the wire, from outside `heyl-grpc`.
//!
//! `GrpcClient` offers a transport seam; the machinery that uses it lives here,
//! so nothing that records ships in the binary users install (DESIGN.md §6).
//! The layer sits *below* tonic-web's framing, so what it captures is the
//! gRPC-Web response body exactly as heylogin sent it — which is what a
//! wire-level replay needs.
//!
//! **One pass.** A recording is made during a real, destructive recovery, and
//! that opportunity does not repeat without pairing a phone again. So the
//! recorder captures every exchange of a whole session in order — challenge,
//! tokens, sync, authenticator list, every `ListCommits` — rather than
//! expecting to be run once per RPC.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use http_body_util::BodyExt as _;

/// One request/response pair, as it went over the wire.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Exchange {
    /// The gRPC method path, e.g. `/domain.SyncService/Sync`.
    pub path: String,
    /// The gRPC-Web request body, base64.
    pub request: String,
    /// The gRPC-Web response body, base64.
    pub response: String,
    /// Response headers worth keeping — the status lives here on a
    /// trailers-only reply.
    pub headers: Vec<(String, String)>,
}

/// What a replay needs to know that is not in the bytes.
///
/// A fixture that requires the reader to guess which random values produced it
/// is coupled to whatever generated it. This states them instead.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    /// The synthetic recovery code the fixture was re-keyed onto.
    pub code: String,
    /// The 32-byte seed the session encryption key is derived from, base64.
    ///
    /// `recovery` draws this from `RandomSource` and derives the session key
    /// with it, so the unlock blob is sealed to whatever the replay's random
    /// source yields first. Stating it here lets the test supply exactly that.
    pub session_seed: String,
}

/// Everything captured during one session.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Recording {
    /// Present on a re-keyed fixture; absent on a raw recording.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
    /// In call order. Replay walks this and asserts the path matches, so a
    /// change in call order fails loudly rather than decrypting the wrong
    /// vault quietly.
    pub exchanges: Vec<Exchange>,
}

/// Shared sink the layer writes into.
#[derive(Clone, Default)]
pub struct Recorder {
    inner: Arc<Mutex<Recording>>,
}

impl Recorder {
    /// A fresh sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// What has been captured so far.
    #[must_use]
    pub fn recording(&self) -> Recording {
        self.inner.lock().expect("not poisoned").clone()
    }

    /// Write it out as JSON.
    ///
    /// # Errors
    /// Any filesystem or serialisation failure.
    pub fn write(&self, path: &PathBuf) -> Result<usize, String> {
        let recording = self.recording();
        let json = serde_json::to_string_pretty(&recording)
            .map_err(|e| format!("serialising the recording: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("writing {}: {e}", path.display()))?;
        Ok(recording.exchanges.len())
    }

    fn push(&self, exchange: Exchange) {
        self.inner
            .lock()
            .expect("not poisoned")
            .exchanges
            .push(exchange);
    }
}

/// Wraps an HTTP service and records what passes through it.
#[derive(Clone)]
pub struct RecordingService<S> {
    inner: S,
    recorder: Recorder,
}

impl<S> RecordingService<S> {
    /// Wrap `inner`, writing into `recorder`.
    pub const fn new(inner: S, recorder: Recorder) -> Self {
        Self { inner, recorder }
    }
}

impl<S, ReqBody, ResBody> tower::Service<http::Request<ReqBody>> for RecordingService<S>
where
    S: tower::Service<
            http::Request<http_body_util::Full<bytes::Bytes>>,
            Response = http::Response<ResBody>,
        > + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: Send,
    ReqBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    ReqBody::Error: std::fmt::Display,
    ResBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    ResBody::Error: std::fmt::Display,
{
    type Response = http::Response<http_body_util::Full<bytes::Bytes>>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        use base64::Engine as _;
        let mut inner = self.inner.clone();
        let recorder = self.recorder.clone();

        Box::pin(async move {
            let path = req.uri().path().to_owned();
            let (parts, body) = req.into_parts();

            // Buffer the request so it can be both recorded and forwarded.
            // Every call here is unary and small; nothing streams.
            let request_bytes = body
                .collect()
                .await
                .map(http_body_util::Collected::to_bytes)
                .unwrap_or_default();

            let forwarded =
                http::Request::from_parts(parts, http_body_util::Full::new(request_bytes.clone()));
            let response = inner.call(forwarded).await?;

            let (parts, body) = response.into_parts();
            let response_bytes = body
                .collect()
                .await
                .map(http_body_util::Collected::to_bytes)
                .unwrap_or_default();

            let b64 = base64::engine::general_purpose::STANDARD;
            recorder.push(Exchange {
                path,
                request: b64.encode(&request_bytes),
                response: b64.encode(&response_bytes),
                headers: parts
                    .headers
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str()
                            .ok()
                            .map(|v| (k.as_str().to_owned(), v.to_owned()))
                    })
                    .collect(),
            });

            Ok(http::Response::from_parts(
                parts,
                http_body_util::Full::new(response_bytes),
            ))
        })
    }
}

// ------------------------------------------------------------------ the driver

/// Build a `GrpcClient` whose transport records everything through it.
///
/// Mirrors `GrpcClient::new`'s stack exactly — platform trust store, both HTTP
/// versions, no idle pooling — with the recorder spliced in below tonic-web.
///
/// # Errors
/// If the TLS stack cannot be initialised.
pub fn recording_client(
    config: heyl_grpc::GrpcConfig,
    recorder: Recorder,
) -> Result<heyl_grpc::GrpcClient<impl heyl_grpc::client::Transportable<Future: Send> + Sync>, String>
{
    use tower::Layer as _;

    let _ = rustls_graviola::default_provider().install_default();
    let tls = <rustls::ClientConfig as rustls_platform_verifier::ConfigVerifierExt>::
        with_platform_verifier()
        .map_err(|e| format!("TLS config: {e}"))?;

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let http = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(connector);

    let recording = RecordingService::new(http, recorder);
    let transport = tonic_web::GrpcWebClientLayer::new().layer(recording);

    Ok(heyl_grpc::GrpcClient::with_transport(config, transport))
}

/// Record a whole session: recovery, then every read `doctor` performs.
///
/// One pass, because a destructive recovery cannot be repeated without pairing
/// a phone again. What it captures is the complete input a wire-level replay
/// needs: `CreateChallenge`, `CreateTokens`, `Sync`,
/// `AuthenticatorService.List`, and `ListCommits` for every vault.
///
/// # Errors
/// Anything the underlying calls fail with, or a filesystem failure.
pub async fn run(endpoint: &str, out: &PathBuf, confirm: bool) -> Result<(), String> {
    let email = std::env::var("HEYL_EMAIL")
        .map_err(|_| "set HEYL_EMAIL (try running under `secrets-env`)".to_owned())?;
    let code = std::env::var("HEYL_RECOVERY_CODE")
        .map_err(|_| "set HEYL_RECOVERY_CODE (try running under `secrets-env`)".to_owned())?;

    let recorder = Recorder::new();
    let config = heyl_grpc::GrpcConfig {
        endpoint: endpoint.to_owned(),
        ..heyl_grpc::GrpcConfig::default()
    };
    let context = config.context();
    // The port over the recording transport: `heyl-app` still sees `HeylApi`,
    // and what lands in the recording is the gRPC-Web bytes underneath.
    let api = heyl_grpc::DomainApi::new(recording_client(config, recorder.clone())?, context);

    // --- the recovery itself, through heyl-app so the recording is of the
    //     path the product actually takes.
    let store = crate::mem::MemoryStore::default();
    let terminal = crate::mem::AnsweringTerminal::new(confirm);
    let clock = heyl_platform::SystemClock;
    let random = heyl_platform::OsRandom;
    let ports = heyl_app::Ports {
        api: &api,
        store: &store,
        terminal: &terminal,
        clock: &clock,
        random: &random,
    };

    let outcome = heyl_app::recovery::run(
        &ports,
        &email,
        if confirm {
            heyl_app::recovery::Confirmation::Granted
        } else {
            heyl_app::recovery::Confirmation::Ask("Disconnect and recover? [y/N] ")
        },
        heyl_app::recovery::CodeSource::Given(zeroize::Zeroizing::new(code)),
        heyl_domain::ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .map_err(|e| format!("recovery: {e}"))?;

    eprintln!(
        "recovered {}; session {}",
        outcome.user_id, outcome.session_id
    );
    if outcome.disconnected.is_empty() {
        eprintln!("nothing was disconnected (the account had no other authenticator)");
    } else {
        for d in &outcome.disconnected {
            eprintln!("disconnected {:?}  {}", d.kind, d.id);
        }
    }

    // --- then `doctor` itself, rather than a hand-rolled sequence of the same
    //     calls. It reads the stored token, sets it on the client, syncs,
    //     handles a token refresh, lists authenticators and walks every vault —
    //     so the recording is the product's own call sequence, in the order a
    //     wire-level replay will assert.
    let report = heyl_app::doctor::run(&ports)
        .await
        .map_err(|e| format!("doctor: {e}"))?;
    let (pass, fail, skip) = report.tally();
    eprintln!("doctor over the recorded session: {pass} passed, {fail} failed, {skip} skipped");
    if report.has_failures() {
        return Err(
            "doctor failed against the live account; the recording would bake in a \
                    broken session"
                .to_owned(),
        );
    }

    let n = recorder.write(out)?;
    eprintln!("\nwrote {n} exchanges to {}", out.display());
    eprintln!(
        "This recording contains REAL key material and a live token. It is input to \
         `rekey`, which\nreplaces all of it with synthetic material; it must not be \
         committed as it stands."
    );
    Ok(())
}
