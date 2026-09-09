//! The transport: a gRPC-Web client that sends what it is given.
//!
//! **Stateless.** It holds no token, no session and no retry policy — a
//! [`crate::Request`] carries everything a call needs, and the generated
//! [`crate::HeyloginApi`] impl is a thin forward per RPC. Policy that used to
//! live here (token rotation, retrying an idempotent read) moved up to
//! [`crate::DomainApi`], because a raw layer that quietly re-sends or
//! re-authenticates is not raw (DESIGN.md §4).
//!
//! Calls go through `tonic::client::Grpc` with the method path from the
//! descriptor set rather than through the generated per-service clients. That
//! keeps the generator honest: it emits the path verbatim from the schema and
//! never has to reproduce tonic's name mangling.

use heyl_ports::ApiError;
use tokio_stream::StreamExt as _;
use tonic::{body::Body, client::Grpc};
use tower::Layer as _;

use crate::{Request, request::ClientContext, status::to_api_error};

/// How to reach heylogin, and the identity to default to.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Base URL, e.g. `https://heylogin.app/api/v1`.
    pub endpoint: String,
    /// Our own crate version, sent as `client-version`.
    pub client_version: String,
    /// The `client-type` value. `CLIENT_TYPE_CLI` in every shipped path; the
    /// probe varies it to find out where a backend constraint actually lives.
    pub client_type: String,
    /// `client-id`: a fresh UUID per client instance.
    ///
    /// The real clients always send one — `getBackendClient()` builds the
    /// `BackendClient` with `clientId: newUuid()`. A *session* is created for a
    /// client, so this is not decoration.
    pub client_id: String,
    /// `user-agent`, which M0 confirmed a custom value is accepted for.
    pub user_agent: String,
}

impl GrpcConfig {
    /// The identity this config describes, with no token yet.
    #[must_use]
    pub fn context(&self) -> ClientContext {
        ClientContext {
            client_id: self.client_id.clone(),
            client_type: self.client_type.clone(),
            client_version: self.client_version.clone(),
            user_agent: self.user_agent.clone(),
            access_token: None,
        }
    }
}

impl Default for GrpcConfig {
    fn default() -> Self {
        let context = ClientContext::default();
        Self {
            endpoint: crate::DEFAULT_ENDPOINT.to_owned(),
            client_version: context.client_version,
            client_type: context.client_type,
            client_id: context.client_id,
            user_agent: context.user_agent,
        }
    }
}

/// The concrete stack: tonic's gRPC-Web client layer over a hyper client with
/// the OS trust store. Named rather than `impl Trait`, because the generated
/// clients need the response body's associated types to be nameable.
/// Note the body type: the gRPC-Web layer wraps every request body in
/// `GrpcWebCall` before it reaches hyper, so the hyper client is parameterised
/// over the *wrapped* body, not over `tonic::body::Body`.
type HttpsClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    tonic_web::GrpcWebCall<Body>,
>;
type Transport = tonic_web::GrpcWebClientService<HttpsClient>;

/// What `GrpcClient` needs of a transport.
///
/// The bounds tonic's generated clients impose, gathered into one name so the
/// seam below reads as a seam rather than as four lines of where-clause.
pub trait Transportable:
    tonic::client::GrpcService<Body, ResponseBody = Self::Body, Error = Self::TransportError>
    + Clone
    + Send
    + 'static
{
    /// Its transport-level error type.
    type TransportError: Into<Box<dyn std::error::Error + Send + Sync>>;
    /// The response body this transport yields.
    type Body: http_body::Body<Data = bytes::Bytes, Error = Self::BodyError> + Send + 'static;
    /// Its error type.
    type BodyError: Into<Box<dyn std::error::Error + Send + Sync>> + Send;
}

impl<T, B, E> Transportable for T
where
    T: tonic::client::GrpcService<Body, ResponseBody = B> + Clone + Send + 'static,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    B: http_body::Body<Data = bytes::Bytes, Error = E> + Send + 'static,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    type TransportError = T::Error;
    type Body = B;
    type BodyError = E;
}

/// A gRPC-Web client for heylogin.
pub struct GrpcClient<T = Transport> {
    config: GrpcConfig,
    transport: T,
}

impl<T> GrpcClient<T> {
    /// Build a client over a transport supplied by the caller.
    ///
    /// The seam that lets a **recorder** wrap the real transport in `tools/`
    /// and a **replayer** stand in for it under test, without either of them
    /// shipping inside this crate: `heyl-grpc` offers the seam, not the
    /// machinery (DESIGN.md §6).
    ///
    /// The transport sits *below* tonic-web's framing, so what a recorder sees
    /// and a replayer supplies is the gRPC-Web wire body — the same bytes the
    /// backend sent.
    pub const fn with_transport(config: GrpcConfig, transport: T) -> Self {
        Self { config, transport }
    }

    /// The identity this client was configured with.
    #[must_use]
    pub fn context(&self) -> ClientContext {
        self.config.context()
    }
}

impl GrpcClient {
    /// Build a client.
    ///
    /// # Errors
    /// [`ApiError::Transport`] if the TLS stack cannot be initialised.
    ///
    /// # Panics
    /// Never: the `CryptoProvider` install is allowed to lose a race with
    /// another installer, which is why its result is discarded.
    pub fn new(config: GrpcConfig) -> Result<Self, ApiError> {
        // rustls has no built-in provider here: both of its usual ones are C
        // projects that `deny.toml` bans, so `rustls-graviola` supplies it and
        // the process-level install has to be explicit or TLS panics on first
        // use (found the hard way at M0 -- DESIGN.md §4).
        // A lost race means somebody else installed one first, which is fine.
        let _ = rustls_graviola::default_provider().install_default();

        // The OS trust store, which is what heylogin's browser-based clients
        // use and what survives a TLS-inspecting corporate proxy.
        let tls = <rustls::ClientConfig as rustls_platform_verifier::ConfigVerifierExt>::
            with_platform_verifier()
            .map_err(|e| ApiError::Transport {
                reason: format!("could not build a TLS config: {e}"),
            })?;

        // Both versions, negotiated by ALPN. heylogin answers HTTP/2 (M0
        // recorded `HTTP/2 200`), and gRPC-Web carries its trailers *inside
        // the body* -- so a mismatch here shows up as an intermittently
        // truncated response with no grpc-status, on larger payloads, rather
        // than as a connection error.
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();

        let http =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                // No idle-connection pooling.
                //
                // A pooled connection the server has already closed produces a
                // response body that ends without gRPC-Web's trailer frame,
                // which surfaces as an intermittent "missing grpc-status
                // trailer" on whichever call happens to reuse it. A CLI makes a
                // handful of requests and exits, so the handshake it costs is
                // not worth the flakiness it buys.
                .pool_max_idle_per_host(0)
                .build(connector);

        Ok(Self {
            config,
            transport: tonic_web::GrpcWebClientLayer::new().layer(http),
        })
    }
}

impl<T: Transportable> GrpcClient<T>
where
    T::Future: Send,
{
    fn origin(&self) -> Result<http::Uri, ApiError> {
        self.config
            .endpoint
            .parse()
            .map_err(|_| ApiError::Transport {
                reason: format!("endpoint is not a URI: {:?}", self.config.endpoint),
            })
    }

    /// Turn our request into tonic's, attaching the metadata it carries.
    ///
    /// `client-type` is mandatory and enum-validated; `client-version` is not
    /// validated on unauthenticated methods, and we send our real version
    /// either way rather than claiming to be something we are not.
    fn tonic_request<M>(request: Request<M>) -> Result<tonic::Request<M>, ApiError> {
        let insert = |meta: &mut tonic::metadata::MetadataMap, key: &'static str, value: &str| {
            value
                .parse()
                .map(|v| meta.insert(key, v))
                .map_err(|_| ApiError::Transport {
                    reason: format!("{key} is not a valid header value"),
                })
        };

        let mut out = tonic::Request::new(request.message);
        let meta = out.metadata_mut();
        insert(meta, "client-id", &request.client_id)?;
        insert(meta, "client-type", &request.client_type)?;
        insert(meta, "client-version", &request.client_version)?;
        insert(meta, "user-agent", &request.user_agent)?;

        if let Some(token) = request.access_token.as_deref() {
            // `backend <token>`, **not** `Bearer <token>`. heylogin's scheme
            // namespaces the credential by which service it is for, and the
            // real client joins several with commas
            // (`backend …,auditlog-write …`). Confirmed in the extension's
            // `EspbServiceClientFactory.ts`; HEYLOGIN_SPEC §1 says so too.
            insert(meta, "authorization", &format!("backend {token}"))?;
        }
        Ok(out)
    }

    fn grpc(&self) -> Result<Grpc<T>, ApiError> {
        Ok(Grpc::with_origin(self.transport.clone(), self.origin()?))
    }

    /// One unary call. The generated impl is 122 forwards to this.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    pub async fn unary<M, R>(&self, request: Request<M>, path: &'static str) -> Result<R, ApiError>
    where
        M: prost::Message + Send + Sync + 'static,
        R: prost::Message + Default + Send + Sync + 'static,
    {
        let mut grpc = self.grpc()?;
        grpc.ready().await.map_err(|e| ApiError::Transport {
            reason: e.into().to_string(),
        })?;
        let request = Self::tonic_request(request)?;
        let path = http::uri::PathAndQuery::from_static(path);
        grpc.unary(request, path, tonic_prost::ProstCodec::default())
            .await
            .map(tonic::Response::into_inner)
            .map_err(|s| to_api_error(&s))
    }

    /// One server-streaming call — `StreamingSync`, and only that.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure. Failures *within* the
    /// stream surface as items.
    pub async fn server_streaming<M, R>(
        &self,
        request: Request<M>,
        path: &'static str,
    ) -> Result<crate::MessageStream<R>, ApiError>
    where
        M: prost::Message + Send + Sync + 'static,
        R: prost::Message + Default + Send + Sync + 'static,
    {
        let mut grpc = self.grpc()?;
        grpc.ready().await.map_err(|e| ApiError::Transport {
            reason: e.into().to_string(),
        })?;
        let request = Self::tonic_request(request)?;
        let path = http::uri::PathAndQuery::from_static(path);
        let stream = grpc
            .server_streaming(request, path, tonic_prost::ProstCodec::default())
            .await
            .map(tonic::Response::into_inner)
            .map_err(|s| to_api_error(&s))?;

        // `tonic::Streaming` is already a `Stream`; boxing it here rather than
        // exposing it is what lets a replay stub yield recorded messages
        // without owning a transport.
        Ok(Box::pin(stream.map(|item| match item {
            Ok(message) => Ok(message),
            Err(status) => Err(to_api_error(&status)),
        })))
    }
}
