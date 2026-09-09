//! The `HeylApi` implementation.

use std::sync::Arc;

use heyl_domain::{
    Authenticator, AuthenticatorId, Challenge, SessionType, SyncSnapshot, Tokens, VaultCommits,
    VaultId,
};
use heyl_ports::{ApiError, HeylApi, api::SessionUnlockGrant};
use tokio::sync::RwLock;
use tonic::{Request, body::Body};
use tower::Layer as _;

use crate::{map, status::to_api_error};

/// How to reach heylogin, and how to identify ourselves.
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

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            endpoint: crate::DEFAULT_ENDPOINT.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            client_type: crate::CLIENT_TYPE_CLI.to_owned(),
            client_id: uuid::Uuid::new_v4().to_string(),
            user_agent: format!(
                "heyl/{} (+{})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_REPOSITORY")
            ),
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

/// What a completed phone-swipe channel hands back (§5).
#[derive(Debug, Clone)]
pub struct LongPollChallenge {
    /// The account.
    pub user_id: String,
    /// The challenge to sign.
    pub challenge: String,
    /// Which authenticator the phone answered with.
    pub authenticator_id: heyl_domain::AuthenticatorId,
    /// `asymEncrypt(ourLongPollPubKey, seed)`.
    pub encrypted_secret: Vec<u8>,
    /// Whether this was a registration rather than a login. The client only
    /// self-grants an unlock when it is *not* a registration.
    pub registration: bool,
}

/// A gRPC-Web client for heylogin.
pub struct GrpcClient {
    config: GrpcConfig,
    transport: Transport,
    /// The bearer token, if we have one. Behind a lock because `RefreshToken`
    /// replaces it mid-flight and every later call must pick up the new value.
    token: Arc<RwLock<Option<String>>>,
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
        // `rustls` sees both `ring` and `aws-lc-rs` through the dependency
        // graph, so the process-level provider must be installed explicitly or
        // TLS panics on first use (found the hard way at M0 -- DESIGN.md §4).
        // A lost race means somebody else installed one first, which is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();

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
            token: Arc::new(RwLock::new(None)),
        })
    }

    /// Attach the metadata every call needs.
    ///
    /// `client-type` is mandatory and enum-validated; `client-version` is not
    /// validated on unauthenticated methods, and we send our real version
    /// either way rather than claiming to be something we are not.
    async fn request<T>(&self, message: T) -> Result<Request<T>, ApiError> {
        let mut request = Request::new(message);
        let meta = request.metadata_mut();

        let insert = |meta: &mut tonic::metadata::MetadataMap, key: &'static str, value: &str| {
            value
                .parse()
                .map(|v| meta.insert(key, v))
                .map_err(|_| ApiError::Transport {
                    reason: format!("{key} is not a valid header value"),
                })
        };

        insert(meta, "client-id", &self.config.client_id)?;
        insert(meta, "client-type", &self.config.client_type)?;
        insert(meta, "client-version", &self.config.client_version)?;
        insert(meta, "user-agent", &self.config.user_agent)?;

        if let Some(token) = self.token.read().await.as_deref() {
            // `backend <token>`, **not** `Bearer <token>`. heylogin's scheme
            // namespaces the credential by which service it is for, and the
            // real client joins several with commas
            // (`backend …,auditlog-write …`). Confirmed in the extension's
            // `EspbServiceClientFactory.ts`; HEYLOGIN_SPEC §1 says so too.
            insert(meta, "authorization", &format!("backend {token}"))?;
        }
        Ok(request)
    }

    fn origin(&self) -> Result<http::Uri, ApiError> {
        self.config
            .endpoint
            .parse()
            .map_err(|_| ApiError::Transport {
                reason: format!("endpoint is not a URI: {:?}", self.config.endpoint),
            })
    }

    /// `CredentialService.CreateLongPollChannelChallenge` — the phone-swipe
    /// channel (§5).
    ///
    /// **Long-polls**: the call does not return until a phone completes the
    /// channel or the backend gives up. Not on `HeylApi` yet — the phone-swipe
    /// flow is M4, and this exists so its reachability can be established
    /// before the port grows a method for it.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    pub async fn create_long_poll_channel_challenge(
        &self,
        public_key_hash: &str,
    ) -> Result<LongPollChallenge, ApiError> {
        // Built inline rather than through `client_for!`: that macro is
        // declared further down this file, and a macro_rules! must precede its
        // use within one module.
        let mut client =
            heyl_proto::credential_service_client::CredentialServiceClient::with_origin(
                self.transport(),
                self.origin()?,
            );
        let request = self
            .request(heyl_proto::CreateLongPollChannelChallengeRequest {
                public_key_hash: public_key_hash.to_owned(),
            })
            .await?;
        let response = client
            .create_long_poll_channel_challenge(request)
            .await
            .map_err(|s| to_api_error(&s))?;
        let r = response.get_ref();
        let authenticator =
            r.authenticator
                .as_ref()
                .ok_or_else(|| ApiError::MalformedResponse {
                    what: "CreateLongPollChannelChallengeResponse.authenticator".to_owned(),
                })?;

        // The reply is an `AuthenticatorReply` protobuf whose
        // `encrypted_secret_reply.encrypted_secret` is
        // `asymEncrypt(ourPubKey, seed)`.
        let reply = <heyl_proto::AuthenticatorReply as prost::Message>::decode(
            &*r.authenticator_reply.clone(),
        )
        .map_err(|_| ApiError::MalformedResponse {
            what: "authenticator_reply is not an AuthenticatorReply".to_owned(),
        })?;
        let Some(heyl_proto::authenticator_reply::ReplyOneof::EncryptedSecretReply(secret)) =
            reply.reply_oneof
        else {
            return Err(ApiError::MalformedResponse {
                what: "authenticator_reply carries no encrypted secret".to_owned(),
            });
        };

        Ok(LongPollChallenge {
            user_id: r.user_id.clone(),
            challenge: r.challenge.clone(),
            authenticator_id: heyl_domain::AuthenticatorId::parse(&authenticator.id).map_err(
                |_| ApiError::MalformedResponse {
                    what: "long-poll authenticator id is not a UUID".to_owned(),
                },
            )?,
            encrypted_secret: secret.encrypted_secret,
            registration: secret.registration,
        })
    }

    fn transport(&self) -> Transport {
        self.transport.clone()
    }
}

/// How many times an idempotent read is retried after a transport fault.
const READ_RETRIES: usize = 3;

/// Retry `call` while it fails at the transport layer.
///
/// heylogin sits behind a proxy that intermittently drops the gRPC-Web trailer
/// frame, which surfaces as `missing grpc-status trailer` on a response that
/// otherwise arrived. It is not correlated with a particular RPC or payload —
/// the same call succeeds on the next attempt.
///
/// Only ever wrapped around **idempotent reads**. `CreateTokens` is not one:
/// a challenge is single-use, so retrying it would answer a spent challenge
/// and turn a transport blip into a confusing credential error.
async fn retrying_read<T, F, Fut>(mut call: F) -> Result<T, ApiError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, ApiError>>,
{
    let mut last = None;
    for attempt in 0..=READ_RETRIES {
        match call().await {
            Ok(value) => return Ok(value),
            // Only a transport fault is worth another go. A backend error is
            // an answer, and repeating the question will not change it.
            Err(ApiError::Transport { reason }) => {
                if attempt < READ_RETRIES {
                    let backoff = 150_u64 << u32::try_from(attempt).unwrap_or(0);
                    tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                }
                last = Some(ApiError::Transport { reason });
            }
            Err(other) => return Err(other),
        }
    }
    Err(last.unwrap_or(ApiError::Transport {
        reason: "read failed with no recorded cause".to_owned(),
    }))
}

macro_rules! client_for {
    ($self:ident, $client:path) => {{
        let origin = $self.origin()?;
        <$client>::with_origin($self.transport(), origin)
    }};
}

#[async_trait::async_trait]
impl HeylApi for GrpcClient {
    async fn set_access_token(&self, token: Option<&str>) {
        *self.token.write().await = token.map(str::to_owned);
    }

    async fn create_challenge(&self, email: &str) -> Result<Challenge, ApiError> {
        retrying_read(|| async {
            let mut client = client_for!(
                self,
                heyl_proto::credential_service_client::CredentialServiceClient<_>
            );
            let request = self
                .request(heyl_proto::CreateChallengeRequest {
                    email: email.to_owned(),
                    ..Default::default()
                })
                .await?;
            let response = client
                .create_challenge(request)
                .await
                .map_err(|s| to_api_error(&s))?;
            map::challenge(response.get_ref())
        })
        .await
    }

    async fn create_tokens(
        &self,
        authenticator_id: AuthenticatorId,
        challenge: &str,
        response: &[u8],
        session_type: SessionType,
        unlock: Option<SessionUnlockGrant>,
    ) -> Result<Tokens, ApiError> {
        let mut client = client_for!(
            self,
            heyl_proto::credential_service_client::CredentialServiceClient<_>
        );
        let request = self
            .request(heyl_proto::CreateTokensRequest {
                authenticator_id: authenticator_id.to_string(),
                challenge: challenge.to_owned(),
                response: response.to_vec(),
                session_unlock: unlock.map(|u| heyl_proto::create_tokens_request::SessionUnlock {
                    encrypted_secret: u.encrypted_secret,
                    expires_at: Some(prost_types::Timestamp {
                        seconds: u.expires_at.as_millisecond().div_euclid(1000),
                        nanos: i32::try_from(u.expires_at.as_millisecond().rem_euclid(1000))
                            .unwrap_or(0)
                            * 1_000_000,
                    }),
                    // A single-use grant would be consumed by the first Sync,
                    // which is exactly the read the grant exists to enable (§6).
                    single_use: false,
                }),
                session_type: map::session_type(session_type) as i32,
            })
            .await?;
        let response = client
            .create_tokens(request)
            .await
            .map_err(|s| to_api_error(&s))?;
        map::tokens(response.get_ref())
    }

    async fn refresh_token(&self) -> Result<String, ApiError> {
        let mut client = client_for!(
            self,
            heyl_proto::credential_service_client::CredentialServiceClient<_>
        );
        let request = self.request(heyl_proto::RefreshTokenRequest {}).await?;
        let response = client
            .refresh_token(request)
            .await
            .map_err(|s| to_api_error(&s))?;
        response
            .get_ref()
            .new_access_token
            .as_ref()
            .map(|t| t.token.clone())
            .ok_or_else(|| ApiError::MalformedResponse {
                what: "RefreshTokenResponse.new_access_token".to_owned(),
            })
    }

    async fn sync(&self) -> Result<SyncSnapshot, ApiError> {
        retrying_read(|| async {
            let mut client =
                client_for!(self, heyl_proto::sync_service_client::SyncServiceClient<_>);
            let request = self.request(heyl_proto::SyncRequest::default()).await?;
            let response = client.sync(request).await.map_err(|s| to_api_error(&s))?;
            let update = response.get_ref().sync_update.as_ref().ok_or_else(|| {
                ApiError::MalformedResponse {
                    what: "SyncResponse.sync_update".to_owned(),
                }
            })?;
            map::sync_update(update)
        })
        .await
    }

    async fn list_authenticators(&self) -> Result<Vec<Authenticator>, ApiError> {
        retrying_read(|| async {
            let mut client = client_for!(
                self,
                heyl_proto::authenticator_service_client::AuthenticatorServiceClient<_>
            );
            let request = self
                .request(heyl_proto::ListAuthenticatorsRequest::default())
                .await?;
            let response = client.list(request).await.map_err(|s| to_api_error(&s))?;
            response
                .get_ref()
                .authenticators
                .iter()
                .filter_map(|a| map::authenticator(a).transpose())
                .collect()
        })
        .await
    }

    async fn list_commits(&self, vault: VaultId) -> Result<VaultCommits, ApiError> {
        retrying_read(|| async {
            let mut client = client_for!(
                self,
                heyl_proto::vault_service_client::VaultServiceClient<_>
            );
            let request = self
                .request(heyl_proto::ListCommitsRequest {
                    vault_id: vault.to_string(),
                    // Nothing is cached, so a lock the backend omits as "you
                    // already have it" would read as a failure (decision 29).
                    force_locks: true,
                    ..Default::default()
                })
                .await?;
            let response = client
                .list_commits(request)
                .await
                .map_err(|s| to_api_error(&s))?;
            map::vault_commits(response.get_ref())
        })
        .await
    }
}
