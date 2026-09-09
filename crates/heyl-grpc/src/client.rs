//! The `HeylApi` implementation.

use std::sync::Arc;

use heyl_domain::{
    Authenticator, AuthenticatorId, Challenge, SyncSnapshot, Tokens, VaultCommits, VaultId,
};
use heyl_ports::{ApiError, HeylApi, api::SessionUnlockGrant};
use tokio::sync::RwLock;
use tonic::{Request, body::Body};
use tower::Layer as _;

use crate::{CLIENT_TYPE_CLI, map, status::to_api_error};

/// How to reach heylogin, and how to identify ourselves.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Base URL, e.g. `https://heylogin.app/api/v1`.
    pub endpoint: String,
    /// Our own crate version, sent as `client-version`.
    pub client_version: String,
    /// `user-agent`, which M0 confirmed a custom value is accepted for.
    pub user_agent: String,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            endpoint: crate::DEFAULT_ENDPOINT.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
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

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();

        let http =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector);

        Ok(Self {
            config,
            transport: tonic_web::GrpcWebClientLayer::new().layer(http),
            token: Arc::new(RwLock::new(None)),
        })
    }

    /// Adopt a bearer token for subsequent calls.
    pub async fn set_token(&self, token: Option<String>) {
        *self.token.write().await = token;
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

        insert(meta, "client-type", CLIENT_TYPE_CLI)?;
        insert(meta, "client-version", &self.config.client_version)?;
        insert(meta, "user-agent", &self.config.user_agent)?;

        if let Some(token) = self.token.read().await.as_deref() {
            insert(meta, "authorization", &format!("Bearer {token}"))?;
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

    fn transport(&self) -> Transport {
        self.transport.clone()
    }
}

macro_rules! client_for {
    ($self:ident, $client:path) => {{
        let origin = $self.origin()?;
        <$client>::with_origin($self.transport(), origin)
    }};
}

#[async_trait::async_trait]
impl HeylApi for GrpcClient {
    async fn create_challenge(&self, email: &str) -> Result<Challenge, ApiError> {
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
    }

    async fn create_tokens(
        &self,
        authenticator_id: AuthenticatorId,
        challenge: &str,
        response: &[u8],
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
                session_type: heyl_proto::SessionType::BackupCode as i32,
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
        let mut client = client_for!(self, heyl_proto::sync_service_client::SyncServiceClient<_>);
        let request = self.request(heyl_proto::SyncRequest::default()).await?;
        let response = client.sync(request).await.map_err(|s| to_api_error(&s))?;
        let update =
            response
                .get_ref()
                .sync_update
                .as_ref()
                .ok_or_else(|| ApiError::MalformedResponse {
                    what: "SyncResponse.sync_update".to_owned(),
                })?;
        map::sync_update(update)
    }

    async fn list_authenticators(&self) -> Result<Vec<Authenticator>, ApiError> {
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
    }

    async fn list_commits(&self, vault: VaultId) -> Result<VaultCommits, ApiError> {
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
    }
}
