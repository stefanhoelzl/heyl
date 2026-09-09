//! `HeylApi`, implemented over `HeyloginApi`.
//!
//! This is the seam the port always described but did not have: `heyl-app`
//! talks to [`heyl_ports::HeylApi`] in domain types, and everything below —
//! prost messages, metadata, the transport — is somebody else's problem. Until
//! now that "somebody else" was `GrpcClient` itself, which meant the mapping
//! could only ever be exercised through a socket or a fake socket.
//!
//! Splitting it moves three things out of the transport and into one place:
//!
//! * **the mapping**, in [`crate::map`], which is the hand-written part and
//!   therefore the part worth testing;
//! * **the token**, which the port is deliberately stateful about because
//!   `RefreshToken` rotates it mid-run (`heyl_ports::api`);
//! * **retrying an idempotent read**, which a raw layer must not do silently.
//!
//! Generic over `A: HeyloginApi`, so the same code runs against the real
//! client and against a recorded one.

use heyl_domain::{
    Authenticator, AuthenticatorId, Challenge, SessionType, SyncSnapshot, Tokens, VaultCommits,
    VaultId,
};
use heyl_ports::{ApiError, HeylApi, api::SessionUnlockGrant};
use tokio::sync::RwLock;

use crate::{ClientContext, HeyloginApi, map};

/// What a completed phone-swipe channel hands back (§5).
#[derive(Debug, Clone)]
pub struct LongPollChallenge {
    /// The account.
    pub user_id: String,
    /// The challenge to sign.
    pub challenge: String,
    /// Which authenticator the phone answered with.
    pub authenticator_id: AuthenticatorId,
    /// `asymEncrypt(ourLongPollPubKey, seed)`.
    pub encrypted_secret: Vec<u8>,
    /// Whether this was a registration rather than a login. The client only
    /// self-grants an unlock when it is *not* a registration.
    pub registration: bool,
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

/// The domain port, over any `HeyloginApi`.
pub struct DomainApi<A> {
    api: A,
    /// Identity plus the current token.
    ///
    /// Behind a lock because `RefreshToken` replaces the token mid-flight and
    /// every later call must pick up the new value — the reason
    /// `heyl_ports::HeylApi` is stateful about authentication at all. The lock
    /// lives here rather than in the transport, so the raw layer stays a pure
    /// function of its request.
    context: RwLock<ClientContext>,
}

impl<A: HeyloginApi> DomainApi<A> {
    /// Wrap an API with an identity.
    pub fn new(api: A, context: ClientContext) -> Self {
        Self {
            api,
            context: RwLock::new(context),
        }
    }

    /// The API underneath, for callers that want the raw surface.
    pub const fn inner(&self) -> &A {
        &self.api
    }

    async fn context(&self) -> ClientContext {
        self.context.read().await.clone()
    }

    /// `CredentialService.CreateLongPollChannelChallenge` — the phone-swipe
    /// channel (§5).
    ///
    /// **Long-polls**: the call does not return until a phone completes the
    /// channel or the backend gives up. Not on `HeylApi` yet — the phone-swipe
    /// flow is a later milestone, and this exists so its reachability can be
    /// established before the port grows a method for it.
    ///
    /// # Errors
    /// [`ApiError`] on any transport or backend failure.
    pub async fn create_long_poll_channel_challenge(
        &self,
        public_key_hash: &str,
    ) -> Result<LongPollChallenge, ApiError> {
        let context = self.context().await;
        let response = self
            .api
            .credential_create_long_poll_channel_challenge(context.request(
                heyl_proto::CreateLongPollChannelChallengeRequest {
                    public_key_hash: public_key_hash.to_owned(),
                },
            ))
            .await?;

        let authenticator =
            response
                .authenticator
                .as_ref()
                .ok_or_else(|| ApiError::MalformedResponse {
                    what: "CreateLongPollChannelChallengeResponse.authenticator".to_owned(),
                })?;

        // The reply is an `AuthenticatorReply` protobuf whose
        // `encrypted_secret_reply.encrypted_secret` is
        // `asymEncrypt(ourPubKey, seed)`.
        let reply = <heyl_proto::AuthenticatorReply as prost::Message>::decode(
            &*response.authenticator_reply.clone(),
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
            user_id: response.user_id.clone(),
            challenge: response.challenge.clone(),
            authenticator_id: AuthenticatorId::parse(&authenticator.id).map_err(|_| {
                ApiError::MalformedResponse {
                    what: "long-poll authenticator id is not a UUID".to_owned(),
                }
            })?,
            encrypted_secret: secret.encrypted_secret,
            registration: secret.registration,
        })
    }
}

#[async_trait::async_trait]
impl<A: HeyloginApi> HeylApi for DomainApi<A> {
    async fn set_access_token(&self, token: Option<&str>) {
        self.context.write().await.access_token = token.map(str::to_owned);
    }

    async fn create_challenge(&self, email: &str) -> Result<Challenge, ApiError> {
        retrying_read(|| async {
            let context = self.context().await;
            let response = self
                .api
                .credential_create_challenge(context.request(heyl_proto::CreateChallengeRequest {
                    email: email.to_owned(),
                    ..Default::default()
                }))
                .await?;
            map::challenge(&response)
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
        let context = self.context().await;

        // A recovery is the one call that does not identify as
        // CLIENT_TYPE_CLI, because heylogin refuses it if it does. Keyed on the
        // session type rather than plumbed down from the app, so `heyl-app`
        // never has to know a client type exists — and now visible here as a
        // value on the request rather than hidden in the transport.
        let context = if session_type == SessionType::BackupCode {
            context.as_client_type(crate::CLIENT_TYPE_RECOVERY)
        } else {
            context
        };

        let request = context.request(heyl_proto::CreateTokensRequest {
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
        });

        map::tokens(&self.api.credential_create_tokens(request).await?)
    }

    async fn refresh_token(&self) -> Result<String, ApiError> {
        let context = self.context().await;
        let response = self
            .api
            .credential_refresh_token(context.request(heyl_proto::RefreshTokenRequest {}))
            .await?;
        response
            .new_access_token
            .as_ref()
            .map(|t| t.token.clone())
            .ok_or_else(|| ApiError::MalformedResponse {
                what: "RefreshTokenResponse.new_access_token".to_owned(),
            })
    }

    async fn sync(&self) -> Result<SyncSnapshot, ApiError> {
        retrying_read(|| async {
            let context = self.context().await;
            let response = self
                .api
                .sync_sync(context.request(heyl_proto::SyncRequest::default()))
                .await?;
            let update =
                response
                    .sync_update
                    .as_ref()
                    .ok_or_else(|| ApiError::MalformedResponse {
                        what: "SyncResponse.sync_update".to_owned(),
                    })?;
            map::sync_update(update)
        })
        .await
    }

    async fn list_authenticators(&self) -> Result<Vec<Authenticator>, ApiError> {
        retrying_read(|| async {
            let context = self.context().await;
            let response = self
                .api
                .authenticator_list(
                    context.request(heyl_proto::ListAuthenticatorsRequest::default()),
                )
                .await?;
            response
                .authenticators
                .iter()
                .filter_map(|a| map::authenticator(a).transpose())
                .collect()
        })
        .await
    }

    async fn list_commits(&self, vault: VaultId) -> Result<VaultCommits, ApiError> {
        retrying_read(|| async {
            let context = self.context().await;
            let response = self
                .api
                .vault_list_commits(context.request(heyl_proto::ListCommitsRequest {
                    vault_id: vault.to_string(),
                    // Nothing is cached, so a lock the backend omits as "you
                    // already have it" would read as a failure (decision 29).
                    force_locks: true,
                    ..Default::default()
                }))
                .await?;
            map::vault_commits(&response)
        })
        .await
    }
}
