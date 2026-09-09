//! What a call carries besides its message.
//!
//! A gRPC request *is* headers plus a body, so [`Request`] is one value rather
//! than a message and a context threaded separately. That shape also makes a
//! recording one value, and gives the generator, the recorder and a replay stub
//! a single type parameter to work with.
//!
//! **Nothing here is ambient.** `client-type`, `client-id`, `client-version`,
//! `user-agent` and the bearer token are all data on the request. The adapter
//! used to hold the token in an `RwLock` and inject it invisibly; automatic
//! injection at this layer is exactly what stops a raw API from being raw, and
//! the token is not special enough to earn an exception (DESIGN.md §4).
//!
//! The set is closed on purpose. heylogin's metadata is these five headers and
//! nothing else, so a struct says more than a `MetadataMap` would.

/// Who we are, for the life of a client.
///
/// `client_id` is a fresh UUID per instance — the real clients always send one,
/// and a *session* is created for a client, so it is not decoration.
#[derive(Debug, Clone)]
pub struct ClientContext {
    /// `client-id`: a fresh UUID per client instance.
    pub client_id: String,
    /// `client-type`. [`crate::CLIENT_TYPE_CLI`] in every shipped path.
    pub client_type: String,
    /// `client-version`: our own crate version.
    pub client_version: String,
    /// `user-agent`, which M0 confirmed a custom value is accepted for.
    pub user_agent: String,
    /// The bearer token, when we have one.
    pub access_token: Option<String>,
}

impl ClientContext {
    /// Stamp this identity onto a message.
    pub fn request<T>(&self, message: T) -> Request<T> {
        Request {
            message,
            client_id: self.client_id.clone(),
            client_type: self.client_type.clone(),
            client_version: self.client_version.clone(),
            user_agent: self.user_agent.clone(),
            access_token: self.access_token.clone(),
        }
    }

    /// The same identity, presenting a different `client-type`.
    ///
    /// Exists for exactly one caller: see [`crate::CLIENT_TYPE_RECOVERY`].
    /// Being a value on the request rather than a private method on the client
    /// is what makes the one honesty exception visible at its call site.
    #[must_use]
    pub fn as_client_type(&self, client_type: &str) -> Self {
        Self {
            client_type: client_type.to_owned(),
            ..self.clone()
        }
    }

    /// The same identity, carrying this token.
    #[must_use]
    pub fn with_token(&self, access_token: Option<String>) -> Self {
        Self {
            access_token,
            ..self.clone()
        }
    }
}

impl Default for ClientContext {
    fn default() -> Self {
        Self {
            client_id: uuid::Uuid::new_v4().to_string(),
            client_type: crate::CLIENT_TYPE_CLI.to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
            user_agent: format!(
                "heyl/{} (+{})",
                env!("CARGO_PKG_VERSION"),
                env!("CARGO_PKG_REPOSITORY")
            ),
            access_token: None,
        }
    }
}

/// One request: the message, and everything that goes in front of it.
#[derive(Debug, Clone)]
pub struct Request<T> {
    /// The protobuf message.
    pub message: T,
    /// `client-id`.
    pub client_id: String,
    /// `client-type`.
    pub client_type: String,
    /// `client-version`.
    pub client_version: String,
    /// `user-agent`.
    pub user_agent: String,
    /// The bearer token, when the call is authenticated.
    pub access_token: Option<String>,
}

impl<T> Request<T> {
    /// Replace the message, keeping the metadata.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Request<U> {
        Request {
            message: f(self.message),
            client_id: self.client_id,
            client_type: self.client_type,
            client_version: self.client_version,
            user_agent: self.user_agent,
            access_token: self.access_token,
        }
    }
}
