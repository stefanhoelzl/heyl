//! Errors the ports raise.
//!
//! No variant ever carries key, plaintext or ciphertext bytes — the same rule
//! `heyl-crypto` and `heyl-domain` follow (DESIGN.md §4).

/// A failure inside an adapter that is not the backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PortError {
    /// The keychain, terminal or OS refused or was unavailable.
    #[error("{operation} failed: {reason}")]
    Unavailable {
        /// What was attempted.
        operation: &'static str,
        /// Why it failed, as the platform reported it.
        reason: String,
    },

    /// The item was not there.
    #[error("{what} not found")]
    NotFound {
        /// Which item.
        what: &'static str,
    },

    /// A stored value could not be interpreted — wrong length, bad encoding.
    #[error("stored {what} is malformed")]
    Malformed {
        /// Which item.
        what: &'static str,
    },
}

/// A failure talking to heylogin.
///
/// The backend distinguishes absent credentials (gRPC status 16, `DomainError`
/// 30100) from rejected ones (status 7, 30420), and so do we: one means "log
/// in", the other means "your token is no longer valid" (DESIGN.md §4).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiError {
    /// No credentials were presented.
    #[error("not authenticated")]
    Unauthenticated {
        /// heylogin's `DomainError.code`, when it sent one.
        domain_code: Option<i32>,
    },

    /// Credentials were presented and refused.
    #[error("permission denied")]
    PermissionDenied {
        /// heylogin's `DomainError.code`, when it sent one.
        domain_code: Option<i32>,
    },

    /// The backend rejected the request itself.
    ///
    /// `DomainError` 10400 `BAD_REQUEST` is what a missing or invalid
    /// `client-type` produces, which is worth recognising because it is a
    /// client bug rather than a user problem (M0).
    #[error("backend rejected the request: {message}")]
    BadRequest {
        /// heylogin's `DomainError.code`, when it sent one.
        domain_code: Option<i32>,
        /// `grpc-message`, or the domain error's user-facing title.
        message: String,
    },

    /// The backend says this client build is too old to be served.
    #[error("this client version is no longer accepted")]
    ClientOutdated,

    /// Anything else the backend returned.
    #[error("backend error ({status}): {message}")]
    Backend {
        /// The gRPC status code.
        status: i32,
        /// heylogin's `DomainError.code`, when it sent one.
        domain_code: Option<i32>,
        /// `grpc-message`, or the domain error's user-facing title.
        message: String,
    },

    /// The request never reached the backend, or the response was unreadable.
    #[error("transport failure: {reason}")]
    Transport {
        /// What went wrong at the transport layer.
        reason: String,
    },

    /// The backend's response did not contain what the schema requires.
    ///
    /// Distinct from [`ApiError::Transport`] because it means our mapping and
    /// heylogin's behaviour disagree, which is a bug to investigate rather than
    /// a network blip to retry.
    #[error("backend response is missing {what}")]
    MalformedResponse {
        /// Which field or invariant was violated.
        what: String,
    },
}
