//! The gRPC-Web adapter: the **only** crate that sees `heyl-proto`.
//!
//! gRPC-Web is the sole protocol the backend serves — probed directly at M0.
//! `application/proto` and `application/connect+proto` return 415, and
//! `application/grpc` is rejected at the edge with 505, so there is no
//! transport choice to make and no escape hatch worth offering (DESIGN.md §4).
//!
//! # Two layers, and why
//!
//! ```text
//! heyl-app ──uses──► heyl_ports::HeylApi      domain types, use-case shaped
//!                         ▲
//!                    DomainApi<A>             mapping + policy; map.rs lives here
//!                         ▲
//!                    HeyloginApi              prost types, 123 methods, generated
//!                         ▲
//!                    GrpcClient               transport, stateless
//! ```
//!
//! [`HeyloginApi`] is heylogin's surface as it actually is: one method per RPC,
//! generated from `descriptors/heylogin.binpb`, taking a [`Request`] that
//! carries its own metadata and token. Nothing is implicit at that layer, which
//! is what makes it worth recording and replaying.
//!
//! [`DomainApi`] is where a use case's view is assembled: the wire→domain
//! mapping in [`map`], and the policy that does not belong in a raw
//! layer — retrying an idempotent read, and the one call that must not identify
//! as `CLIENT_TYPE_CLI`.
//!
//! # Request metadata
//!
//! `client-type` is mandatory and validated against the `ClientType` enum: omit
//! it, or send a value outside the enum, and every call fails with
//! `grpc-status: 13`. `CLIENT_TYPE_CLI = 400` is accepted, so we identify
//! honestly rather than impersonating the web client.

pub mod client;
pub mod domain;
pub mod map;
pub mod request;
pub mod status;

#[cfg(feature = "api")]
pub mod corpus;
#[cfg(feature = "api")]
pub mod json;
#[cfg(feature = "server")]
pub mod server;

pub use client::{GrpcClient, GrpcConfig, Transportable};
pub use domain::DomainApi;
pub use request::{ClientContext, Request};
pub use status::{DomainErrorDetail, decode_details, decode_details_base64, to_api_error};

use heyl_ports::ApiError;

/// A server-streaming response.
///
/// Boxed rather than `tonic::Streaming` so a replay stub can yield recorded
/// messages without owning a transport. Exactly one RPC in the schema needs
/// it — `domain.SyncService/StreamingSync`.
pub type MessageStream<T> =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<T, ApiError>> + Send>>;

/// The generated surface: the [`HeyloginApi`] trait, its implementation over
/// [`GrpcClient`], `METHODS`, and — under the `api` feature — the dispatch.
///
/// Isolated in its own module for the same reason `heyl-proto` isolates its
/// output: generated code is not ours to lint. 123 near-identical methods trip
/// `too_many_lines` and `needless_borrow` on a scale that would mean either
/// contorting the generator to satisfy a style rule or silencing the rule for
/// hand-written code too. The workspace's real invariants still apply here —
/// `unsafe_code = "forbid"` among them.
#[allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unreachable_pub,
    rustdoc::all
)]
mod generated {
    use heyl_ports::ApiError;

    use crate::{
        Rpc,
        client::{GrpcClient, Transportable},
    };

    include!(concat!(env!("OUT_DIR"), "/api.rs"));

    #[cfg(feature = "api")]
    include!(concat!(env!("OUT_DIR"), "/dispatch.rs"));

    #[cfg(feature = "api")]
    include!(concat!(env!("OUT_DIR"), "/serve.rs"));
}

pub use generated::{HeyloginApi, METHODS};

#[cfg(feature = "api")]
pub use corpus::{Meta, Record, RecordedApi, RecordingApi, Scenario, Step};
#[cfg(feature = "api")]
pub use generated::{dispatch, serve};
#[cfg(feature = "server")]
pub use server::Server;

/// One RPC in the schema.
///
/// The catalogue exists so tooling can walk heylogin's surface without a
/// second source of truth about what it contains — a migration needs to know
/// which message a recorded response is, and only the descriptor set knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rpc {
    /// The gRPC method path, e.g. `/domain.SyncService/Sync`.
    pub path: &'static str,
    /// The [`HeyloginApi`] method serving it.
    pub method: &'static str,
    /// The request message's protobuf type name.
    pub request_type: &'static str,
    /// The response message's protobuf type name.
    pub response_type: &'static str,
    /// Whether the response is a stream.
    pub streaming: bool,
}

impl Rpc {
    /// Find an RPC by its gRPC path.
    #[must_use]
    pub fn by_path(path: &str) -> Option<Self> {
        let wanted = path.trim_start_matches('/');
        METHODS
            .into_iter()
            .find(|rpc| rpc.path.trim_start_matches('/') == wanted)
    }
}

/// A `heyl api` call that could not be made.
#[cfg(feature = "api")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DispatchError {
    /// No RPC in the schema has this path.
    #[error("no such method: {method}")]
    UnknownMethod {
        /// What was asked for.
        method: String,
    },

    /// The request or response could not be transcoded.
    #[error(transparent)]
    Json(#[from] json::JsonError),

    /// The call itself failed.
    #[error(transparent)]
    Api(#[from] ApiError),
}

/// The production endpoint.
pub const DEFAULT_ENDPOINT: &str = "https://heylogin.app/api/v1";

/// `CLIENT_TYPE_CLI`, the value M0 confirmed the backend accepts.
///
/// Sent on every call but one — see [`CLIENT_TYPE_RECOVERY`].
pub const CLIENT_TYPE_CLI: &str = "400";

/// `CLIENT_TYPE_AND`, sent **only** on a recovery's `CreateTokens`.
///
/// heylogin refuses to mint a session from a `BACKUP_CODE` authenticator for
/// any browser-family client type: `CLIENT_TYPE_CLI` (400), `CLIENT_TYPE_WEB`
/// (100) and `CLIENT_TYPE_EXT` (300) all return `DomainError 30460
/// INVALID_SESSION_TYPE`, for every value of `session_type` including the
/// proto3 zero. The mobile types are accepted. No shipped heylogin surface
/// offers recovery login either — it is reachable in `client-core` only from
/// their own debug harness on `ClientType.TEST`.
///
/// DESIGN.md §4 commits to identifying honestly, and this is the one recorded
/// exception. It is scoped as narrowly as the protocol allows: a single call,
/// on a command the user has explicitly confirmed, which exists because their
/// phone is gone. Every other request this client makes says `400`.
///
/// Since the token and identity are data on a [`Request`], this exception is
/// now visible at its call site in [`DomainApi`] rather than buried in the
/// adapter.
pub const CLIENT_TYPE_RECOVERY: &str = "200";
