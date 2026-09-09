//! The gRPC-Web adapter: the **only** crate that sees `heyl-proto`.
//!
//! gRPC-Web is the sole protocol the backend serves — probed directly at M0.
//! `application/proto` and `application/connect+proto` return 415, and
//! `application/grpc` is rejected at the edge with 505, so there is no
//! transport choice to make and no escape hatch worth offering (DESIGN.md §4).
//!
//! # Request metadata
//!
//! `client-type` is mandatory and validated against the `ClientType` enum: omit
//! it, or send a value outside the enum, and every call fails with
//! `grpc-status: 13`. `CLIENT_TYPE_CLI = 400` is accepted, so we identify
//! honestly rather than impersonating the web client.

pub mod client;
pub mod map;
pub mod status;

pub use client::{GrpcClient, GrpcConfig, LongPollChallenge, Transportable};
pub use status::{DomainErrorDetail, decode_details, decode_details_base64, to_api_error};

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
pub const CLIENT_TYPE_RECOVERY: &str = "200";
