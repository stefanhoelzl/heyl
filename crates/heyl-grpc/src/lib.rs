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

pub use client::{GrpcClient, GrpcConfig, LongPollChallenge};
pub use status::{DomainErrorDetail, decode_details, decode_details_base64, to_api_error};

/// The production endpoint.
pub const DEFAULT_ENDPOINT: &str = "https://heylogin.app/api/v1";

/// `CLIENT_TYPE_CLI`, the value M0 confirmed the backend accepts.
pub const CLIENT_TYPE_CLI: &str = "400";
