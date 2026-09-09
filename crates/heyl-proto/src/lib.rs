//! Generated heylogin protobuf types and gRPC clients.
//!
//! Everything here is produced at build time from
//! `descriptors/heylogin.binpb` — 19 services and 123 methods, package
//! `domain`. Nothing is hand-written and nothing is committed.
//!
//! **This crate is the boundary.** `heyl-grpc` is the only crate permitted to
//! depend on it (DESIGN.md §4), so no generated type ever reaches `heyl-app`,
//! `heyl-domain` or `heyl-crypto`. That is what lets the core be tested
//! against a fake `HeylApi` with no transport in the graph.

// Generated code is not ours to lint: it carries no docs on its items and
// trips a number of pedantic rules. The workspace lints still apply to
// everything else in this crate, including `unsafe_code = "forbid"`.
#[allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unreachable_pub,
    rustdoc::all
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/domain.rs"));
}

pub use generated::*;

/// `google.rpc.Status`, for decoding `grpc-status-details-bin`.
///
/// heylogin's own `domain.Status` in `errors.proto` is structurally identical
/// to `google.rpc.Status`, so the schema decodes its own error envelope and we
/// need no extra dependency (DESIGN.md §4).
pub use generated::Status as RpcStatus;
