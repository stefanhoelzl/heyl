//! Decoding heylogin's error envelope.
//!
//! Responses are trailers-only, carrying `grpc-status`, `grpc-message` and
//! `grpc-status-details-bin` — base64 (standard alphabet, **unpadded**) of a
//! `google.rpc.Status` whose `details[0]` is an `Any` wrapping
//! `domain.DomainError { code, user_title, user_detail, request_id }`.
//!
//! `domain.Status` in `errors.proto` is structurally identical to
//! `google.rpc.Status`, so the schema decodes its own envelope with no extra
//! dependency (M0; DESIGN.md §4).

use base64::Engine as _;
use heyl_ports::ApiError;
use prost::Message as _;

/// The metadata key the details ride in.
pub const DETAILS_KEY: &str = "grpc-status-details-bin";

/// heylogin's `DomainError` codes that mean something specific to us.
mod code {
    /// No credentials presented at all.
    pub const MISSING_CREDENTIALS: i32 = 30100;
    /// Credentials presented and rejected.
    pub const REJECTED_CREDENTIALS: i32 = 30420;
    /// The request itself was malformed — e.g. a missing `client-type`.
    pub const BAD_REQUEST: i32 = 10400;
}

/// The parts of `DomainError` we act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainErrorDetail {
    /// heylogin's own error code.
    pub code: i32,
    /// The user-facing title. Never contains secret material.
    pub user_title: String,
}

/// Pull a `DomainError` out of the raw `google.rpc.Status` protobuf.
///
/// Returns [`None`] rather than erroring: a response without decodable details
/// is still a perfectly good error, and failing to parse the *explanation* must
/// never mask the failure it explains.
#[must_use]
pub fn decode_details(bytes: &[u8]) -> Option<DomainErrorDetail> {
    let status = heyl_proto::RpcStatus::decode(bytes).ok()?;
    status.details.iter().find_map(|any| {
        any.type_url
            .ends_with("domain.DomainError")
            .then(|| heyl_proto::DomainError::decode(&*any.value).ok())
            .flatten()
            .map(|e| DomainErrorDetail {
                code: e.code,
                user_title: e.user_title,
            })
    })
}

/// Pull a `DomainError` out of a base64 `grpc-status-details-bin` header value.
///
/// `tonic` decodes binary metadata itself, so [`to_api_error`] never needs
/// this. It exists for the recorded fixtures, which hold the header verbatim,
/// and for diagnosing a raw exchange by hand.
///
/// The backend sends the standard alphabet unpadded; both are accepted, since
/// nothing guarantees it stays that way.
#[must_use]
pub fn decode_details_base64(raw: &str) -> Option<DomainErrorDetail> {
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
        .ok()?;
    decode_details(&bytes)
}

/// Map a `tonic::Status` onto the port's error taxonomy.
///
/// The backend distinguishes absent credentials (status 16, `DomainError`
/// 30100) from rejected ones (status 7, 30420); so do we, because one means
/// "log in" and the other means "your token is no longer valid".
#[must_use]
pub fn to_api_error(status: &tonic::Status) -> ApiError {
    // `grpc-status-details-bin` ends in `-bin`, so tonic classifies it as
    // binary metadata and base64-decodes it for us.
    let detail = status
        .metadata()
        .get_bin(DETAILS_KEY)
        .and_then(|v| v.to_bytes().ok())
        .and_then(|bytes| decode_details(&bytes));
    let domain_code = detail.as_ref().map(|d| d.code);

    // Prefer heylogin's own user-facing title: `grpc-message` is often just
    // "missing credentials", while the detail says which check failed.
    let message = detail
        .as_ref()
        .filter(|d| !d.user_title.is_empty())
        .map_or_else(|| status.message().to_owned(), |d| d.user_title.clone());

    match (status.code(), domain_code) {
        (_, Some(code::MISSING_CREDENTIALS)) | (tonic::Code::Unauthenticated, _) => {
            ApiError::Unauthenticated { domain_code }
        }
        (_, Some(code::REJECTED_CREDENTIALS)) | (tonic::Code::PermissionDenied, _) => {
            ApiError::PermissionDenied { domain_code }
        }
        (_, Some(code::BAD_REQUEST)) => ApiError::BadRequest {
            domain_code,
            message,
        },
        (status, _) => ApiError::Backend {
            status: status.into(),
            domain_code,
            message,
        },
    }
}
