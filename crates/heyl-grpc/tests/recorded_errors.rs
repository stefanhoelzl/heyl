//! M0's recorded exchanges, replayed against the error decoder.
//!
//! These are the four fixtures in `tests/fixtures/protocol/`, captured against
//! `https://heylogin.app/api/v1` during the M0 spike. They are the reason the
//! error taxonomy exists in the shape it does, and replaying them here means a
//! change to the decoding is caught without an account, a network, or a
//! credential (DESIGN.md §6).
//!
//! The fixtures are parsed rather than transcribed, so the assertions cannot
//! drift from the recording they claim to check.

use heyl_grpc::{decode_details_base64, to_api_error};
use heyl_ports::ApiError;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/protocol");

/// Pull one header value out of a recorded `.http` exchange.
fn header(fixture: &str, name: &str) -> Option<String> {
    let raw = std::fs::read_to_string(format!("{FIXTURES}/{fixture}.http"))
        .unwrap_or_else(|e| panic!("fixture {fixture}.http is missing: {e}"));
    let response = raw.split("### response").nth(1)?;
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().eq_ignore_ascii_case(name)).then(|| value.trim().to_owned())
    })
}

fn status_from(fixture: &str) -> tonic::Status {
    let code: i32 = header(fixture, "grpc-status")
        .unwrap_or_else(|| panic!("{fixture} has no grpc-status"))
        .parse()
        .expect("grpc-status is a number");
    let message = header(fixture, "grpc-message").unwrap_or_default();

    // Built from a header map, exactly as tonic does off the wire.
    //
    // An earlier version assembled the Status by hand with `insert_bin`, which
    // put the details somewhere the real client never reads them: the tests
    // passed while the shipped path discarded every DomainError code.
    let mut headers = http::HeaderMap::new();
    headers.insert("grpc-status", code.to_string().parse().expect("valid"));
    headers.insert(
        "grpc-message",
        message
            .parse()
            .unwrap_or_else(|_| "".parse().expect("valid")),
    );
    if let Some(details) = header(fixture, "grpc-status-details-bin") {
        headers.insert(
            "grpc-status-details-bin",
            details.parse().expect("valid header value"),
        );
    }
    tonic::Status::from_header_map(&headers).expect("a status the wire could produce")
}

/// `sync-unauthenticated`: a valid `client-type` but no `authorization`.
/// Status 16, `DomainError` 30100 — the backend cannot identify the client.
#[test]
fn absent_credentials_decode_to_unauthenticated() {
    let status = status_from("sync-unauthenticated");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    let detail = decode_details_base64(
        &header("sync-unauthenticated", "grpc-status-details-bin")
            .expect("fixture carries details"),
    )
    .expect("details decode with the schema's own types");

    assert_eq!(detail.code, 30100);
    assert_eq!(detail.user_title, "Could not identify client");

    assert!(
        matches!(
            to_api_error(&status),
            ApiError::Unauthenticated {
                domain_code: Some(30100)
            }
        ),
        "{:?}",
        to_api_error(&status)
    );
}

/// `sync-bad-token`: credentials presented and refused. The backend
/// distinguishes this from absent credentials, and so must we — one means
/// "log in", the other means "your token is no longer valid".
#[test]
fn rejected_credentials_are_distinguished_from_absent_ones() {
    let rejected = to_api_error(&status_from("sync-bad-token"));
    let absent = to_api_error(&status_from("sync-unauthenticated"));

    assert!(
        matches!(rejected, ApiError::PermissionDenied { .. }),
        "expected PermissionDenied, got {rejected:?}"
    );
    assert!(
        matches!(absent, ApiError::Unauthenticated { .. }),
        "expected Unauthenticated, got {absent:?}"
    );
}

/// `missing-client-type`: `client-type` is mandatory and enum-validated.
/// This is a client bug, not a user problem, so it maps to `BadRequest`.
#[test]
fn an_invalid_client_type_is_reported_as_a_bad_request() {
    let err = to_api_error(&status_from("missing-client-type"));
    assert!(
        matches!(
            err,
            ApiError::BadRequest {
                domain_code: Some(10400),
                ..
            }
        ),
        "{err:?}"
    );
}

/// A response with no details at all is still a perfectly good error: failing
/// to parse the *explanation* must never mask the failure it explains.
#[test]
fn a_status_without_details_still_maps() {
    let status = tonic::Status::new(tonic::Code::Unavailable, "backend is down");
    let err = to_api_error(&status);
    assert!(
        matches!(
            err,
            ApiError::Backend {
                domain_code: None,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn undecodable_details_are_ignored_rather_than_fatal() {
    assert!(decode_details_base64("not base64 at all !!!").is_none());
    assert!(decode_details_base64("").is_none());
}
