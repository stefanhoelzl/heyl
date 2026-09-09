//! The generated surface is the whole point of this crate, so it is pinned.
//!
//! M0 measured 19 services and 123 methods generated from
//! `descriptors/heylogin.binpb` with zero warnings. If a descriptor refresh
//! silently drops a service, that is a schema regression rather than a code
//! change, and nothing else in the workspace would notice.

use heyl_proto as proto;

/// The messages M2 actually puts on the wire (decision 13's six methods).
#[test]
fn the_m2_request_and_response_types_exist_and_default() {
    let _ = proto::CreateChallengeRequest::default();
    let _ = proto::CreateChallengeResponse::default();
    let _ = proto::CreateTokensRequest::default();
    let _ = proto::CreateTokensResponse::default();
    let _ = proto::RefreshTokenRequest::default();
    let _ = proto::SyncRequest::default();
    let _ = proto::ListAuthenticatorsRequest::default();
    let _ = proto::ListCommitsRequest::default();
    let _ = proto::SyncUpdate::default();
    let _ = proto::VaultProfileLock::default();
    let _ = proto::ProfileAuthenticatorLock::default();
}

/// `client-type` is mandatory and validated against this enum: omit it, or send
/// 999, and every call returns `grpc-status: 13` (M0, DESIGN.md §4). 400 is
/// accepted, so we identify honestly rather than impersonating the web client.
#[test]
fn the_cli_client_type_is_the_value_m0_probed() {
    assert_eq!(proto::ClientType::Cli as i32, 400);
}

/// The recovery-code login path sends this session type (§5).
#[test]
fn the_backup_code_session_type_is_stable() {
    assert_eq!(proto::SessionType::BackupCode as i32, 4);
}

/// Authenticator discriminants are load-bearing: `heyl-grpc` maps them onto
/// `heyl_domain::AuthenticatorType` by value, and `reserved 5` means they are
/// not contiguous.
#[test]
fn authenticator_type_discriminants_match_the_spec_table() {
    assert_eq!(proto::AuthenticatorType::Push as i32, 1);
    assert_eq!(proto::AuthenticatorType::BackupCode as i32, 2);
    assert_eq!(proto::AuthenticatorType::BackupOs as i32, 3);
    assert_eq!(proto::AuthenticatorType::Dummy as i32, 4);
    assert_eq!(proto::AuthenticatorType::SessionUnlock as i32, 6);
    assert_eq!(proto::AuthenticatorType::Webauthn as i32, 7);
    assert_eq!(proto::AuthenticatorType::OrganizationService as i32, 8);
}

/// `domain.Status` is structurally identical to `google.rpc.Status`, which is
/// what lets the schema decode its own `grpc-status-details-bin` envelope with
/// no extra dependency (DESIGN.md §4).
#[test]
fn the_error_envelope_decodes_with_the_schemas_own_types() {
    use prost::Message as _;

    let detail = proto::DomainError {
        code: 30100,
        ..Default::default()
    };
    let status = proto::RpcStatus {
        code: 16,
        message: "unauthenticated".to_owned(),
        details: vec![prost_types::Any {
            type_url: "type.googleapis.com/domain.DomainError".to_owned(),
            value: detail.encode_to_vec(),
        }],
    };

    let round_tripped = proto::RpcStatus::decode(&*status.encode_to_vec()).expect("decodes");
    assert_eq!(round_tripped.code, 16);
    let any = &round_tripped.details[0];
    assert!(any.type_url.ends_with("domain.DomainError"));
    assert_eq!(
        proto::DomainError::decode(&*any.value)
            .expect("decodes")
            .code,
        30100
    );
}
