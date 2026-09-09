//! `secretInfo` parsing (DESIGN.md §4 — parsed in the domain, not the transport).
//!
//! These run with no `tonic` in the graph, which is the point of putting the
//! parser here: it is a heylogin domain structure, not a wire format.

use heyl_crypto::recovery::MAX_MEMORY_COST_KIB;
use heyl_domain::{AuthenticatorSecret, AuthenticatorType, DomainError};

/// The shape `RecoverySecretInfo` actually has (§4).
const RECOVERY: &str = r#"{
  "checksum": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
  "recoveryParameters": {
    "saltBase64": "c2FsdHktc2FsdC0xMjM0",
    "iterations": 3,
    "memoryCost": 65536,
    "parallelism": 4
  }
}"#;

#[test]
fn a_backup_code_secret_info_parses_into_argon2_parameters() {
    let secret =
        AuthenticatorSecret::parse(AuthenticatorType::BackupCode, RECOVERY).expect("parses");
    let AuthenticatorSecret::Recovery(recovery) = secret else {
        panic!("expected a recovery secret, got {secret:?}");
    };

    assert_eq!(recovery.checksum.len(), 32, "checksum is SHA512(seed)[:32]");
    assert_eq!(recovery.checksum[0], 0x00);
    assert_eq!(recovery.checksum[31], 0x1f);
    assert_eq!(recovery.salt, b"salty-salt-1234");
    assert_eq!(recovery.params.memory_cost_kib, 65536);
    assert_eq!(recovery.params.iterations, 3);
    assert_eq!(recovery.params.parallelism, 4);
}

/// The parameters are attacker-influenced if the backend is hostile, so they
/// are bounded at the boundary rather than on the way into Argon2.
#[test]
fn a_hostile_memory_cost_is_refused_at_the_parse_rather_than_at_the_hash() {
    let hostile = RECOVERY.replace("65536", &(u64::from(MAX_MEMORY_COST_KIB) + 1).to_string());
    let err =
        AuthenticatorSecret::parse(AuthenticatorType::BackupCode, &hostile).expect_err("bounded");
    assert!(matches!(err, DomainError::Crypto(_)), "{err:?}");
}

/// `SESSION_UNLOCK` and `ORGANIZATION_SERVICE` show up in a normal listing.
/// They must not fail the parse of the whole response.
#[test]
fn an_unmodelled_authenticator_type_is_opaque_rather_than_an_error() {
    let secret = AuthenticatorSecret::parse(AuthenticatorType::SessionUnlock, r#"{"anything": 1}"#)
        .expect("tolerated");
    assert_eq!(secret, AuthenticatorSecret::Opaque);
}

#[test]
fn an_absent_secret_info_is_opaque() {
    // CreateChallenge returns an empty string for types that publish nothing.
    let secret = AuthenticatorSecret::parse(AuthenticatorType::Push, "").expect("tolerated");
    assert_eq!(secret, AuthenticatorSecret::Opaque);
}

#[test]
fn a_malformed_recovery_payload_names_the_field_and_never_the_value() {
    let err = AuthenticatorSecret::parse(AuthenticatorType::BackupCode, r#"{"checksum": 7}"#)
        .expect_err("rejected");
    let rendered = err.to_string();
    assert!(
        matches!(err, DomainError::MalformedSecretInfo { .. }),
        "{err:?}"
    );
    assert!(
        !rendered.contains('7'),
        "must not echo the payload: {rendered}"
    );
}

/// A DUMMY authenticator's `secretInfo` is a plaintext seed. We parse it —
/// it is a real backend-supported flow — but nothing must ever print it.
#[test]
fn a_dummy_secret_info_yields_a_seed_that_does_not_render() {
    let seed_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let secret = AuthenticatorSecret::parse(
        AuthenticatorType::Dummy,
        &format!(r#"{{"seed": "{seed_b64}"}}"#),
    )
    .expect("parses");

    let AuthenticatorSecret::Dummy(seed) = &secret else {
        panic!("expected a dummy seed, got {secret:?}");
    };
    assert_eq!(seed.expose_secret()[0], 0x00);
    assert_eq!(seed.expose_secret()[31], 0x1f);
    assert!(
        !format!("{secret:?}").contains("0, 1, 2"),
        "Debug must redact the seed: {secret:?}"
    );
}
