//! Recovery-code seed derivation.

use heyl_crypto::{
    CryptoError, RecoveryParams, derive_recovery_seed, hash_data,
    recovery::{MAX_ITERATIONS, MAX_MEMORY_COST_KIB, checksum_matches, normalize_code},
};

/// Cheap parameters. Real ones come from the server.
fn params() -> RecoveryParams {
    RecoveryParams {
        memory_cost_kib: 64,
        iterations: 1,
        parallelism: 1,
    }
}

/// heylogin hashes the code **with its dashes**. Stripping them, as a
/// well-meaning normaliser might, derives a completely different seed and
/// fails login with nothing pointing at the cause.
#[test]
fn dashes_are_part_of_the_code() {
    let with = derive_recovery_seed(
        "1234-5678-9012-3456-7890-1234",
        b"0123456789abcdef",
        params(),
    )
    .expect("derives");
    let without = derive_recovery_seed("123456789012345678901234", b"0123456789abcdef", params())
        .expect("derives");
    assert_ne!(with.as_slice(), without.as_slice());
}

/// Whitespace and case are paste artefacts; dashes are not.
#[test]
fn normalisation_drops_whitespace_and_keeps_dashes() {
    assert_eq!(
        normalize_code(" 1234-5678 \n9012 ").as_str(),
        "1234-56789012"
    );
    assert_eq!(normalize_code("1234-5678").as_str(), "1234-5678");
}

#[test]
fn derivation_is_deterministic() {
    let a = derive_recovery_seed("1234-5678", b"0123456789abcdef", params()).expect("derives");
    let b = derive_recovery_seed("1234-5678", b"0123456789abcdef", params()).expect("derives");
    assert_eq!(a.as_slice(), b.as_slice());
}

#[test]
fn the_salt_changes_the_seed() {
    let a = derive_recovery_seed("1234-5678", b"0123456789abcdef", params()).expect("derives");
    let b = derive_recovery_seed("1234-5678", b"fedcba9876543210", params()).expect("derives");
    assert_ne!(a.as_slice(), b.as_slice());
}

/// The checksum lets a mistyped code be rejected locally, before
/// `CreateTokens` is ever called.
#[test]
fn a_mistyped_code_is_caught_offline() {
    let salt = b"0123456789abcdef";
    let real = derive_recovery_seed("1234-5678-9012", salt, params()).expect("derives");
    let published = hash_data(&*real);

    assert!(checksum_matches(&real, &published));

    let typo = derive_recovery_seed("1234-5678-9013", salt, params()).expect("derives");
    assert!(!checksum_matches(&typo, &published));
}

#[test]
fn a_truncated_checksum_does_not_match() {
    let seed = [7u8; 32];
    let published = hash_data(&seed);
    assert!(!checksum_matches(&seed, &published[..16]));
}

/// The parameters arrive from the server, so they are attacker-influenced if
/// the backend is hostile. A login must not be turnable into an OOM.
#[test]
fn absurd_server_parameters_are_refused() {
    let salt = b"0123456789abcdef";

    let huge = RecoveryParams {
        memory_cost_kib: MAX_MEMORY_COST_KIB + 1,
        ..params()
    };
    assert!(matches!(
        derive_recovery_seed("1234", salt, huge),
        Err(CryptoError::Argon2Params { .. })
    ));

    let slow = RecoveryParams {
        iterations: MAX_ITERATIONS + 1,
        ..params()
    };
    assert!(matches!(
        derive_recovery_seed("1234", salt, slow),
        Err(CryptoError::Argon2Params { .. })
    ));

    for bad in [
        RecoveryParams {
            iterations: 0,
            ..params()
        },
        RecoveryParams {
            parallelism: 0,
            ..params()
        },
    ] {
        assert!(matches!(
            derive_recovery_seed("1234", salt, bad),
            Err(CryptoError::Argon2Params { .. })
        ));
    }
}

/// Argon2 requires a salt of at least 8 bytes; a shorter one is a parameter
/// error rather than a panic.
#[test]
fn a_too_short_salt_is_an_error_not_a_panic() {
    assert!(matches!(
        derive_recovery_seed("1234", b"short", params()),
        Err(CryptoError::Argon2Params { .. })
    ));
}

/// No error may carry the recovery code or any derived material.
#[test]
fn errors_never_carry_the_code() {
    let err = derive_recovery_seed("1234-5678-secret", b"short", params()).expect_err("fails");
    let rendered = err.to_string();
    assert!(!rendered.contains("secret"), "{rendered}");
    assert!(!rendered.contains("1234"), "{rendered}");
}
