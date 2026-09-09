//! Recovery-code seed derivation.

use heyl_crypto::{
    CryptoError, RecoveryParams, derive_recovery_seed, hash_data,
    recovery::{MAX_ITERATIONS, MAX_MEMORY_COST_KIB, checksum_matches, normalize_code},
};

/// A well-formed code: six dash-separated groups of four digits (§4).
const CODE: &str = "1234-5678-9012-3456-7890-1234";
/// The same code with one digit changed.
const CODE_TYPO: &str = "1234-5678-9012-3456-7890-1235";

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
/// M1 stripped *all* whitespace and kept dashes, so a space-separated code
/// became 24 bare digits and silently derived the wrong seed — reported to the
/// user as "that code is incorrect". It is now refused, and said so.
#[test]
fn a_space_separated_code_is_refused_rather_than_silently_mis_hashed() {
    let err = derive_recovery_seed(
        "1234 5678 9012 3456 7890 1234",
        b"0123456789abcdef",
        params(),
    )
    .expect_err("refused");
    assert!(matches!(err, CryptoError::MalformedRecoveryCode), "{err:?}");
}

/// Surrounding whitespace is a transport artefact and is trimmed. Nothing
/// inside the code is touched — dashes above all.
#[test]
fn normalisation_trims_only_the_edges() {
    assert_eq!(normalize_code("  1234-5678  \n").as_str(), "1234-5678");
    assert_eq!(normalize_code("1234-5678").as_str(), "1234-5678");
    assert_eq!(normalize_code("1234 5678").as_str(), "1234 5678");
}

#[test]
fn derivation_is_deterministic() {
    let a = derive_recovery_seed(CODE, b"0123456789abcdef", params()).expect("derives");
    let b = derive_recovery_seed(CODE, b"0123456789abcdef", params()).expect("derives");
    assert_eq!(a.as_slice(), b.as_slice());
}

#[test]
fn the_salt_changes_the_seed() {
    let a = derive_recovery_seed(CODE, b"0123456789abcdef", params()).expect("derives");
    let b = derive_recovery_seed(CODE, b"fedcba9876543210", params()).expect("derives");
    assert_ne!(a.as_slice(), b.as_slice());
}

/// The checksum lets a mistyped code be rejected locally, before
/// `CreateTokens` is ever called.
#[test]
fn a_mistyped_code_is_caught_offline() {
    let salt = b"0123456789abcdef";
    let real = derive_recovery_seed(CODE, salt, params()).expect("derives");
    let published = hash_data(&*real);

    assert!(checksum_matches(&real, &published));

    let typo = derive_recovery_seed(CODE_TYPO, salt, params()).expect("derives");
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
        derive_recovery_seed(CODE, salt, huge),
        Err(CryptoError::Argon2Params { .. })
    ));

    let slow = RecoveryParams {
        iterations: MAX_ITERATIONS + 1,
        ..params()
    };
    assert!(matches!(
        derive_recovery_seed(CODE, salt, slow),
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
            derive_recovery_seed(CODE, salt, bad),
            Err(CryptoError::Argon2Params { .. })
        ));
    }
}

/// Argon2 requires a salt of at least 8 bytes; a shorter one is a parameter
/// error rather than a panic.
#[test]
fn a_too_short_salt_is_an_error_not_a_panic() {
    assert!(matches!(
        derive_recovery_seed(CODE, b"short", params()),
        Err(CryptoError::Argon2Params { .. })
    ));
}

/// No error may carry the recovery code or any derived material.
#[test]
fn errors_never_carry_the_code() {
    // A well-formed code, so the failure is the salt rather than the shape --
    // and the message must still not echo any of it.
    let err = derive_recovery_seed("9876-5432-1098-7654-3210-9876", b"short", params())
        .expect_err("fails");
    let rendered = err.to_string();
    assert!(!rendered.contains("9876"), "{rendered}");
    assert!(!rendered.contains("5432"), "{rendered}");

    // And the shape error must not illustrate itself with digits either.
    let malformed = derive_recovery_seed("nope", b"0123456789abcdef", params()).expect_err("fails");
    assert!(
        !malformed.to_string().chars().any(|c| c.is_ascii_digit()),
        "{malformed}"
    );
}

// ---------------------------------------------------------------- separators

/// A code arriving through a pipe or an environment variable carries the
/// transport's whitespace, and that much is forgiven.
#[test]
fn surrounding_whitespace_does_not_make_a_code_invalid() {
    for spelling in [
        "  1234-5678-9012-3456-7890-1234",
        "1234-5678-9012-3456-7890-1234\n",
        "\t1234-5678-9012-3456-7890-1234  \r\n",
    ] {
        derive_recovery_seed(spelling, b"0123456789abcdef", params())
            .unwrap_or_else(|e| panic!("{spelling:?} should be accepted: {e}"));
    }
}

/// heylogin defines exactly one spelling, so anything else is refused rather
/// than reshaped — and refused *distinctly*, so the user is told to retype it
/// rather than told their code is wrong.
#[test]
fn a_non_canonical_code_is_refused_before_it_is_hashed() {
    for bad in [
        "123456789012345678901234",       // no separators at all
        "1234 5678 9012 3456 7890 1234",  // spaces instead of dashes
        "1234-5678-9012-3456-7890",       // five groups
        "1234-5678-9012-3456-7890-12345", // a group of five
        "1234_5678_9012_3456_7890_1234",  // the wrong separator
        "abcd-5678-9012-3456-7890-1234",  // not digits
    ] {
        let err = derive_recovery_seed(bad, b"0123456789abcdef", params()).expect_err("refused");
        assert!(
            matches!(err, CryptoError::MalformedRecoveryCode),
            "{bad:?} gave {err:?}"
        );
    }
}

/// The dashes must survive normalisation, because they are part of the
/// material heylogin hashes (§4) — not decoration.
///
/// This is the guard against "simplifying" `normalize_code` into stripping
/// every separator. That change compiles, reads as tidier, and derives a
/// completely wrong seed for every account.
#[test]
fn the_canonical_form_is_a_fixed_point_and_keeps_its_dashes() {
    let dashed = "1111-2222-3333-4444-5555-6666";
    let normalised = normalize_code(dashed);
    assert_eq!(normalised.as_str(), dashed);
    assert_eq!(
        normalised.matches('-').count(),
        5,
        "the dashes are hashed; stripping them changes every derived seed"
    );
}
