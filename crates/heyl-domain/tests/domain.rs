//! Domain rules: the timestamp format, the key-generation guard, and the
//! chain's refusals.

use heyl_crypto::{EncryptionPrivateKey, Nonce, SecretSalt, Seed};
use heyl_domain::{
    AuthenticatorId, AuthenticatorKeys, AuthenticatorType, DomainError, HighSecurity,
    KeyGenerationId, ProfileAuthenticatorLock, ProfileId, ProfileSeed, Storable, Timestamp,
    VaultProfileLock, VaultType,
};

fn auth_id(n: u8) -> AuthenticatorId {
    AuthenticatorId::parse(&format!("00000000-0000-4000-8000-0000000000{n:02}")).expect("valid")
}

fn fixture_profile() -> ProfileId {
    ProfileId::parse("00000000-0000-4000-8000-0000000000aa").expect("valid")
}

// ---------------------------------------------------------------- timestamps

/// heymerge resolves conflicts with `leftUpdateTime > rightUpdateTime`, a
/// *lexicographic string comparison*. So the rendering must match
/// `Date.toISOString()` byte for byte: UTC, literal `Z`, exactly three
/// fractional digits — always, including when they are zero.
#[test]
fn timestamps_render_exactly_like_date_to_isostring() {
    let cases = [
        (0_i64, "1970-01-01T00:00:00.000Z"),
        (1_i64, "1970-01-01T00:00:00.001Z"),
        (1_000_i64, "1970-01-01T00:00:01.000Z"),
        (1_757_376_000_000_i64, "2025-09-09T00:00:00.000Z"),
        (1_757_376_000_123_i64, "2025-09-09T00:00:00.123Z"),
        // A whole number of seconds must still print three digits, not none.
        (1_757_376_060_000_i64, "2025-09-09T00:01:00.000Z"),
    ];
    for (ms, expected) in cases {
        let ts = Timestamp::from_millisecond(ms).expect("in range");
        assert_eq!(ts.to_string(), expected, "for {ms} ms");
        assert_eq!(ts.to_string().len(), 24, "always 24 characters");
    }
}

/// The property the format exists to protect: for any two instants, comparing
/// the *rendered strings* must agree with comparing the instants. If that ever
/// breaks, merges silently resolve the wrong way.
#[test]
fn lexicographic_string_order_matches_chronological_order() {
    let samples: Vec<Timestamp> = [
        0_i64,
        1,
        999,
        1_000,
        59_999,
        60_000,
        1_757_376_000_000,
        1_757_376_000_001,
        4_102_444_800_000, // 2100-01-01
    ]
    .into_iter()
    .map(|ms| Timestamp::from_millisecond(ms).expect("in range"))
    .collect();

    for a in &samples {
        for b in &samples {
            let by_instant = a.truncate_to_millis().cmp(&b.truncate_to_millis());
            let by_string = a.to_string().cmp(&b.to_string());
            assert_eq!(by_instant, by_string, "{a} vs {b}");
        }
    }
}

#[test]
fn timestamps_round_trip_through_their_own_rendering() {
    let ts = Timestamp::from_millisecond(1_757_376_000_123).expect("in range");
    assert_eq!(Timestamp::parse(&ts.to_string()).expect("parses"), ts);
}

#[test]
fn timestamps_parse_what_other_clients_emit() {
    // Other clients may emit more precision; we must read it, then render it
    // truncated so our own writes stay comparable.
    let ts = Timestamp::parse("2025-09-09T00:00:00.123456789Z").expect("parses");
    assert_eq!(ts.to_string(), "2025-09-09T00:00:00.123Z");
}

// ------------------------------------------------------------------ the chain

struct Fixture {
    keys: AuthenticatorKeys,
    lock: ProfileAuthenticatorLock,
    storable_seed: [u8; 32],
    high_security_seed: [u8; 32],
}

fn fixture() -> Fixture {
    let seed = Seed::from_bytes(&[9u8; 32]);
    let salt = SecretSalt::from_bytes([0xa5; 32]);
    let keys = AuthenticatorKeys::derive(auth_id(1), &seed, &salt).expect("derives");

    // Rebuild the authenticator's profile-seed encryption key to seal with.
    let enc = EncryptionPrivateKey::derive(
        seed.expose_secret(),
        Some(salt.as_bytes()),
        heyl_crypto::context::AUTHENTICATOR_PROFILE_SEED_ENCRYPTION,
    )
    .expect("derives");
    let to = enc.public_key();
    let ephemeral = EncryptionPrivateKey::from_bytes(&[0x33; 32]);

    let storable_seed = [0x11; 32];
    let high_security_seed = [0x22; 32];
    Fixture {
        keys,
        lock: ProfileAuthenticatorLock {
            authenticator_id: auth_id(1),
            profile_id: fixture_profile(),
            profile_key_generation_id: KeyGenerationId::new("gen-1"),
            encrypted_storable_profile_seed: to.seal(
                &ephemeral,
                &Nonce::from_bytes([1; 24]),
                &storable_seed,
            ),
            encrypted_high_security_profile_seed: to.seal(
                &ephemeral,
                &Nonce::from_bytes([2; 24]),
                &high_security_seed,
            ),
        },
        storable_seed,
        high_security_seed,
    }
}

#[test]
fn the_chain_unwraps_both_tiers_from_one_lock() {
    let f = fixture();
    assert_eq!(
        f.keys
            .unlock_storable_profile_seed(&f.lock, &KeyGenerationId::new("gen-1"))
            .expect("opens")
            .expose_secret(),
        &f.storable_seed,
    );
    assert_eq!(
        f.keys
            .unlock_high_security_profile_seed(&f.lock, &KeyGenerationId::new("gen-1"))
            .expect("opens")
            .expose_secret(),
        &f.high_security_seed,
    );
}

#[test]
fn a_lock_for_another_authenticator_is_refused_rather_than_attempted() {
    let f = fixture();
    let foreign = ProfileAuthenticatorLock {
        authenticator_id: auth_id(2),
        ..f.lock.clone()
    };

    let err = f
        .keys
        .unlock_storable_profile_seed(&foreign, &KeyGenerationId::new("gen-1"))
        .expect_err("refused");
    assert!(
        matches!(err, DomainError::NoLockForAuthenticator { .. }),
        "{err:?}"
    );
}

/// `ProfileAuthenticatorLock` carries its own `profile_key_generation_id`, and
/// a stale one is refused the same way `VaultProfileLock`'s is. M1 checked the
/// authenticator id here but not the generation; the wire message carries both.
#[test]
fn a_re_keyed_profile_is_refused_at_the_authenticator_lock_too() {
    let f = fixture();
    let err = f
        .keys
        .unlock_storable_profile_seed(&f.lock, &KeyGenerationId::new("gen-2"))
        .expect_err("refused");
    assert!(
        matches!(
            &err,
            DomainError::KeyGenerationMismatch { profile, lock, .. }
                if profile.as_str() == "gen-2" && lock.as_str() == "gen-1"
        ),
        "{err:?}",
    );
}

fn vault_lock(
    profile: &ProfileId,
    generation: &KeyGenerationId,
) -> (VaultProfileLock, [u8; 32], [u8; 32]) {
    let storable = ProfileSeed::<Storable>::from_bytes(&[0x11; 32]);
    let high = ProfileSeed::<HighSecurity>::from_bytes(&[0x22; 32]);
    let vault_secret = [0x77; 32];
    let protected_secret = [0x88; 32];
    let ephemeral = EncryptionPrivateKey::from_bytes(&[0x44; 32]);

    let lock = VaultProfileLock {
        locking_profile_id: *profile,
        locking_profile_key_generation_id: generation.clone(),
        encrypted_storable_vault_key: storable
            .vault_key_encryption_key()
            .expect("derives")
            .public_key()
            .seal(&ephemeral, &Nonce::from_bytes([3; 24]), &vault_secret),
        encrypted_high_security_vault_key: high
            .vault_key_encryption_key()
            .expect("derives")
            .public_key()
            .seal(&ephemeral, &Nonce::from_bytes([4; 24]), &protected_secret),
        encrypted_vault_message_private_key: None,
    };
    (lock, vault_secret, protected_secret)
}

#[test]
fn each_tier_unwraps_its_own_vault_secret() {
    let profile = ProfileId::parse("00000000-0000-4000-8000-0000000000ff").expect("valid");
    let generation = KeyGenerationId::new("gen-7");
    let (lock, vault_secret, protected_secret) = vault_lock(&profile, &generation);

    let storable = ProfileSeed::<Storable>::from_bytes(&[0x11; 32]);
    let high = ProfileSeed::<HighSecurity>::from_bytes(&[0x22; 32]);

    assert_eq!(
        storable
            .unlock_vault(&lock, profile, &generation)
            .expect("opens")
            .key()
            .expose_secret(),
        &vault_secret,
    );
    assert_eq!(
        high.unlock_vault(&lock, profile, &generation)
            .expect("opens")
            .key()
            .expose_secret(),
        &protected_secret,
    );
}

/// A stale lock is reported as a key-generation mismatch, not as a decryption
/// failure — because the fix is to re-sync, not to re-authenticate.
#[test]
fn a_re_keyed_profile_is_refused_before_any_decryption() {
    let profile = ProfileId::parse("00000000-0000-4000-8000-0000000000ff").expect("valid");
    let (lock, _, _) = vault_lock(&profile, &KeyGenerationId::new("gen-7"));

    let storable = ProfileSeed::<Storable>::from_bytes(&[0x11; 32]);
    let err = storable
        .unlock_vault(&lock, profile, &KeyGenerationId::new("gen-8"))
        .expect_err("refused");
    assert!(
        matches!(
            &err,
            DomainError::KeyGenerationMismatch { profile, lock, .. }
                if profile.as_str() == "gen-8" && lock.as_str() == "gen-7"
        ),
        "{err:?}",
    );
}

#[test]
fn profile_seeds_redact_in_debug_and_name_their_tier() {
    let storable = ProfileSeed::<Storable>::from_bytes(&[0xAB; 32]);
    let rendered = format!("{storable:?}");
    assert!(rendered.contains("Storable"), "{rendered}");
    assert!(rendered.contains("redacted"), "{rendered}");
    // Not a substring check on "ab": "Storable" contains one.
    assert!(
        !rendered.contains(&hex::encode(storable.expose_secret())),
        "{rendered}"
    );

    let high = ProfileSeed::<HighSecurity>::from_bytes(&[0xCD; 32]);
    let rendered = format!("{high:?}");
    assert!(rendered.contains("HighSecurity"), "{rendered}");
    assert!(
        !rendered.contains(&hex::encode(high.expose_secret())),
        "{rendered}"
    );
}

// ------------------------------------------------------------------ vocabulary

#[test]
fn unsupported_vault_types_are_named_rather_than_guessed_at() {
    assert!(!VaultType::OrganizationAdmin.is_supported());
    assert!(!VaultType::OrganizationLoginSummary.is_supported());
    assert!(VaultType::Meta.is_supported());
    assert!(VaultType::Team.is_supported());
}

#[test]
fn every_credential_bearing_vault_uses_the_login_schema() {
    for vault in [
        VaultType::Private,
        VaultType::Team,
        VaultType::Inbox,
        VaultType::OrganizationPersonal,
    ] {
        assert!(vault.holds_logins(), "{vault:?}");
    }
    for vault in [VaultType::Meta, VaultType::TeamMeta, VaultType::InboxMeta] {
        assert!(!vault.holds_logins(), "{vault:?}");
    }
}

#[test]
fn only_push_and_backup_code_are_supported_login_paths_in_v1() {
    assert!(AuthenticatorType::Push.is_supported());
    assert!(AuthenticatorType::BackupCode.is_supported());
    for kind in [
        AuthenticatorType::Webauthn,
        AuthenticatorType::Dummy,
        AuthenticatorType::BackupOs,
        AuthenticatorType::SessionUnlock,
        AuthenticatorType::OrganizationService,
    ] {
        assert!(!kind.is_supported(), "{kind:?}");
    }
}

#[test]
fn identifiers_reject_non_uuids() {
    assert!(ProfileId::parse("not-a-uuid").is_err());
    assert!(ProfileId::parse("00000000-0000-4000-8000-0000000000ff").is_ok());
}

// -------------------------------------------------------------- session keys

/// The session encryption key is **KDF-derived** from a random seed, not the
/// random bytes used directly as an X25519 scalar.
///
/// `createUnsignedSessionKeys()` in the shipped client:
/// ```js
/// const secret = randomSeed();
/// return deriveEncryptionKeyPair(secret, null, FIXED_INFO_SESSION_ENCRYPTION_KEY);
/// ```
///
/// Using the bytes directly round-trips perfectly with itself, so nothing in
/// M2 would notice — we seal to our own public key and open with our own
/// private key. It diverges at M5, where the public half is published and
/// signed, and at M10, where another session encrypts to it.
#[test]
fn the_session_key_goes_through_the_kdf_rather_than_being_raw_random() {
    let seed = [0x3c; 32];
    let derived = heyl_domain::session_encryption_key(&seed).expect("derives");
    let raw = EncryptionPrivateKey::from_bytes(&seed);

    assert_ne!(
        derived.public_key().as_bytes(),
        raw.public_key().as_bytes(),
        "a raw scalar would work with itself and be wrong with everyone else"
    );

    // And it is the session context specifically, not some other one.
    let expected =
        EncryptionPrivateKey::derive(&seed, None, heyl_crypto::context::SESSION_ENCRYPTION)
            .expect("derives");
    assert_eq!(
        derived.public_key().as_bytes(),
        expected.public_key().as_bytes()
    );
}
