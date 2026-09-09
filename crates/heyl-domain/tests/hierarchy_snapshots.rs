//! Per-link regression baselines for the key hierarchy.
//!
//! **These prove self-consistency, not correctness.** Nothing here has been
//! checked against heylogin, and it cannot be offline: a mistyped context
//! yields stable, self-consistent, wrong keys and every assertion below stays
//! green (DESIGN.md §6).
//!
//! They are stored **one snapshot per link** so that when M2 fails — and M2 is
//! where the hierarchy is first confirmed, by `CreateTokens` accepting our
//! signature and by decrypting one vault — the diff names the link that moved
//! rather than pointing at "crypto".
//!
//! A diff surfacing in `cargo insta review` means a derivation changed. Before
//! accepting one, establish *why*: after M2 has passed once, an unexplained
//! change here is a regression, not a new baseline.

use heyl_crypto::{SecretSalt, Seed};
use heyl_domain::{
    AuthenticatorId, AuthenticatorKeys, HighSecurity, ProfileSeed, Storable, login_signing_key,
};

/// Fixed inputs. Arbitrary, but never changed — that is the whole point.
const SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const SECRET_SALT: [u8; 32] = [0xa5; 32];
const PROFILE_SEED: [u8; 32] = [0x5a; 32];

fn authenticator_keys() -> AuthenticatorKeys {
    AuthenticatorKeys::derive(
        AuthenticatorId::parse("00000000-0000-4000-8000-000000000001").expect("valid uuid"),
        &Seed::from_bytes(&SEED),
        &SecretSalt::from_bytes(SECRET_SALT),
    )
    .expect("derivation succeeds")
}

#[test]
fn link_01_authenticator_login_signing_key() {
    // Derived with a *null* secondary seed, which is what lets login happen
    // before the server reveals `secretSalt`. This is the first link M2
    // confirms: `CreateTokens` accepting our signature proves it.
    let key = login_signing_key(&Seed::from_bytes(&SEED)).expect("derivation succeeds");
    insta::assert_snapshot!(hex::encode(key.verifying_key().as_bytes()));
}

#[test]
fn link_02_authenticator_identity_signing_key() {
    let keys = authenticator_keys();
    insta::assert_snapshot!(hex::encode(
        keys.identity_signing_key().verifying_key().as_bytes()
    ));
}

#[test]
fn link_03_profile_storable_vault_key_encryption_key() {
    let seed = ProfileSeed::<Storable>::from_bytes(&PROFILE_SEED);
    let key = seed
        .vault_key_encryption_key()
        .expect("derivation succeeds");
    insta::assert_snapshot!(hex::encode(key.public_key().as_bytes()));
}

#[test]
fn link_04_profile_high_security_vault_key_encryption_key() {
    let seed = ProfileSeed::<HighSecurity>::from_bytes(&PROFILE_SEED);
    let key = seed
        .vault_key_encryption_key()
        .expect("derivation succeeds");
    insta::assert_snapshot!(hex::encode(key.public_key().as_bytes()));
}

#[test]
fn link_05_profile_storable_identity_signing_key() {
    let seed = ProfileSeed::<Storable>::from_bytes(&PROFILE_SEED);
    let key = seed.identity_signing_key().expect("derivation succeeds");
    insta::assert_snapshot!(hex::encode(key.verifying_key().as_bytes()));
}

#[test]
fn link_06_profile_high_security_identity_signing_key() {
    let seed = ProfileSeed::<HighSecurity>::from_bytes(&PROFILE_SEED);
    let key = seed.identity_signing_key().expect("derivation succeeds");
    insta::assert_snapshot!(hex::encode(key.verifying_key().as_bytes()));
}

#[test]
fn link_07_profile_storable_profile_key_encryption_key() {
    let seed = ProfileSeed::<Storable>::from_bytes(&PROFILE_SEED);
    let key = seed
        .profile_key_encryption_key()
        .expect("derivation succeeds");
    insta::assert_snapshot!(hex::encode(key.public_key().as_bytes()));
}

#[test]
fn link_08_profile_high_security_profile_key_encryption_key() {
    let seed = ProfileSeed::<HighSecurity>::from_bytes(&PROFILE_SEED);
    let key = seed
        .profile_key_encryption_key()
        .expect("derivation succeeds");
    insta::assert_snapshot!(hex::encode(key.public_key().as_bytes()));
}

/// The two tiers must never derive the same key from the same profile seed.
///
/// If they ever do, the phantom-type separation is decorative and the storable
/// tier can reach high-security material.
#[test]
fn the_two_tiers_diverge_at_the_profile_layer() {
    let storable = ProfileSeed::<Storable>::from_bytes(&PROFILE_SEED);
    let high = ProfileSeed::<HighSecurity>::from_bytes(&PROFILE_SEED);

    assert_ne!(
        storable.vault_key_encryption_key().unwrap().public_key(),
        high.vault_key_encryption_key().unwrap().public_key(),
    );
    assert_ne!(
        storable.identity_signing_key().unwrap().verifying_key(),
        high.identity_signing_key().unwrap().verifying_key(),
    );
    assert_ne!(
        storable.profile_key_encryption_key().unwrap().public_key(),
        high.profile_key_encryption_key().unwrap().public_key(),
    );
}

/// Conversely: at the *authenticator* layer heylogin's storable and
/// high-security context constants hold identical values, so there is one key
/// rather than two. Recorded as a test because it looks like a bug otherwise,
/// and because if heylogin ever splits them this must fail loudly.
#[test]
fn the_two_tiers_share_one_key_at_the_authenticator_layer() {
    use heyl_crypto::{EncryptionPrivateKey, SigningKey, context};

    let storable_sig = SigningKey::derive(
        &SEED,
        Some(&SECRET_SALT),
        context::AUTHENTICATOR_IDENTITY_SIGNING,
    )
    .unwrap();
    let storable_enc = EncryptionPrivateKey::derive(
        &SEED,
        Some(&SECRET_SALT),
        context::AUTHENTICATOR_PROFILE_SEED_ENCRYPTION,
    )
    .unwrap();

    let keys = authenticator_keys();
    assert_eq!(
        keys.identity_signing_key().verifying_key(),
        storable_sig.verifying_key()
    );
    assert_eq!(
        keys.unlock_storable_profile_seed(&stub_lock(&storable_enc))
            .unwrap()
            .expose_secret(),
        &PROFILE_SEED,
    );
}

/// A lock built with the authenticator's own key, so the round trip exercises
/// the real unwrap path rather than a hand-made ciphertext.
fn stub_lock(enc: &heyl_crypto::EncryptionPrivateKey) -> heyl_domain::ProfileAuthenticatorLock {
    use heyl_crypto::Nonce;

    let ephemeral = heyl_crypto::EncryptionPrivateKey::from_bytes(&[0x33; 32]);
    let to = enc.public_key();
    heyl_domain::ProfileAuthenticatorLock {
        authenticator_id: AuthenticatorId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        encrypted_storable_profile_seed: to.seal(
            &ephemeral,
            &Nonce::from_bytes([0x44; 24]),
            &PROFILE_SEED,
        ),
        encrypted_high_security_profile_seed: to.seal(
            &ephemeral,
            &Nonce::from_bytes([0x55; 24]),
            &[0x6b; 32],
        ),
    }
}
