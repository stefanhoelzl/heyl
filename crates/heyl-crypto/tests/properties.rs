//! Round-trip and hygiene properties.
//!
//! These prove self-consistency, not agreement with heylogin — see the crate
//! docs. They are what catches a framing mistake that both our encrypt and our
//! decrypt would otherwise share.

use heyl_crypto::{
    AesGcmKey, EncryptionPrivateKey, Nonce, Seed, SymKey,
    context::{AUTHENTICATOR_LOGIN_SIGNING, SESSION_ENCRYPTION},
    signing::SigningKey,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn secretbox_round_trips(key: [u8; 32], nonce: [u8; 24], plaintext: Vec<u8>) {
        let key = SymKey::from_bytes(&key);
        let blob = key.encrypt(&Nonce::from_bytes(nonce), &plaintext);
        let opened = key.decrypt(&blob).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    /// The wire format is heylogin's, not the library's: `nonce ‖ box`.
    #[test]
    fn secretbox_wire_format_is_nonce_then_box(key: [u8; 32], nonce: [u8; 24], plaintext: Vec<u8>) {
        let blob = SymKey::from_bytes(&key).encrypt(&Nonce::from_bytes(nonce), &plaintext);
        prop_assert_eq!(&blob[..24], &nonce[..]);
        prop_assert_eq!(blob.len(), 24 + plaintext.len() + 16);
    }

    #[test]
    fn secretbox_rejects_a_tampered_tag(key: [u8; 32], nonce: [u8; 24], plaintext: Vec<u8>) {
        let key = SymKey::from_bytes(&key);
        let mut blob = key.encrypt(&Nonce::from_bytes(nonce), &plaintext);
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        prop_assert!(key.decrypt(&blob).is_err());
    }

    #[test]
    fn crypto_box_round_trips(
        recipient: [u8; 32], ephemeral: [u8; 32], nonce: [u8; 24], plaintext: Vec<u8>,
    ) {
        let recipient = EncryptionPrivateKey::from_bytes(&recipient);
        let ephemeral = EncryptionPrivateKey::from_bytes(&ephemeral);
        let blob = recipient.public_key().seal(&ephemeral, &Nonce::from_bytes(nonce), &plaintext);
        let opened = recipient.open(&blob).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    /// `nonce(24) ‖ ephemeralPub(32) ‖ box` — tweetnacl's `nacl.box` layout.
    #[test]
    fn crypto_box_wire_format_carries_the_ephemeral_key(
        recipient: [u8; 32], ephemeral: [u8; 32], nonce: [u8; 24], plaintext: Vec<u8>,
    ) {
        let recipient = EncryptionPrivateKey::from_bytes(&recipient);
        let ephemeral = EncryptionPrivateKey::from_bytes(&ephemeral);
        let blob = recipient.public_key().seal(&ephemeral, &Nonce::from_bytes(nonce), &plaintext);
        prop_assert_eq!(&blob[..24], &nonce[..]);
        let eph_pub = ephemeral.public_key();
        prop_assert_eq!(&blob[24..56], eph_pub.as_bytes().as_slice());
        prop_assert_eq!(blob.len(), 24 + 32 + plaintext.len() + 16);
    }

    #[test]
    fn aes_gcm_round_trips(key: [u8; 32], nonce: [u8; 12], plaintext: Vec<u8>) {
        let key = AesGcmKey::from_bytes(&key);
        let blob = key.encrypt(&nonce, &plaintext);
        let opened = key.decrypt(&blob).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn signatures_round_trip(seed: [u8; 32], message: Vec<u8>) {
        let key = SigningKey::from_bytes(&seed);
        let sig = key.sign_unprefixed(&message);
        prop_assert!(key.verifying_key().verify_unprefixed(&message, &sig));
    }

    /// Derivation is a pure function: the same inputs always give the same key.
    #[test]
    fn derivation_is_deterministic(seed: [u8; 32], salt: [u8; 32]) {
        let a = SigningKey::derive(&seed, Some(&salt), AUTHENTICATOR_LOGIN_SIGNING).unwrap();
        let b = SigningKey::derive(&seed, Some(&salt), AUTHENTICATOR_LOGIN_SIGNING).unwrap();
        prop_assert_eq!(a.verifying_key(), b.verifying_key());
    }

    /// The secondary seed is load-bearing: dropping it must change the key.
    /// This is what separates the login key from every other authenticator key.
    #[test]
    fn the_secondary_seed_changes_the_key(seed: [u8; 32], salt: [u8; 32]) {
        let with = SigningKey::derive(&seed, Some(&salt), AUTHENTICATOR_LOGIN_SIGNING).unwrap();
        let without = SigningKey::derive(&seed, None, AUTHENTICATOR_LOGIN_SIGNING).unwrap();
        prop_assert_ne!(with.verifying_key(), without.verifying_key());
    }
}

/// Truncated blobs are reported as such rather than as authentication
/// failures, so M2/M3 can tell a framing bug from a wrong key.
#[test]
fn short_blobs_are_distinguished_from_bad_tags() {
    use heyl_crypto::CryptoError;

    let key = SymKey::from_bytes(&[1u8; 32]);
    assert!(matches!(
        key.decrypt(&[0u8; 39]),
        Err(CryptoError::TooShort { len: 39, min: 40 })
    ));
    assert!(matches!(
        key.decrypt(&[0u8; 40]),
        Err(CryptoError::Authentication)
    ));

    let enc = EncryptionPrivateKey::from_bytes(&[1u8; 32]);
    assert!(matches!(
        enc.open(&[0u8; 71]),
        Err(CryptoError::TooShort { len: 71, min: 72 })
    ));
    assert!(matches!(
        enc.open(&[0u8; 72]),
        Err(CryptoError::Authentication)
    ));
}

/// DESIGN §3: secrets are "never logged, never included in error messages".
/// `Debug` is the easiest way to break that by accident.
#[test]
fn debug_never_leaks_secret_bytes() {
    let seed = Seed::from_bytes(&[0xAB; 32]);
    let rendered = format!("{seed:?}");
    assert!(!rendered.contains("ab"), "{rendered}");
    assert!(!rendered.contains("171"), "{rendered}");
    assert!(rendered.contains("redacted"), "{rendered}");

    let key = SymKey::from_bytes(&[0xCD; 32]);
    assert!(!format!("{key:?}").contains("cd"));

    let enc = EncryptionPrivateKey::derive(&[3u8; 32], None, SESSION_ENCRYPTION).unwrap();
    let rendered = format!("{enc:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    let leaked = hex::encode(enc.expose_secret());
    assert!(!rendered.contains(&leaked), "{rendered}");
}

/// The KDF's own guard rails, transcribed from `lib-vault-crypto`.
#[test]
fn kdf_rejects_a_short_context() {
    use heyl_crypto::CryptoError;
    // Every constant in `context` is far longer than the 8-character floor, so
    // this is only reachable by constructing one by hand; the check exists
    // because heylogin enforces it and a divergence would be silent.
    let err = heyl_crypto::derive_secret_from_seed_modern(&[0u8; 32], None, "short").unwrap_err();
    assert_eq!(err, CryptoError::ContextTooShort { len: 5 });
}
