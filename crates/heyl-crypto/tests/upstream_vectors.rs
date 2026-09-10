//! Vectors transcribed from RFC 8032, RFC 4231 and FIPS 180-4.
//!
//! These are the only tests in the workspace that prove agreement with
//! something outside this repository. If one fails, our code is wrong or the
//! transcription is — the vector is never the thing to adjust.

use heyl_crypto::{Signature, SigningKey, VerifyingKey, derive_secret_from_seed_modern, hash_data};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

fn load(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/upstream/");
    let raw = std::fs::read_to_string(format!("{path}{name}"))
        .unwrap_or_else(|e| panic!("reading {name}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {name}: {e}"))
}

fn hex_of(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().expect("field is a string")).expect("field is hex")
}

/// A vector file that parsed to nothing would let every assertion below pass
/// vacuously — which is exactly what happened while these fixtures were being
/// generated. Refuse to run on an empty or under-populated case list.
fn cases(doc: &Value, least: usize) -> &[Value] {
    let cases = doc["cases"].as_array().expect("cases is an array");
    assert!(
        cases.len() >= least,
        "expected at least {least} vectors, found {}",
        cases.len()
    );
    cases
}

#[test]
fn ed25519_rfc8032() {
    let doc = load("ed25519.json");
    for case in cases(&doc, 4) {
        let name = case["name"].as_str().unwrap_or("?");
        let seed: [u8; 32] = hex_of(case, "secret_key").try_into().expect("32-byte seed");
        let message = hex_of(case, "message");
        let expected_pub = hex_of(case, "public_key");
        let expected_sig = hex_of(case, "signature");

        let key = SigningKey::from_bytes(&seed);
        assert_eq!(
            key.verifying_key().as_bytes().as_slice(),
            expected_pub,
            "{name}: public key"
        );

        let sig = key.sign_unprefixed(&message);
        assert_eq!(sig.as_bytes().as_slice(), expected_sig, "{name}: signature");

        let verifying = VerifyingKey::try_from_slice(&expected_pub).expect("32-byte public key");
        let parsed = Signature::try_from_slice(&expected_sig).expect("64-byte signature");
        assert!(
            verifying.verify_unprefixed(&message, &parsed),
            "{name}: verify"
        );
    }
}

/// The context is prefixed to the *message*, so a signature made under one
/// context must not verify under another. This is the property that makes
/// `SignatureContext` worth having.
#[test]
fn signature_context_is_bound_to_the_message() {
    use heyl_crypto::context::{AUTHENTICATOR_ENCRYPTION_SIGNATURE, SESSION_ENCRYPTION_SIGNATURE};

    let key = SigningKey::from_bytes(&[7u8; 32]);
    let data = b"a public key";

    let sig = key.sign(SESSION_ENCRYPTION_SIGNATURE, data);
    assert!(
        key.verifying_key()
            .verify(SESSION_ENCRYPTION_SIGNATURE, data, &sig)
    );
    assert!(
        !key.verifying_key()
            .verify(AUTHENTICATOR_ENCRYPTION_SIGNATURE, data, &sig)
    );
    assert!(!key.verifying_key().verify_unprefixed(data, &sig));
}

#[test]
fn hmac_sha256_rfc4231() {
    let doc = load("hmac_sha256.json");
    for case in cases(&doc, 3) {
        let name = case["name"].as_str().unwrap_or("?");
        let key = hex_of(case, "key");
        let data = hex_of(case, "data");
        let expected = hex_of(case, "hmac");

        // `derive_secret_from_seed_modern` fixes the key at 32 or 64 bytes and
        // the message at a &str, so drive the same construction directly.
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("any key length");
        mac.update(&data);
        assert_eq!(mac.finalize().into_bytes().as_slice(), expected, "{name}");
    }
}

/// Ties our KDF wrapper to the RFC-verified construction above: the modern
/// variant must be exactly `HMAC-SHA256(key = seed, msg = utf8(salt))`.
#[test]
fn modern_kdf_is_plain_hmac_over_the_salt() {
    let seed = [0x11u8; 32];
    let salt = "salt-key-symmetric-example-";

    let ours = derive_secret_from_seed_modern(&seed, None, salt).expect("valid salt");

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&seed).expect("any key length");
    mac.update(salt.as_bytes());
    assert_eq!(ours.as_slice(), mac.finalize().into_bytes().as_slice());
}

/// With a secondary seed the HMAC key is `seed ‖ secondary`, not a nested MAC.
#[test]
fn modern_kdf_concatenates_the_secondary_into_the_key() {
    let seed = [0x11u8; 32];
    let secondary = [0x22u8; 32];
    let salt = "salt-key-symmetric-example-";

    let ours = derive_secret_from_seed_modern(&seed, Some(&secondary), salt).expect("valid salt");

    let mut key = Vec::new();
    key.extend_from_slice(&seed);
    key.extend_from_slice(&secondary);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("any key length");
    mac.update(salt.as_bytes());
    assert_eq!(ours.as_slice(), mac.finalize().into_bytes().as_slice());

    assert_ne!(
        ours.as_slice(),
        derive_secret_from_seed_modern(&seed, None, salt)
            .expect("valid salt")
            .as_slice(),
        "the secondary seed must change the output"
    );
}

#[test]
fn sha512_fips180_4() {
    let doc = load("sha512.json");
    for case in cases(&doc, 2) {
        let name = case["name"].as_str().unwrap_or("?");
        let message = hex_of(case, "message");
        let expected = hex_of(case, "sha512");

        assert_eq!(
            Sha512::digest(&message).as_slice(),
            expected,
            "{name}: sha512"
        );

        // hashData is that digest truncated to 32 bytes.
        assert_eq!(
            hash_data(&message).as_slice(),
            &expected[..32],
            "{name}: hash_data"
        );
    }
}
