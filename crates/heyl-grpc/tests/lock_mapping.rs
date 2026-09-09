//! Mapping a `ProfileAuthenticatorLock` off the wire.
//!
//! Found by a real login: the backend leaves `profile_id` and
//! `profile_key_generation_id` **empty** on locks nested inside the
//! `SyncUpdateProfile` that already identifies them — which is every lock on
//! the login path. Requiring them turned a successful `CreateTokens` into
//! `ProfileAuthenticatorLock.profile_id is not a UUID: ""`.

use heyl_domain::{KeyGenerationId, ProfileId};
use heyl_grpc::map::profile_authenticator_lock;

fn owner() -> ProfileId {
    ProfileId::parse("00000000-0000-4000-8000-0000000000bb").expect("valid")
}

fn generation() -> KeyGenerationId {
    KeyGenerationId::new("generation-1")
}

fn wire(profile_id: &str, generation_id: &str) -> heyl_proto::ProfileAuthenticatorLock {
    heyl_proto::ProfileAuthenticatorLock {
        authenticator_id: "00000000-0000-4000-8000-0000000000aa".to_owned(),
        profile_id: profile_id.to_owned(),
        profile_key_generation_id: generation_id.to_owned(),
        encrypted_storable_profile_seed: vec![1, 2, 3],
        encrypted_high_security_profile_seed: vec![4, 5, 6],
    }
}

/// The shape a real login actually returns.
#[test]
fn omitted_fields_are_inherited_from_the_owning_profile() {
    let lock = profile_authenticator_lock(&wire("", ""), owner(), &generation()).expect("maps");
    assert_eq!(lock.profile_id, owner());
    assert_eq!(lock.profile_key_generation_id, generation());
}

/// When the backend does send them, they are taken as sent.
#[test]
fn stated_fields_are_used_when_present() {
    let lock = profile_authenticator_lock(
        &wire("00000000-0000-4000-8000-0000000000bb", "generation-9"),
        owner(),
        &generation(),
    )
    .expect("maps");
    assert_eq!(lock.profile_id, owner());
    assert_eq!(lock.profile_key_generation_id.as_str(), "generation-9");
}

/// A lock nested under the wrong profile is still refused. Inheriting an
/// absent value must not become "believe whatever you are told".
#[test]
fn a_lock_nested_under_the_wrong_profile_is_refused() {
    let err = profile_authenticator_lock(
        &wire("00000000-0000-4000-8000-0000000000cc", ""),
        owner(),
        &generation(),
    )
    .expect_err("refused");
    assert!(
        err.to_string().contains("does not match the profile"),
        "{err}"
    );
}

/// A present-but-malformed id is a mapping failure, not silently inherited.
#[test]
fn a_malformed_profile_id_is_still_an_error() {
    let err = profile_authenticator_lock(&wire("not-a-uuid", ""), owner(), &generation())
        .expect_err("refused");
    assert!(err.to_string().contains("not a UUID"), "{err}");
}
