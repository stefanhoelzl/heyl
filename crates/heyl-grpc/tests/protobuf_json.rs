//! Protobuf-JSON, in both directions.
//!
//! The reason this is not `serde` derives on the generated types: heylogin's
//! schema is mostly `bytes` — sealed blobs, keys, signatures, commit payloads —
//! and prost's own `serde` shape renders those as arrays of integers and enums
//! as bare `i32`. What is asserted here is that the mapping we get instead is
//! the one `HEYLOGIN_SPEC.md` and heylogin's own client speak.

#![cfg(feature = "api")]

use heyl_grpc::json;

#[test]
fn bytes_are_base64_and_enums_are_names() {
    let pool = json::pool().expect("the embedded schema loads");

    let vault = heyl_proto::sync_update::Vault {
        id: "9f0e7a2c-0000-4000-8000-000000000001".to_owned(),
        vault_type: heyl_proto::VaultType::Private as i32,
        ..Default::default()
    };

    let rendered = json::to_json(pool, "domain.SyncUpdate.Vault", &vault).expect("renders");

    // An enum by name, not by discriminant: `2` tells a reader nothing, and the
    // name is what the spec and the extension both use.
    assert!(
        rendered.contains("VAULT_TYPE_PRIVATE"),
        "enums should render by name:\n{rendered}"
    );
    // camelCase, from `json_name`, not Rust's snake_case.
    assert!(
        rendered.contains("\"vaultType\"") && !rendered.contains("\"vault_type\""),
        "field names should be the schema's camelCase:\n{rendered}"
    );
}

#[test]
fn a_bytes_field_survives_a_round_trip_as_base64() {
    let pool = json::pool().expect("the embedded schema loads");

    // A sealed blob is the shape that matters: every interesting field in this
    // schema is bytes, and base64 is what makes them readable and re-sendable.
    let blob = (0_u8..=255).collect::<Vec<u8>>();
    let lock = heyl_proto::VaultProfileLock {
        encrypted_storable_vault_key: blob.clone(),
        ..Default::default()
    };

    let rendered = json::to_json(pool, "domain.VaultProfileLock", &lock).expect("renders");
    assert!(
        rendered.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"),
        "bytes should be base64:\n{rendered}"
    );

    let back: heyl_proto::VaultProfileLock =
        json::from_json(pool, "domain.VaultProfileLock", &rendered).expect("parses");
    assert_eq!(back.encrypted_storable_vault_key, blob);
}

#[test]
fn an_empty_body_means_the_default_message() {
    let pool = json::pool().expect("the embedded schema loads");

    // So `heyl api call Sync` needs no argument for an RPC whose request has
    // nothing required in it.
    let message: heyl_proto::SyncRequest =
        json::from_json(pool, "domain.SyncRequest", "").expect("an empty body parses");
    assert_eq!(message, heyl_proto::SyncRequest::default());
}

#[test]
fn a_malformed_body_names_the_message_it_failed_on() {
    let pool = json::pool().expect("the embedded schema loads");

    let err = json::from_json::<heyl_proto::CreateChallengeRequest>(
        pool,
        "domain.CreateChallengeRequest",
        "{ not json",
    )
    .expect_err("that is not JSON");

    // The message type is in the error because the alternative — a bare serde
    // complaint about line 1 column 3 — does not say which of 123 RPCs you got
    // wrong.
    assert!(
        err.to_string().contains("domain.CreateChallengeRequest"),
        "{err}"
    );
}

#[test]
fn a_sync_document_maps_to_the_domain_snapshot() {
    // The path `heyl api derive --sync` takes: a document printed by
    // `heyl api call Sync` goes back through the *same* `map::sync_update` the
    // port uses, so what it walks is what `heyl doctor` would walk.
    let document = r#"{
      "syncUpdate": {
        "vaults": [
          {
            "id": "9f0e7a2c-0000-4000-8000-000000000001",
            "vaultType": "VAULT_TYPE_PRIVATE",
            "generationId": "11111111-0000-4000-8000-000000000001",
            "profiles": []
          }
        ]
      }
    }"#;

    let snapshot = json::sync_snapshot(document).expect("maps");
    assert_eq!(snapshot.vaults.len(), 1);
    assert_eq!(
        snapshot.vaults[0].vault_type,
        heyl_domain::VaultType::Private
    );
}
