//! The META vault's `sessions` map — the device list, as heylogin stores it.
//!
//! Every function here is **read-modify-write on the decoded document**, never
//! a rebuild: the document is the fold of every commit (`heyl_vault::fold`), so
//! anything we do not understand has to come back out unchanged (DESIGN.md §3,
//! "Reading and writing safely"). In practice that means editing the JSON in
//! place and touching exactly one key — the entry whose id is our own session.
//!
//! heymerge is last-write-wins per key on `updateTime`, and the key we write is
//! one no other client owns, so a concurrent write cannot lose data of ours or
//! theirs. That is the whole reason no merge is ever executed here.

use heyl_domain::{SessionId, SessionMetadata, Timestamp};
use serde_json::{Map, Value};

use crate::{Document, VaultError};

/// The document type a META vault declares.
pub const META_DOCUMENT_TYPE: &str = "meta";

/// The key the session registry lives under.
const SESSIONS: &str = "sessions";

/// Every session entry this document holds, in document order.
///
/// Entries that do not parse are **skipped, not fatal**: the map belongs to
/// every client on the account, and a shape we have not modelled is somebody
/// else's business rather than a reason to refuse to run. They stay untouched
/// on the way back out.
#[must_use]
pub fn sessions(document: &Document) -> Vec<(SessionId, SessionMetadata)> {
    document
        .content
        .get(SESSIONS)
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(id, entry)| {
                    let id = SessionId::parse(id).ok()?;
                    let entry: SessionMetadata = serde_json::from_value(entry.clone()).ok()?;
                    Some((id, entry))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// One session's entry, if it is present and parses.
#[must_use]
pub fn session(document: &Document, id: SessionId) -> Option<SessionMetadata> {
    sessions(document)
        .into_iter()
        .find_map(|(found, entry)| (found == id).then_some(entry))
}

/// Write our entry, replacing any earlier one.
///
/// # Errors
/// [`VaultError::NotADocument`] if `content.sessions` exists but is not an
/// object, which would mean this is not the schema we think it is.
pub fn upsert_session(
    document: &mut Document,
    id: SessionId,
    entry: &SessionMetadata,
) -> Result<(), VaultError> {
    let value = serde_json::to_value(entry).map_err(|_| VaultError::NotADocument {
        what: "session metadata does not serialize",
    })?;
    sessions_mut(document)?.insert(id.to_string(), value);
    Ok(())
}

/// Mark our entry deleted, keeping the fields heymerge still compares.
///
/// A tombstone rather than a removal: heymerge merges by key, so dropping the
/// key would let another client's stale copy resurrect the device.
///
/// # Errors
/// [`VaultError::NotADocument`] if the entry is missing or the map is not an
/// object — a caller that cannot tombstone must say so rather than pretend.
pub fn tombstone_session(
    document: &mut Document,
    id: SessionId,
    now: Timestamp,
) -> Result<(), VaultError> {
    let entry = sessions_mut(document)?
        .get_mut(&id.to_string())
        .and_then(Value::as_object_mut)
        .ok_or(VaultError::NotADocument {
            what: "no session entry to tombstone",
        })?;
    entry.insert("isDeleted".to_owned(), Value::Bool(true));
    stamp(entry, now);
    Ok(())
}

/// Change the description the phone shows, leaving every other field alone.
///
/// # Errors
/// [`VaultError::NotADocument`] if the entry is missing.
pub fn set_description(
    document: &mut Document,
    id: SessionId,
    description: &str,
    now: Timestamp,
) -> Result<(), VaultError> {
    let entry = sessions_mut(document)?
        .get_mut(&id.to_string())
        .and_then(Value::as_object_mut)
        .ok_or(VaultError::NotADocument {
            what: "no session entry to rename",
        })?;
    entry.insert(
        "description".to_owned(),
        Value::String(description.to_owned()),
    );
    stamp(entry, now);
    Ok(())
}

/// A display name that no live device already uses.
///
/// Mirrors the web client's `disambiguateDescription`: `Chrome`, `Chrome (2)`,
/// `Chrome (3)`. A name is taken only by a device the account still has —
/// `live` is the session ids `Sync` returned. This is deliberately stricter
/// than "not tombstoned": heylogin's app **never** tombstones a device it
/// deletes, so its META entry lingers forever (measured: 22 dead entries on one
/// account). Counting those would push every fresh `heyl CLI` to `heyl CLI
/// (23)`. Only heyl's own `session remove` writes a tombstone, so a live-id
/// join is the only way to tell a real device from a ghost (DESIGN.md §3).
#[must_use]
pub fn disambiguate(description: &str, document: &Document, live: &[SessionId]) -> String {
    let taken: Vec<String> = sessions(document)
        .into_iter()
        .filter(|(id, entry)| !entry.is_deleted && live.contains(id))
        .filter_map(|(_, entry)| entry.description)
        .collect();

    let mut candidate = description.to_owned();
    let mut counter = 1u32;
    while taken.iter().any(|used| used == &candidate) {
        counter += 1;
        candidate = format!("{description} ({counter})");
    }
    candidate
}

fn sessions_mut(document: &mut Document) -> Result<&mut Map<String, Value>, VaultError> {
    let entry = document
        .content
        .entry(SESSIONS.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    entry.as_object_mut().ok_or(VaultError::NotADocument {
        what: "`content.sessions` is not an object",
    })
}

/// heymerge compares `updateTime` lexicographically; `editTime` is what the
/// app shows. Both move together on every edit, as the shipped clients do.
fn stamp(entry: &mut Map<String, Value>, now: Timestamp) {
    entry.insert("editTime".to_owned(), Value::String(now.to_string()));
    entry.insert("updateTime".to_owned(), Value::String(now.to_string()));
}

#[cfg(test)]
mod tests {
    use heyl_domain::{AuthenticatorId, ICON_CLI};

    use super::*;
    use crate::{DESCRIPTOR_VERSION_HEYMERGE, Format};

    fn now() -> Timestamp {
        Timestamp::parse("2026-09-10T12:00:00.000Z").expect("valid")
    }

    fn id(n: u8) -> SessionId {
        SessionId::parse(&format!("bbff21af-55d9-4288-b406-bb253c80{n:04}")).expect("valid uuid")
    }

    fn entry(description: &str) -> SessionMetadata {
        SessionMetadata {
            description: Some(description.to_owned()),
            icon_type: Some(ICON_CLI.to_owned()),
            is_self_unlocking: false,
            enc_pub_key: "AAAA".to_owned(),
            enc_pub_key_signature: "BBBB".to_owned(),
            signing_auth_id: AuthenticatorId::parse("8eb04641-0c77-4fb0-8bca-78cb28050514")
                .expect("valid uuid"),
            creation_time: now(),
            edit_time: now(),
            is_deleted: false,
            update_time: now(),
        }
    }

    fn document() -> Document {
        Document {
            format: Format::Snappy,
            document_type: META_DOCUMENT_TYPE.to_owned(),
            version: DESCRIPTOR_VERSION_HEYMERGE,
            content: Map::new(),
        }
    }

    #[test]
    fn round_trips_our_entry() {
        let mut doc = document();
        upsert_session(&mut doc, id(1), &entry("heyl CLI")).expect("writes");
        assert_eq!(session(&doc, id(1)), Some(entry("heyl CLI")));
    }

    /// The point of the whole module: another client's entry is not ours to
    /// rewrite, and must survive byte-for-byte.
    #[test]
    fn leaves_entries_it_cannot_parse_untouched() {
        let mut doc = document();
        let foreign = serde_json::json!({"somethingElse": true});
        doc.content.insert(
            SESSIONS.to_owned(),
            serde_json::json!({ "not-a-uuid": foreign.clone() }),
        );

        upsert_session(&mut doc, id(1), &entry("heyl CLI")).expect("writes");

        assert_eq!(doc.content[SESSIONS]["not-a-uuid"], foreign);
        assert_eq!(sessions(&doc).len(), 1, "only ours parses");
    }

    #[test]
    fn tombstone_keeps_the_key_and_moves_update_time() {
        let mut doc = document();
        upsert_session(&mut doc, id(1), &entry("heyl CLI")).expect("writes");
        let later = Timestamp::parse("2026-09-10T13:00:00.000Z").expect("valid");
        tombstone_session(&mut doc, id(1), later).expect("tombstones");

        let stored = session(&doc, id(1)).expect("still present");
        assert!(stored.is_deleted);
        assert_eq!(stored.update_time, later);
        assert_eq!(stored.description.as_deref(), Some("heyl CLI"));
    }

    #[test]
    fn tombstoning_something_absent_is_an_error() {
        let mut doc = document();
        assert!(tombstone_session(&mut doc, id(9), now()).is_err());
    }

    #[test]
    fn rename_touches_only_the_description_and_the_clocks() {
        let mut doc = document();
        upsert_session(&mut doc, id(1), &entry("heyl CLI")).expect("writes");
        let later = Timestamp::parse("2026-09-10T13:00:00.000Z").expect("valid");
        set_description(&mut doc, id(1), "Claude (api)", later).expect("renames");

        let stored = session(&doc, id(1)).expect("present");
        assert_eq!(stored.description.as_deref(), Some("Claude (api)"));
        assert_eq!(stored.enc_pub_key, "AAAA", "key untouched");
        assert_eq!(stored.creation_time, now(), "creation time untouched");
        assert_eq!(stored.edit_time, later);
    }

    #[test]
    fn disambiguates_like_the_web_client() {
        let mut doc = document();
        upsert_session(&mut doc, id(1), &entry("heyl CLI")).expect("writes");
        let live = [id(1), id(2)];
        assert_eq!(disambiguate("heyl CLI", &doc, &live), "heyl CLI (2)");

        upsert_session(&mut doc, id(2), &entry("heyl CLI (2)")).expect("writes");
        assert_eq!(disambiguate("heyl CLI", &doc, &live), "heyl CLI (3)");
        assert_eq!(
            disambiguate("something else", &doc, &live),
            "something else"
        );
    }

    /// A tombstoned device frees its name again.
    #[test]
    fn deleted_entries_do_not_reserve_a_name() {
        let mut doc = document();
        upsert_session(&mut doc, id(1), &entry("heyl CLI")).expect("writes");
        tombstone_session(&mut doc, id(1), now()).expect("tombstones");
        assert_eq!(disambiguate("heyl CLI", &doc, &[id(1)]), "heyl CLI");
    }

    /// A ghost — an entry heylogin's app left behind when it deleted the device
    /// — is not live, so its name is free even though it was never tombstoned.
    #[test]
    fn a_name_held_only_by_a_dead_device_is_free() {
        let mut doc = document();
        upsert_session(&mut doc, id(1), &entry("heyl CLI")).expect("writes");
        // id(1) is not in the live set: the device is gone from the account,
        // but its (untombstoned) META entry lingers.
        assert_eq!(disambiguate("heyl CLI", &doc, &[id(2)]), "heyl CLI");
    }
}
