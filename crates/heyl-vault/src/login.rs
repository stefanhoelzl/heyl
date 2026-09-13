//! `LoginVaultContentV2` — the schema every credential lives in.
//!
//! Parses a **folded** login vault ([`crate::fold`]) into structured logins.
//! This layer is deliberately crypto-free: a `ProtectedValue` (the password, a
//! protected custom field) is carried as the base64 ciphertext heylogin stored,
//! and `heyl-app` — which holds the vault's `protectedSecret` — turns it into
//! plaintext. Structure here, secrets there, the same split the port boundary
//! draws everywhere else (DESIGN.md §4).
//!
//! Field names and shapes are measured against a real account and checked
//! against heylogin's own `persistable-types` schema
//! (`vaultContent/login/Login.ts`, `CustomField.ts`):
//!
//! * the name the app shows is **`displayHeadline`**, not `title` — `title` is
//!   usually empty (`Login.ts`);
//! * a label is an entry in **`tags`**, a string array;
//! * a **`customFields`** entry is `{id?, name, protected, value, …}`, its
//!   `value` a plain string when `protected: false` and a `ProtectedValue`
//!   when `protected: true`; the `id` may be **absent** and is never invented
//!   (`CustomField.ts`);
//! * a login is **live** (`!isDeleted`), **archived** (`isDeleted &&
//!   isArchived`) or a **tombstone** (`isDeleted && !isArchived`) — heymerge's
//!   own three-way (`HeymergeList.ts`).

use heyl_domain::{FieldId, LoginId};
use serde_json::Value;

use crate::Document;

/// The list name a login vault keeps its credentials under.
const LOGINS: &str = "logins";

/// A `ProtectedValue`: a secret still sealed to the vault's `protectedSecret`.
///
/// The ciphertext is `nonce ‖ box`, base64. `heyl-app` decrypts it; this crate
/// never sees a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protected {
    /// `symEncrypt(protectedSecret, plaintext)`, base64 — as stored.
    pub encrypted: String,
    /// The stored `isEmpty` flag: a field the user left blank still has a
    /// (short) ciphertext, and this is how heylogin marks it empty.
    pub is_empty: bool,
}

/// One custom field on a login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomField {
    /// The field's id, when it has one. Absent for fields written by importers
    /// that dropped it; heyl never invents one (`-F` cannot reach such a
    /// field, DESIGN.md §5).
    pub id: Option<FieldId>,
    /// The field's name, as the user typed it.
    pub name: String,
    /// Plain text, or a value sealed to `protectedSecret`.
    pub value: FieldValue,
}

/// A custom field's value: in the clear, or protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    /// `protected: false` — the string as stored.
    Plain(String),
    /// `protected: true` — sealed to `protectedSecret`.
    Protected(Protected),
}

/// Which liveness bucket a login is in — the first key of the read ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Liveness {
    /// `!isDeleted` — a normal, visible login.
    Live = 0,
    /// `isDeleted && isArchived` — archived, recoverable in the app.
    Archived = 1,
    /// `isDeleted && !isArchived` — a hard-deleted tombstone.
    Deleted = 2,
}

/// One login, parsed. Protected values are still sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    /// The login's id — the `logins` map key, not a field of the element.
    pub id: LoginId,
    /// `displayHeadline`, the name the app shows. Absent when never set.
    pub display_headline: Option<String>,
    /// `title` — usually empty; kept because a login titled by another client
    /// is matchable by it.
    pub title: String,
    /// `username`.
    pub username: String,
    /// `note`.
    pub note: String,
    /// `websites`, in stored order.
    pub websites: Vec<String>,
    /// `tags` — the labels.
    pub tags: Vec<String>,
    /// `password`, sealed. Absent if the login has no password field at all.
    pub password: Option<Protected>,
    /// `customFields`, in stored order.
    pub custom_fields: Vec<CustomField>,
    /// `creationTime`, as stored.
    pub created: Option<String>,
    /// `editTime` — when the content was last edited.
    pub edited: Option<String>,
    /// `changeTime` — when the login last surfaced in the app's list (edit,
    /// restore, or move); the ranking key. Optional in the schema.
    pub change_time: Option<String>,
    /// `isDeleted`.
    pub is_deleted: bool,
    /// `isArchived`.
    pub is_archived: bool,
}

impl Login {
    /// Which liveness bucket this login is in (heymerge's three-way).
    #[must_use]
    pub const fn liveness(&self) -> Liveness {
        if !self.is_deleted {
            Liveness::Live
        } else if self.is_archived {
            Liveness::Archived
        } else {
            Liveness::Deleted
        }
    }

    /// The ranking key within a liveness bucket: `changeTime ?? editTime`,
    /// which is heylogin's own list order (`loginFilter.ts`). Compared as a
    /// string — ISO-8601 UTC sorts correctly — with the empty string sorting
    /// oldest, so a login with neither timestamp ranks last.
    #[must_use]
    pub fn recency(&self) -> &str {
        self.change_time
            .as_deref()
            .or(self.edited.as_deref())
            .unwrap_or("")
    }

    /// Whether `needle` names this login — its `displayHeadline`, `title`, or
    /// any of its websites, compared case-insensitively and exactly (no
    /// substring). Websites compare as stored, byte for byte after casefold.
    #[must_use]
    pub fn matches_name(&self, needle: &str) -> bool {
        let needle = needle.to_lowercase();
        self.display_headline
            .as_deref()
            .is_some_and(|h| h.to_lowercase() == needle)
            || self.title.to_lowercase() == needle
            || self.websites.iter().any(|w| w.to_lowercase() == needle)
    }

    /// The custom field with this id, if the login has one that carries it.
    #[must_use]
    pub fn custom_field_by_id(&self, id: FieldId) -> Option<&CustomField> {
        self.custom_fields.iter().find(|f| f.id == Some(id))
    }

    /// The custom field with this exact name (case-sensitive, as stored).
    #[must_use]
    pub fn custom_field_by_name(&self, name: &str) -> Option<&CustomField> {
        self.custom_fields.iter().find(|f| f.name == name)
    }
}

/// Every login in a folded login vault, in the map's document order.
///
/// Entries whose id is not a UUID are skipped rather than fatal — the same
/// tolerance `meta::sessions` applies, for the same reason: the list belongs to
/// every client on the account, and one malformed entry is not a reason to
/// refuse to read the rest.
#[must_use]
pub fn logins(document: &Document) -> Vec<Login> {
    document
        .content
        .get(LOGINS)
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(id, element)| parse_login(id, element))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse one `logins` entry. `None` if the id is not a UUID or the element is
/// not an object.
fn parse_login(id: &str, element: &Value) -> Option<Login> {
    let id = LoginId::parse(id).ok()?;
    let obj = element.as_object()?;

    Some(Login {
        id,
        display_headline: string_opt(obj, "displayHeadline"),
        title: string(obj, "title"),
        username: string(obj, "username"),
        note: string(obj, "note"),
        websites: string_array(obj, "websites"),
        tags: string_array(obj, "tags"),
        password: obj.get("password").and_then(parse_protected),
        custom_fields: parse_custom_fields(obj.get("customFields")),
        created: string_opt(obj, "creationTime"),
        edited: string_opt(obj, "editTime"),
        change_time: string_opt(obj, "changeTime"),
        is_deleted: obj
            .get("isDeleted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        is_archived: obj
            .get("isArchived")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn parse_custom_fields(value: Option<&Value>) -> Vec<CustomField> {
    value
        .and_then(Value::as_array)
        .map(|fields| fields.iter().filter_map(parse_custom_field).collect())
        .unwrap_or_default()
}

fn parse_custom_field(value: &Value) -> Option<CustomField> {
    let obj = value.as_object()?;
    let name = string(obj, "name");
    // `protected` decides how `value` is read; a missing flag means plain, the
    // more common case, and a plain value read as protected would just fail to
    // decrypt rather than mislead.
    let protected = obj
        .get("protected")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let field_value = if protected {
        FieldValue::Protected(parse_protected(obj.get("value")?)?)
    } else {
        FieldValue::Plain(obj.get("value").and_then(Value::as_str)?.to_owned())
    };
    Some(CustomField {
        // A missing or malformed id is simply no id — never a fresh one.
        id: obj
            .get("id")
            .and_then(Value::as_str)
            .and_then(|s| FieldId::parse(s).ok()),
        name,
        value: field_value,
    })
}

fn parse_protected(value: &Value) -> Option<Protected> {
    let obj = value.as_object()?;
    Some(Protected {
        encrypted: obj.get("encrypted").and_then(Value::as_str)?.to_owned(),
        is_empty: obj.get("isEmpty").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn string(obj: &serde_json::Map<String, Value>, key: &str) -> String {
    obj.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// A string field that is absent when missing or empty — for the optional
/// display name and the timestamps, where "" and "not set" read the same and
/// the caller wants to omit it.
fn string_opt(obj: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn string_array(obj: &serde_json::Map<String, Value>, key: &str) -> Vec<String> {
    obj.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DESCRIPTOR_VERSION_HEYMERGE, Format};

    fn vault(logins_json: &Value) -> Document {
        Document {
            format: Format::Snappy,
            document_type: "login".to_owned(),
            version: DESCRIPTOR_VERSION_HEYMERGE,
            content: serde_json::json!({ "logins": logins_json.clone() })
                .as_object()
                .unwrap()
                .clone(),
        }
    }

    /// The exact shape measured on a real account (2026-09-13): a plain and a
    /// protected custom field, a label, an empty title with a displayHeadline.
    fn measured() -> Value {
        serde_json::json!({
            "f1bcfdf7-c3ca-4fc6-925d-f57d5e8919bd": {
                "uiType": "login",
                "displayHeadline": "User",
                "title": "",
                "username": "user@example.com",
                "websites": ["user.example.com"],
                "password": { "contentId": "b6", "encrypted": "cGFzcw==", "isEmpty": false },
                "note": "",
                "tags": ["label-test"],
                "customFields": [
                    { "id": "7d1626d2-bcd9-4b9e-83c4-0c5503c23443", "name": "custom-field",
                      "protected": false, "value": "custom-value", "multiline": false },
                    { "id": "69abefc3-44c1-4718-9fc7-860bd64f4e3a", "name": "custom-secret",
                      "protected": true,
                      "value": { "contentId": "b6", "encrypted": "c2VjcmV0", "isEmpty": false } }
                ],
                "creationTime": "2026-09-09T00:57:58.041Z",
                "editTime": "2026-09-12T20:11:16.733Z",
                "changeTime": "2026-09-12T20:11:16.733Z",
                "isDeleted": false
            }
        })
    }

    #[test]
    fn parses_the_measured_login() {
        let v = logins(&vault(&measured()));
        assert_eq!(v.len(), 1);
        let l = &v[0];
        assert_eq!(l.display_headline.as_deref(), Some("User"));
        assert_eq!(l.title, "");
        assert_eq!(l.username, "user@example.com");
        assert_eq!(l.websites, ["user.example.com"]);
        assert_eq!(l.tags, ["label-test"]);
        assert_eq!(l.password.as_ref().unwrap().encrypted, "cGFzcw==");
        assert_eq!(l.liveness(), Liveness::Live);
    }

    #[test]
    fn a_plain_field_is_plain_and_a_protected_field_stays_sealed() {
        let l = &logins(&vault(&measured()))[0];
        let plain = l.custom_field_by_name("custom-field").unwrap();
        assert_eq!(plain.value, FieldValue::Plain("custom-value".to_owned()));
        let secret = l.custom_field_by_name("custom-secret").unwrap();
        assert!(matches!(secret.value, FieldValue::Protected(_)));
    }

    #[test]
    fn a_field_is_reachable_by_id_when_it_has_one() {
        let l = &logins(&vault(&measured()))[0];
        let id = FieldId::parse("7d1626d2-bcd9-4b9e-83c4-0c5503c23443").unwrap();
        assert_eq!(l.custom_field_by_id(id).unwrap().name, "custom-field");
    }

    #[test]
    fn a_field_without_an_id_is_name_only() {
        let l = &logins(&vault(&serde_json::json!({
            "f1bcfdf7-c3ca-4fc6-925d-f57d5e8919bd": {
                "customFields": [{ "name": "api-key", "protected": false, "value": "v" }],
                "isDeleted": false
            }
        })))[0];
        let field = l.custom_field_by_name("api-key").unwrap();
        assert_eq!(field.id, None);
    }

    #[test]
    fn matching_is_case_insensitive_over_headline_title_and_website() {
        let l = &logins(&vault(&measured()))[0];
        assert!(l.matches_name("user"));
        assert!(l.matches_name("USER.EXAMPLE.COM"));
        assert!(!l.matches_name("user.example")); // exact, not substring
    }

    #[test]
    fn liveness_reads_the_two_flags_as_heymerge_does() {
        let archived = &logins(&vault(&serde_json::json!({
            "f1bcfdf7-c3ca-4fc6-925d-f57d5e8919bd": { "isDeleted": true, "isArchived": true }
        })))[0];
        assert_eq!(archived.liveness(), Liveness::Archived);

        let tombstone = &logins(&vault(&serde_json::json!({
            "f1bcfdf7-c3ca-4fc6-925d-f57d5e8919bd": { "isDeleted": true, "isArchived": false }
        })))[0];
        assert_eq!(tombstone.liveness(), Liveness::Deleted);
    }

    #[test]
    fn recency_prefers_change_time_then_edit_time() {
        let l = &logins(&vault(&measured()))[0];
        assert_eq!(l.recency(), "2026-09-12T20:11:16.733Z");

        let no_change = &logins(&vault(&serde_json::json!({
            "f1bcfdf7-c3ca-4fc6-925d-f57d5e8919bd": {
                "editTime": "2026-01-01T00:00:00.000Z", "isDeleted": false
            }
        })))[0];
        assert_eq!(no_change.recency(), "2026-01-01T00:00:00.000Z");
    }

    #[test]
    fn a_non_uuid_entry_is_skipped_not_fatal() {
        let v = logins(&vault(&serde_json::json!({
            "not-a-uuid": { "isDeleted": false },
            "f1bcfdf7-c3ca-4fc6-925d-f57d5e8919bd": { "isDeleted": false }
        })));
        assert_eq!(v.len(), 1);
    }
}
