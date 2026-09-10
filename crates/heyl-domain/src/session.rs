//! What a session publishes about itself, and how it is policed.
//!
//! Two kinds of state, in two places, with two very different costs:
//!
//! * [`SessionMetadata`] lives in the **META vault**, so writing it needs the
//!   vault key — and therefore the seed, and therefore an unlock. This is the
//!   entry that makes a device appear in the heylogin app, and its
//!   `description` is **the only string the phone shows on the approval
//!   screen** (`HEYLOGIN_SPEC.md` §6-7, confirmed live).
//! * [`SessionPolicy`] lives on the **session record**, behind the access
//!   token alone: `unlock_time_limit_minutes` is heylogin's own field, and the
//!   rest rides in `client_settings`, a per-session string every shipped
//!   heylogin client leaves empty. No unlock is needed to change any of it.
//!
//! That split is why `heyl session set display-name` may ask for a swipe and
//! `heyl session set timeout` never does.

use serde::{Deserialize, Serialize};

use crate::{AuthenticatorId, Timestamp};

/// The icon every heyl session publishes.
///
/// heylogin's own Android client ships `ic_device_cli`, and the value set is
/// shared across platforms because any client may write the field and every
/// other one has to render it. An unknown value renders as a question mark, so
/// this is a fixed constant rather than a setting.
pub const ICON_CLI: &str = "cli";

/// A session's entry in the META vault's `sessions` map.
///
/// Field names are the wire's, so this serialises straight into the heymerge
/// document. Unknown keys are *not* modelled here — the read-modify-write in
/// `heyl-vault` edits the JSON in place precisely so that keys we do not know
/// survive untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMetadata {
    /// What the phone shows: in the device list, and on the approval screen.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// Which icon the app draws. Always [`ICON_CLI`] for us.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub icon_type: Option<String>,
    /// Whether this session can unlock itself without another device.
    ///
    /// False for every heyl session: we are unlocked by the phone.
    pub is_self_unlocking: bool,
    /// This session's X25519 public key, which a granter encrypts the seed to.
    pub enc_pub_key: String,
    /// That key, signed with the authenticator's identity key.
    ///
    /// The phone verifies this before it will unlock us; without it the
    /// request produces a notification with nothing behind it.
    pub enc_pub_key_signature: String,
    /// Which authenticator's identity key made the signature.
    pub signing_auth_id: AuthenticatorId,
    /// When the entry was first written.
    pub creation_time: Timestamp,
    /// When it was last edited.
    pub edit_time: Timestamp,
    /// heymerge's tombstone flag.
    pub is_deleted: bool,
    /// heymerge's last-write-wins discriminator.
    pub update_time: Timestamp,
}

/// How often this session must be re-approved.
///
/// `timeout_minutes` is server-enforced: the backend stops serving the unlock
/// blob at the deadline, so it binds any client that discards the seed. The
/// two flags are heyl's own behaviour, carried in `client_settings` so that a
/// slot's policy follows it to another machine and nothing lands on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// `unlock_time_limit_minutes`. One minute is the backend's floor.
    pub timeout_minutes: u32,
    /// Drop the unlock when the command exits, so the next access re-asks.
    pub strict: bool,
    /// Slide the window on use (`ExtendSessionUnlock`).
    ///
    /// Off by default: a window that an agent's own traffic keeps alive is not
    /// a window.
    pub auto_extend: bool,
}

/// The backend's minimum for `unlock_time_limit_minutes`; 0 is refused.
pub const MIN_TIMEOUT_MINUTES: u32 = 1;

/// heylogin's default, and ours: eight hours.
pub const DEFAULT_TIMEOUT_MINUTES: u32 = 480;

/// After this, the backend deletes the blob whatever the session says.
pub const SERVER_UNLOCK_CAP_HOURS: u32 = 30;

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            timeout_minutes: DEFAULT_TIMEOUT_MINUTES,
            strict: false,
            auto_extend: false,
        }
    }
}

/// heyl's corner of `client_settings`.
///
/// The whole field is a JSON string owned by whichever client wrote it; every
/// shipped heylogin client leaves it empty (`Record<string, never>`), and the
/// entry is per session, so nothing of theirs is at risk of being overwritten.
/// Unknown keys are preserved on write for the same reason ours are.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeylClientSettings {
    /// Drop the unlock at command exit.
    #[serde(default, skip_serializing_if = "is_false")]
    pub strict: bool,
    /// Slide the unlock window on use.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_extend: bool,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if"
)]
const fn is_false(value: &bool) -> bool {
    !*value
}

impl SessionPolicy {
    /// Read a policy out of a session record.
    ///
    /// A `client_settings` we cannot parse is treated as absent rather than
    /// fatal: it is another client's field, and refusing to run because
    /// somebody wrote something unexpected there would be the wrong trade.
    #[must_use]
    pub fn from_wire(timeout_minutes: u32, client_settings: &str) -> Self {
        let ours = serde_json::from_str::<serde_json::Value>(client_settings)
            .ok()
            .and_then(|v| v.get("heyl").cloned())
            .and_then(|v| serde_json::from_value::<HeylClientSettings>(v).ok())
            .unwrap_or_default();
        Self {
            timeout_minutes,
            strict: ours.strict,
            auto_extend: ours.auto_extend,
        }
    }

    /// Render this policy's flags back into a `client_settings` string,
    /// preserving every key that is not ours.
    ///
    /// # Errors
    /// Never in practice: the value being serialised is a map of JSON we just
    /// parsed, plus two booleans.
    ///
    /// # Panics
    /// Never: the value is filtered to an object immediately above the unwrap.
    pub fn to_client_settings(self, existing: &str) -> Result<String, serde_json::Error> {
        let mut root = serde_json::from_str::<serde_json::Value>(existing)
            .ok()
            .filter(serde_json::Value::is_object)
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

        let ours = serde_json::to_value(HeylClientSettings {
            strict: self.strict,
            auto_extend: self.auto_extend,
        })?;

        let object = root.as_object_mut().expect("filtered to an object above");
        if ours.as_object().is_some_and(serde_json::Map::is_empty) {
            object.remove("heyl");
        } else {
            object.insert("heyl".to_owned(), ours);
        }
        serde_json::to_string(&root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_client_settings_is_empty() {
        let policy = SessionPolicy::from_wire(480, "");
        assert_eq!(policy, SessionPolicy::default());
    }

    #[test]
    fn reads_our_flags_back() {
        let policy = SessionPolicy::from_wire(1, r#"{"heyl":{"strict":true,"autoExtend":true}}"#);
        assert!(policy.strict && policy.auto_extend);
        assert_eq!(policy.timeout_minutes, 1);
    }

    #[test]
    fn another_clients_keys_survive_a_write() {
        let policy = SessionPolicy {
            strict: true,
            ..SessionPolicy::default()
        };
        let written = policy
            .to_client_settings(r#"{"someOtherClient":{"x":1}}"#)
            .expect("serialises");
        let value: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
        assert_eq!(value["someOtherClient"]["x"], 1);
        assert_eq!(value["heyl"]["strict"], true);
    }

    /// Turning everything off leaves no `heyl` key behind at all.
    #[test]
    fn clearing_our_flags_removes_our_key() {
        let written = SessionPolicy::default()
            .to_client_settings(r#"{"heyl":{"strict":true}}"#)
            .expect("serialises");
        let value: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
        assert!(value.get("heyl").is_none(), "{written}");
    }

    /// Garbage in that field is another client's business, not a crash.
    #[test]
    fn unparseable_client_settings_reads_as_default() {
        assert_eq!(
            SessionPolicy::from_wire(480, "not json at all"),
            SessionPolicy::default()
        );
    }
}
